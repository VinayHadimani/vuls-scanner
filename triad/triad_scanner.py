"""
TRIAD_Scanner - unified lightweight vulnerability scanner for the TRIAD platform.

Agentic AI Vulnerability Intelligence: INGEST -> ENRICH (NVD/EPSS) -> FUSE -> EXPLAIN.
This module is the INGEST front door. It merges the core detection mechanisms of
three open-source scanners, reverse engineered from their sources (see README):

  * Trivy lane  (dependency manifests -> CVE version-range matching)
      - parsers ported from trivy pkg/dependency/parser/{nodejs/packagejson, python/pip}
      - advisory matching ported from trivy pkg/detector/library/{driver, compare}/
      - index data sourced live from OSV (upstream of trivy-db's OSV pipeline),
        with range semantics from trivy-db pkg/vulnsrc/osv/range.go

  * Nuclei lane (YAML templates -> HTTP request -> matchers/extractors)
      - matchers-condition default OR  (nuclei pkg/operators/operators.go)
      - per-matcher word/regex condition, negative, case-insensitive, parts
        (nuclei pkg/operators/matchers/match.go)
      - event map ported from nuclei pkg/protocols/http/operators.go
        (body / header / response / status_code, lowercased header keys)

  * ZAP lane (passive web checks on one fetched response)
      - rules ported from zaproxy + zap-extensions pscanrules with their exact
        trigger conditions, risk levels and CWE ids.

Output contract (per finding, keys ALWAYS present):
    cve_id, target_url, severity, source_tool, description
Optional enrichment keys: cwe, evidence, fix.

DEMO_MODE: mocks the TARGET (fixture data), never the ENGINE. The real
matching code runs against built-in fixtures and returns instantly with no
network access - ideal for hackathon demos.

Authorized targets only. This tool sends a small number of read-only GET
requests to the target you point it at.
"""
from __future__ import annotations

import json
import os
import re
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INDEX = os.path.join(_HERE, "data", "dep_cve_index.json")
DEFAULT_TEMPLATES = os.path.join(_HERE, "triad_templates")
DEFAULT_DEMO_DIR = os.path.join(_HERE, "data", "demo")


# --------------------------------------------------------------------------
# Input routing
# --------------------------------------------------------------------------
_GITHUB_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", re.I)


def classify_target(target: str) -> tuple[str, str]:
    """Route the input. Returns (kind, normalized) with kind in
    {"github", "web", "local", "invalid"}."""
    target = (target or "").strip()
    if not target:
        return "invalid", ""
    if os.path.isdir(target):
        return "local", os.path.abspath(target)
    m = _GITHUB_RE.match(target)
    if m:
        owner, repo = m.group(1), m.group(2)
        return "github", f"https://github.com/{owner}/{repo}"
    if target.lower().startswith(("http://", "https://")):
        return "web", target
    if re.match(r"^[A-Za-z0-9_.-]+\.[A-Za-z]{2,}(:\d+)?(/.*)?$", target):
        return "web", "https://" + target          # bare host -> https
    return "invalid", target


# --------------------------------------------------------------------------
# Version engine (trivy-derived)
# SemVer for npm, PEP440-lite for pip; constraint grammar from trivy-db
# range.go output: ">=X, <Y" groups OR-joined across list entries.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class _V:
    """Parsed version. tuple ordering per scheme."""
    scheme: str
    release: tuple
    pre: tuple | None = None      # ('rc', 1) style identifiers
    post: int | None = None

def _parse_semver(v: str) -> _V:
    v = v.strip().lstrip("vV")
    core, _, _build = v.partition("+")
    core, _, pre = core.partition("-")
    nums = []
    for part in core.split("."):
        m = re.match(r"^(\d+)", part)
        nums.append(int(m.group(1)) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    pre_ids = tuple(pre.split(".")) if pre else None
    return _V("semver", tuple(nums[:3]), pre_ids)

def _parse_pep440(v: str) -> _V:
    v = v.strip().lstrip("vV")
    m = re.match(
        r"^(\d+!)?(\d+(?:\.\d+)*)"
        r"(?:(a|b|rc)(\d+))?"
        r"(?:\.post(\d+))?"
        r"(?:\.dev(\d+))?",
        v,
    )
    if not m:
        return _V("pep440", (0,))
    release = tuple(int(x) for x in m.group(2).split("."))
    pre = None
    if m.group(3):
        label = {"a": "a", "b": "b", "rc": "rc"}[m.group(3)]
        pre = (label, int(m.group(4) or 0))
    post = int(m.group(5)) if m.group(5) else None
    dev = int(m.group(6)) if m.group(6) else None  # noqa: F841 - dev ordering folded below
    out = _V("pep440", release, pre, post)
    # fold dev into pre slot marker: dev releases sort before everything
    if m.group(6) is not None:
        out = _V("pep440", release, ("dev", int(m.group(6))), post)
    return out

_PRE_ORDER = {"dev": -2, "a": -1, "b": 0, "rc": 1}

def _cmp_versions(a: _V, b: _V) -> int:
    if a.release != b.release:
        return -1 if a.release < b.release else 1
    # same release: dev < pre < final < post
    def rank(v: _V) -> tuple:
        if v.pre:
            if v.pre[0] == "dev":
                return (-2, 0)          # pep440 dev release
            return (0, tuple(str(x) for x in v.pre))   # prerelease set
        if v.post is not None:
            return (2, v.post)
        return (1, 0)                   # final release
    ra, rb = rank(a), rank(b)
    return -1 if ra < rb else (1 if ra > rb else 0)

def _parse_version(v: str, scheme: str) -> _V:
    return _parse_semver(v) if scheme == "semver" else _parse_pep440(v)

def _check_comparator(op: str, threshold: str, version: _V) -> bool:
    t = _parse_version(threshold, version.scheme)
    c = _cmp_versions(version, t)
    return {
        ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0,
        "=": c == 0, "!=": c != 0,
    }[op]

def _match_group(version: _V, group: str) -> bool:
    """One constraint group: AND across comma-separated comparators."""
    for piece in group.split(","):
        piece = piece.strip()
        if not piece:
            continue
        m = re.match(r"^(>=|<=|!=|>|<|=)\s*(.+)$", piece)
        if not m:
            return False
        if not _check_comparator(m.group(1), m.group(2), version):
            return False
    return True

def matches_constraints(version: str, constraints: list[str], scheme: str) -> bool:
    """True if version satisfies the OR-of-groups constraint list.
    Port of trivy compare.IsVulnerable step 2 (vulnerable_versions joined with ' || ')."""
    v = _parse_version(version, scheme)
    return any(_match_group(v, g) for g in constraints)


def is_vulnerable(version: str, advisory: dict, scheme: str) -> bool:
    """Faithful port of trivy pkg/detector/library/compare/compare.go:
    1. empty entry (or '*') anywhere -> fail-open vulnerable
    2. must match vulnerable_versions (OR of groups), else not vulnerable
    3. must NOT match patched/unaffected (fixed_versions), else not vulnerable
    """
    vulnerable = list(advisory.get("vulnerable_versions") or [])
    patched = [f"={f}" for f in (advisory.get("fixed_versions") or [])]
    vulnerable = [c for c in vulnerable if c != "*"]
    if "" in vulnerable or "" in patched or not vulnerable:
        # trivy: empty vulnerable/patched entry -> detect anyway (fail-open)
        if not vulnerable and not patched:
            return True
    if vulnerable:
        if not matches_constraints(version, vulnerable, scheme):
            return False
    if patched:
        if matches_constraints(version, patched, scheme):
            return False
    return True


def normalize_pkg_name(name: str, ecosystem: str) -> str:
    """Port of trivy-db vulnerability.NormalizePkgName (pip branch)."""
    if ecosystem == "pip":
        return name.lower().replace("_", "-")
    return name


# --------------------------------------------------------------------------
# Dependency lane (Trivy-derived)
# --------------------------------------------------------------------------
_NAME_RE = re.compile(r"^(@[A-Za-z0-9-._]+/)?[A-Za-z0-9-._]+$")   # trivy packagejson.IsValidName


def parse_package_json(text: str) -> list[tuple[str, str, str]]:
    """Port of trivy pkg/dependency/parser/nodejs/packagejson: dependencies,
    optionalDependencies and devDependencies are direct deps of the app."""
    doc = json.loads(text)
    name = doc.get("name", "")
    if name and not _NAME_RE.match(name):
        raise ValueError("invalid package.json name")
    out: list[tuple[str, str, str]] = []
    for key in ("dependencies", "optionalDependencies", "devDependencies"):
        deps = doc.get(key) or {}
        if isinstance(deps, dict):
            for pkg, ver in deps.items():
                if isinstance(ver, str):
                    out.append((pkg, ver.strip().lstrip("^~vV ") or "0", "npm"))
    return out


def parse_requirements_txt(text: str) -> list[tuple[str, str, str]]:
    """Port of trivy pkg/dependency/parser/python/pip/parse.go:
    - strip comments (#), options (--), BOM; join continuations
    - split name/specs at first non-name char (PEP 508 name set [a-zA-Z0-9._-])
    - accept version from ==, then >=, then ~= (min-version fallback)
    - strip extras [...] and environment markers after ';'
    """
    if text.startswith("﻿"):
        text = text.lstrip("﻿")
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        if lines and lines[-1].endswith("\\"):
            lines[-1] = lines[-1][:-1] + " " + line
            continue
        lines.append(line)
    out: list[tuple[str, str, str]] = []
    for line in lines:
        line = line.split("#", 1)[0].strip()      # inline comments (trivy pip parser)
        if not line:
            continue
        line = line.split(";")[0].strip()          # env markers
        # find end of package name: first char not in [A-Za-z0-9._-]
        i = 0
        while i < len(line) and (line[i].isalnum() or line[i] in "._-"):
            i += 1
        name, specs = line[:i].strip(), line[i:].strip()
        if not name or not specs:
            continue
        if name.startswith("[") or "]" in name:
            continue
        specs = specs.split("[")[0].strip()        # extras like pkg[extra]
        for op in ("==", ">=", "~="):
            for spec in specs.split(","):
                if spec.strip().startswith(op):
                    ver = spec.strip()[len(op):].strip().lstrip("vV ").split()[0] if spec.strip()[len(op):].strip() else ""
                    if ver:
                        out.append((name, ver, "pip"))
                    break
            else:
                continue
            break
    return out


def parse_pyproject_toml(text: str) -> list[tuple[str, str, str]]:
    """[project].dependencies (PEP 508 strings) - PEP 621 projects."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:  # pragma: no cover
        return []
    try:
        doc = tomllib.loads(text)
    except Exception:
        return []
    deps = (doc.get("project") or {}).get("dependencies") or []
    out: list[tuple[str, str, str]] = []
    for req in deps:
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(~=|==|>=|>)\s*([0-9][^\s;,]*)", req.strip())
        if m:
            out.append((m.group(1), m.group(3).strip(), "pip"))
    return out


MANIFEST_PARSERS = {
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
}

_SCHEME = {"npm": "semver", "pip": "pep440"}


class DependencyLane:
    """Trivy-derived: parse manifests, match against the CVE index
    (same advisory model trivy-db builds from OSV)."""

    def __init__(self, index_path: str = DEFAULT_INDEX):
        with open(index_path, encoding="utf-8") as fh:
            self.index: dict = json.load(fh)
        self.provenance: dict = self.index.get("provenance", {})

    def scan_manifests(self, files: dict[str, str], target_url: str) -> list[dict]:
        findings: list[dict] = []
        for fname, text in files.items():
            parser = MANIFEST_PARSERS.get(os.path.basename(fname))
            if parser is None:
                continue
            try:
                deps = parser(text)
            except Exception as exc:  # noqa: BLE001
                findings.append(self._finding(None, target_url, "info", "triad-derived",
                                              f"Could not parse {fname}: {exc}", None, fname, None))
                continue
            for name, version, eco in deps:
                findings.extend(self._match_package(name, version, eco, target_url, fname))
        return findings

    def _match_package(self, name: str, version: str, eco: str, target_url: str, manifest: str) -> list[dict]:
        bucket = (self.index.get("advisories") or {}).get(eco) or {}
        advisories = bucket.get(normalize_pkg_name(name, eco)) or bucket.get(name) or []
        out = []
        for adv in advisories:
            if is_vulnerable(version, adv, _SCHEME.get(eco, "semver")):
                fixed = ", ".join(adv.get("fixed_versions") or []) or None
                out.append(self._finding(
                    adv.get("vulnerability_id"), target_url,
                    adv.get("severity", "unknown"), "triad-derived",
                    f"{name} {version} is affected: {adv.get('summary', '')} "
                    f"(affected: {' or '.join(adv.get('vulnerable_versions', []))}; fixed in: {fixed or 'n/a'}). "
                    f"Source: {adv.get('url', '')}",
                    None,
                    f"{manifest}: {name}@{version}",
                    fixed,
                ))
        return out

    @staticmethod
    def _finding(cve_id, target_url, severity, source_tool, description, cwe, evidence, fix):
        return {
            "cve_id": cve_id, "target_url": target_url, "severity": severity,
            "source_tool": source_tool, "description": description,
            "cwe": cwe, "evidence": evidence, "fix": fix,
        }


# --------------------------------------------------------------------------
# Template lane (Nuclei-derived)
# --------------------------------------------------------------------------
def load_templates(templates_dir: str = DEFAULT_TEMPLATES) -> list[dict]:
    import yaml  # kept local so the dependency lane works without PyYAML
    out = []
    for fname in sorted(os.listdir(templates_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(templates_dir, fname), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        doc["_path"] = os.path.join(templates_dir, fname)
        out.append(doc)
    return out


def _interpolate(path: str, base_url: str) -> str:
    """Port of nuclei BaseURL-style variable substitution (subset)."""
    from urllib.parse import urlsplit
    u = urlsplit(base_url)
    root = f"{u.scheme}://{u.netloc}"
    vals = {
        "{{BaseURL}}": base_url.rstrip("/"),
        "{{RootURL}}": root,
        "{{Host}}": u.netloc,
        "{{Scheme}}": u.scheme,
    }
    for k, v in vals.items():
        path = path.replace(k, v)
    return path


def build_event(resp: Any) -> dict:
    """Port of nuclei pkg/protocols/http/operators.go responseToDSLMap:
    body / header / response / status_code / content_length plus every header
    lowercased with '-'->'_' and cookies by name."""
    raw = resp["raw"]
    header_blob, _, body = raw.partition("\r\n\r\n")
    status_line = raw.split("\r\n", 1)[0] if raw else ""
    headers: dict[str, list[str]] = {}
    for line in header_blob.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    event: dict[str, Any] = {
        "body": body,
        "header": "\r\n".join(f"{k}: {', '.join(v)}" for k, v in headers.items()),
        "all_headers": "\r\n".join(f"{k}: {', '.join(v)}" for k, v in headers.items()),
        "response": raw,
        "status_code": resp["status"],
        "content_length": len(body),
        "matched": resp.get("matched", base_url_of(resp)),
        "request": resp.get("request", ""),
        "_status_line": status_line,
        "_status_ok": 200 <= resp["status"] < 400,
    }
    for k, v in headers.items():
        event[k.replace("-", "_")] = ", ".join(v)
    for c in resp.get("cookies") or []:
        name, _, val = c.partition("=")
        event.setdefault(name.strip().lower(), val)
    return event


def base_url_of(resp: dict) -> str:
    return resp.get("url", "")


def _event_for(resp: dict) -> dict:
    return build_event(resp)


class MatcherError(ValueError):
    pass


def run_matchers(matchers: list[dict], condition: str, event: dict) -> tuple[bool, dict]:
    """Port of nuclei pkg/operators/operators.go Execute + pkg/operators/matchers/match.go.
    matchers-condition default OR (operators.go:52)."""
    is_and = (condition or "or").lower() == "and"
    matched_any = False
    matched_all = True
    detail: dict[str, list[str]] = {}
    for m in matchers:
        ok, ev = _run_one_matcher(m, event)
        neg = bool(m.get("negative"))
        ok = (not ok) if neg else ok
        matched_any = matched_any or ok
        matched_all = matched_all and ok
        if ok:
            detail[m.get("name") or m.get("type", "?")] = ev or []
    return (matched_all if is_and else matched_any), detail


def _run_one_matcher(m: dict, event: dict) -> tuple[bool, list[str]]:
    part = (m.get("part") or "body").lower()
    if part == "header":
        part = "all_headers"          # nuclei getMatchPart
    if part == "all":
        corpus = str(event.get("body", "")) + str(event.get("all_headers", ""))
    elif part == "response":
        corpus = str(event.get("response", ""))
    else:
        corpus = str(event.get(part if part in event else "body", ""))
    mtype = (m.get("type") or "").lower()
    if mtype == "status":
        ok = event["status_code"] in (m.get("status") or [])
        return ok, ([str(event["status_code"])] if ok else [])
    if mtype == "word":
        return _match_words(m, corpus)
    if mtype == "regex":
        return _match_regex(m, corpus)
    raise MatcherError(f"unsupported matcher type: {mtype} (subset: status/word/regex)")


def _match_words(m: dict, corpus: str) -> tuple[bool, list[str]]:
    cond = (m.get("condition") or "or").lower()
    words = list(m.get("words") or [])
    ci = bool(m.get("case-insensitive"))
    if ci:
        corpus = corpus.lower()
    hit: list[str] = []
    for w in words:
        ww = w.lower() if ci else w
        if ww in corpus:
            if cond == "or":
                return True, [ww]
            hit.append(ww)
        elif cond == "and":
            return False, []
    if cond == "and" and len(hit) == len(words) and words:
        return True, hit
    return (len(hit) > 0), hit


def _match_regex(m: dict, corpus: str) -> tuple[bool, list[str]]:
    cond = (m.get("condition") or "or").lower()
    flags = re.IGNORECASE if m.get("case-insensitive") else 0
    hit: list[str] = []
    for rx in m.get("regex") or []:
        found = re.findall(rx, corpus, flags) or []
        if found:
            if cond == "or":
                return True, found[:1]
            hit += [found[0] if isinstance(found[0], str) else str(found[0])]
        elif cond == "and":
            return False, []
    if cond == "and" and hit:
        return True, hit
    return (len(hit) > 0), hit


def run_extractors(extractors: list[dict], event: dict) -> list[str]:
    """Port of nuclei extractors (subset): regex w/ group, kval on the event
    map (lowercased keys), json dotted paths with [N] indices."""
    out: list[str] = []
    for e in extractors:
        etype = (e.get("type") or "").lower()
        part = (e.get("part") or "body").lower()
        if part == "header":
            part = "all_headers"
        if part == "all":
            corpus = str(event.get("body", "")) + str(event.get("all_headers", ""))
        else:
            corpus = str(event.get(part if part in event else "body", ""))
        if etype == "regex":
            group = int(e.get("group") or 0)
            for rx in e.get("regex") or []:
                # nuclei uses FindAllStringSubmatch: m.group(group) semantics
                for m in re.finditer(rx, corpus, re.IGNORECASE if e.get("case-insensitive") else 0):
                    try:
                        out.append(m.group(group))
                    except (IndexError, re.error):
                        continue
        elif etype == "kval":
            for k in e.get("kval") or []:
                v = event.get(k.lower().replace("-", "_"))
                if v is None:
                    v = event.get(k.lower())
                if v is not None:
                    out.append(str(v))
        elif etype == "json":
            try:
                doc = json.loads(corpus)
            except Exception:
                continue
            for path in e.get("json") or []:
                cur: Any = doc
                ok = True
                for token in re.findall(r"[^.\[\]]+|\[\d+\]", path):
                    if token.startswith("[") and token.endswith("]"):
                        idx = int(token[1:-1])
                        if isinstance(cur, list) and idx < len(cur):
                            cur = cur[idx]
                        else:
                            ok = False; break
                    else:
                        if isinstance(cur, dict) and token in cur:
                            cur = cur[token]
                        else:
                            ok = False; break
                if ok:
                    out.append(cur if isinstance(cur, str) else json.dumps(cur))
    return out


# --------------------------------------------------------------------------
# HTTP transports (live + demo fixture)
# --------------------------------------------------------------------------
@dataclass
class Transport:
    timeout: float = 8.0

    def get(self, url: str, headers: dict | None = None, redirects: bool = False,
            max_redirects: int = 5) -> dict | None:
        raise NotImplementedError


class LiveTransport(Transport):
    """httpx-backed transport. Only GET is emitted by template lane."""

    def get(self, url, headers=None, redirects=False, max_redirects=5):
        import httpx
        try:
            with httpx.Client(follow_redirects=redirects, timeout=self.timeout,
                              max_redirects=max_redirects) as client:
                r = client.get(url, headers=headers or {})
        except Exception:
            return None
        raw = "HTTP/1.1 " + str(r.status_code) + " " + r.reason_phrase + "\r\n"
        raw += "".join(f"{k}: {v}\r\n" for k, v in r.headers.items())
        raw += "\r\n" + r.text
        return {
            "url": str(r.url), "status": r.status_code, "raw": raw,
            "cookies": [f"{c.name}={c.value}" for c in r.cookies.jar],
            "request": f"GET {url}",
            "matched": str(r.url),
        }


class FixtureTransport(Transport):
    """DEMO_MODE transport: serves deterministic fixture responses."""

    def __init__(self, fixture: dict, timeout: float = 8.0):
        super().__init__(timeout)
        self.routes: list[tuple[str, dict]] = [
            (r["path"], r) for r in fixture.get("routes", [])
        ]
        self.routes.sort(key=lambda t: -len(t[0]))      # longest prefix first

    def get(self, url, headers=None, redirects=False, max_redirects=5):
        from urllib.parse import urlsplit
        path = urlsplit(url).path or "/"
        for prefix, route in self.routes:
            if path == prefix or path.startswith(prefix):
                return {
                    "url": url, "status": route.get("status", 200),
                    "raw": route["raw"], "cookies": route.get("cookies", []),
                    "request": f"GET {url}", "matched": url,
                }
        return None


# --------------------------------------------------------------------------
# Template lane runner (Nuclei-derived)
# --------------------------------------------------------------------------
class TemplateLane:
    def __init__(self, templates: list[dict]):
        self.templates = templates

    def scan(self, target_url: str, transport: Transport) -> list[dict]:
        findings: list[dict] = []
        for tpl in self.templates:
            blocks = tpl.get("http") or []
            all_matched, extracts, match_evidence = True, [], []
            for block in blocks:
                matched, block_extracts, detail = self._run_block(block, target_url, transport)
                if not matched:
                    all_matched = False
                    break
                extracts += block_extracts
                match_evidence += [v for vals in detail.values() for v in vals]
            if blocks and all_matched:
                findings.append(self._finding(tpl, target_url, extracts, match_evidence))
        return findings

    def _run_block(self, block: dict, target_url: str, transport: Transport):
        headers = {k: str(v) for k, v in (block.get("headers") or {}).items()}
        redirects = bool(block.get("redirects"))
        max_redirects = int(block.get("max-redirects") or 5)
        for raw_path in block.get("path") or []:
            url = _interpolate(str(raw_path), target_url)
            resp = transport.get(url, headers=headers, redirects=redirects,
                                 max_redirects=max_redirects)
            if resp is None:
                continue
            event = _event_for(resp)
            matchers = block.get("matchers") or []
            condition = block.get("matchers-condition") or "or"
            matched, detail = run_matchers(matchers, condition, event)
            extracts = run_extractors(block.get("extractors") or [], event)
            if matched:
                return True, extracts, detail
        return False, [], {}

    @staticmethod
    def _finding(tpl: dict, target_url: str, extracts: list[str], match_evidence: list[str]) -> dict:
        info = tpl.get("info") or {}
        classification = info.get("classification") or {}
        cve = classification.get("cve-id") or None
        cve = cve[0] if isinstance(cve, list) else cve
        cwe = classification.get("cwe-id") or None
        cwe = cwe[0] if isinstance(cwe, list) else cwe
        tid = tpl.get("id") or os.path.basename(tpl.get("_path", ""))
        ev = "; ".join(dict.fromkeys([e for e in extracts if e] + [e for e in match_evidence if e])) or None
        return {
            "cve_id": cve, "target_url": target_url,
            "severity": (info.get("severity") or "info").lower(),
            "source_tool": "nuclei-derived",
            "description": f"{info.get('name', tid)} [template {tid}]. "
                           f"Nuclei-style template match"
                           + (f"; extracted: {ev}" if ev else ""),
            "cwe": cwe, "evidence": ev or "template matched", "fix": None,
        }


# --------------------------------------------------------------------------
# Passive lane (ZAP-derived)
# --------------------------------------------------------------------------
ZAP_RISK = {"info": "info", "low": "low", "medium": "medium", "high": "high"}


@dataclass
class PassiveResponse:
    url: str
    method: str = "GET"
    status: int = 200
    headers: dict[str, list[str]] = field(default_factory=dict)
    body: str = ""
    https: bool = True

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or [""])[0].lower()

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type

    def header(self, name: str) -> str | None:
        vals = self.headers.get(name.lower())
        return vals[0] if vals else None

    def header_values(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])


def _cookie_name(value: str) -> str:
    eq, semi = value.find("="), value.find(";")
    if eq == -1 or (semi != -1 and eq > semi):
        return ""
    return value[:eq].strip()


def _cookie_has_attr(value: str, attr: str) -> bool:
    """ZAP CookieUtils.hasAttribute: attributes are the ';'-split tail."""
    parts = value.split(";")
    if len(parts) == 1:
        return False
    return any(p.strip().lower() == attr for p in parts[1:])


def _cookie_expired(value: str) -> bool:
    """ZAP CookieUtils.isExpired: no expires attr -> not expired;
    unparseable or past date -> expired."""
    from email.utils import parsedate_to_datetime
    parts = value.split(";")
    expiry = next((p.split("=", 1)[1].strip() for p in parts[1:]
                   if p.strip().lower().startswith("expires=")), None)
    if expiry is None:
        return False
    try:
        when = parsedate_to_datetime(expiry)
    except Exception:
        return True                      # ZAP: null parse counts as expired
    from datetime import datetime, timezone
    return when.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)


def _cookie_attr_value(value: str, attr: str) -> str | None:
    """ZAP CookieUtils.getAttributeValue: value of 'attr=...' in the tail."""
    parts = value.split(";")
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip().lower() == attr and v.strip():
            return v.strip()
    return None


# zap-extensions pscanrules zapHomeFiles/xml/debug-error-messages.txt (rule 10023)
_DEBUG_ERROR_PATTERNS = (
    "error occurred while processing request",
    "internal server error",
    "test page for apache",
    "failed to open stream: http request failed!",
    "parse error: parse error, unexpected t_variable",
    "the script whose uid is",
    "php parse error",
    "php warning",
    "php error",
    "warning: cannot modify header information - headers already sent",
    "mysqli error is",
    "mysql error is",
    "404 sc_not_found",
    "asp.net_sessionid",
    "servlet error:",
    "under construction",
    "welcome to windows 2000 internet services",
    "welcome to iis 4.0",
    "warning: supplied argument is not a valid file-handle resource",
    "warning: division by zero in",
    "warning: safe mode restriction in effect.",
    "error message : error loading required libraries.",
    "fatal error: call to undefined function",
    "access denied for user",
    "incorrect syntax near",
    "unclosed quotation mark before the character string",
    "there seems to have been a problem with the",
    "customerrors mode",
    "this error page might contain sensitive information because asp.net",
)

# zap-extensions pscanrules zapHomeFiles/xml/URL-information-disclosure-messages.txt
# (rule 10024) - param names matched case-insensitively with 'contains'
_URL_SENSITIVE_NAMES = (
    "user", "username", "pass", "password", "pwd", "token", "ticket",
    "session", "jsessionid", "sessionid",
)

# rule 10024 value patterns (copied from InformationDisclosureInUrlScanRule.java)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b")
_CREDIT_CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}"
    r"|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b")
_US_SSN_RE = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")


def _zap_finding(rule: str, plugin_id: int, target: str, risk: str, cwe: int,
                  evidence: str, description: str) -> dict:
    return {
        "cve_id": None, "target_url": target,
        "severity": ZAP_RISK.get(risk, "info"),
        "source_tool": "zap-derived",
        "description": f"[{plugin_id}] {rule}: {description}",
        "cwe": f"CWE-{cwe}", "evidence": evidence, "fix": None,
    }


class PassiveLane:
    """Ports of zaproxy/zap-extensions pscanrules. Each rule keeps the Java
    trigger conditions, risk level and CWE id of its upstream rule."""

    def scan(self, resp: PassiveResponse) -> list[dict]:
        out: list[dict] = []
        out += self._server_header(resp)
        out += self._x_powered_by(resp)
        out += self._cookie_httponly(resp)
        out += self._cookie_secure(resp)
        out += self._hsts(resp)
        out += self._x_content_type_options(resp)
        out += self._csp_missing(resp)
        out += self._cache_control(resp)
        out += self._cors_wildcard(resp)
        out += self._debug_errors(resp)
        out += self._url_sensitive_info(resp)
        out += self._cookie_samesite(resp)
        out += self._x_frame_options(resp)
        return out

    def _server_header(self, r: PassiveResponse) -> list[dict]:
        # 10036 ServerHeaderInfoLeakScanRule: any digit in Server header value
        finds = []
        for directive in r.header_values("server"):
            if re.search(r"\d", directive):
                finds.append(_zap_finding(
                    "Server Header Info Leak", 10036, r.url, "low", 497, directive,
                    "The web/server header discloses a version number, giving attackers a "
                    "head start (ZAP rule 10036; OWASP A05:2021 Security Misconfiguration)."))
        return finds

    def _x_powered_by(self, r: PassiveResponse) -> list[dict]:
        # 10037 XPoweredByHeaderInfoLeakScanRule: header present at all
        vals = r.header_values("x-powered-by")
        if vals:
            return [_zap_finding("X-Powered-By Info Leak", 10037, r.url, "low", 497,
                                 ", ".join(vals),
                                 "X-Powered-By discloses technology information (ZAP rule 10037).")]
        return []

    def _cookie_httponly(self, r: PassiveResponse) -> list[dict]:
        # 10010 CookieHttpOnlyScanRule: Set-Cookie without HttpOnly, skipping expired cookies
        finds = []
        for value in r.header_values("set-cookie") + r.header_values("set-cookie2"):
            if not _cookie_has_attr(value, "httponly") and not _cookie_expired(value):
                finds.append(_zap_finding(
                    "Cookie No HttpOnly Flag", 10010, r.url, "low", 1004,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' set without the HttpOnly attribute "
                    "(ZAP rule 10010; CWE-1004)."))
        return finds

    def _cookie_secure(self, r: PassiveResponse) -> list[dict]:
        # 10011 CookieSecureFlagScanRule: only checked when request used SSL
        if not r.https:
            return []
        finds = []
        for value in r.header_values("set-cookie") + r.header_values("set-cookie2"):
            if not _cookie_has_attr(value, "secure") and not _cookie_expired(value):
                finds.append(_zap_finding(
                    "Cookie Without Secure Flag", 10011, r.url, "low", 614,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' set over HTTPS without the Secure "
                    "attribute (ZAP rule 10011; CWE-614)."))
        return finds

    def _hsts(self, r: PassiveResponse) -> list[dict]:
        # 10035 StrictTransportSecurityScanRule: HTTPS responses missing HSTS.
        # ZAP skips https redirects to the same host at thresholds above LOW.
        if not r.https:
            return []
        if r.header_values("strict-transport-security"):
            return []
        if r.status in (301, 302, 303, 307, 308):
            loc = r.header("location") or ""
            if not loc.startswith(("http://", "https://", "//")):
                return []          # relative redirect: ZAP skips
            if loc.lower().startswith("https://"):
                from urllib.parse import urlsplit
                req = urlsplit(r.url)
                dst = urlsplit(loc)
                if dst.netloc == req.netloc:
                    return []      # same-host https redirect: ZAP skips
        return [_zap_finding(
            "Strict-Transport-Security Missing", 10035, r.url, "low", 319,
            "(no Strict-Transport-Security header)",
            "HTTPS response does not set HSTS, allowing downgrade and cleartext "
            "interception on later visits (ZAP rule 10035; CWE-319).")]

    def _x_content_type_options(self, r: PassiveResponse) -> list[dict]:
        # 10021: body present, skip 4xx/5xx/redirects, header missing
        if len(r.body) == 0:
            return []
        if r.status >= 400 or r.status in (301, 302, 303, 307, 308):
            return []
        if r.header_values("x-content-type-options"):
            return []
        return [_zap_finding(
            "X-Content-Type-Options Missing", 10021, r.url, "low", 693,
            "(no X-Content-Type-Options header)",
            "Response lacks nosniff, allowing MIME-type confusion/sniffing attacks "
            "(ZAP rule 10021; CWE-693).")]

    def _csp_missing(self, r: PassiveResponse) -> list[dict]:
        # 10038: HTML non-redirect responses; no CSP header and no meta CSP
        if not r.is_html:
            return []
        if r.status in (301, 302, 303, 307, 308):
            return []
        if r.header_values("content-security-policy"):
            return []
        if re.search(r"<meta[^>]+http-equiv=[\"']?content-security-policy[\"']?",
                     r.body, re.I):
            return []              # meta CSP present (ZAP checks the parsed DOM)
        return [_zap_finding(
            "Content-Security-Policy Missing", 10038, r.url, "medium", 693,
            "(no Content-Security-Policy header)",
            "No CSP header or meta policy: inline script injection is not constrained "
            "(ZAP rule 10038; CWE-693, WASC-15).")]

    def _cache_control(self, r: PassiveResponse) -> list[dict]:
        # 10015: HTTPS + body + not image; applies to text-ish content.
        # Alert when header missing or any of no-store/no-cache/must-revalidate absent.
        if not r.https or len(r.body) == 0:
            return []
        if r.method == "POST" or r.content_type.startswith("image/"):
            return []
        if r.status >= 400 or r.status in (301, 302, 303, 307, 308):
            return []
        ct = r.content_type
        if not (ct.startswith("text/") or "json" in ct or "xml" in ct):
            return []
        joined = ", ".join(r.header_values("cache-control")).lower()
        if (not joined or "no-store" not in joined or "no-cache" not in joined
                or "must-revalidate" not in joined):
            return [_zap_finding(
                "Re-examine Cache Policy Directives", 10015, r.url, "info", 525,
                joined or "(no Cache-Control header)",
                "Cache-Control does not combine no-store, no-cache and "
                "must-revalidate, so sensitive content may be cached (ZAP rule 10015).")]
        return []

    def _cors_wildcard(self, r: PassiveResponse) -> list[dict]:
        # 10098 CrossDomainMisconfigurationScanRule: ACAO == "*"
        acao = r.header("access-control-allow-origin")
        if acao is not None and acao.strip() == "*":
            return [_zap_finding(
                "Cross-Domain Misconfiguration", 10098, r.url, "medium", 264,
                "Access-Control-Allow-Origin: *",
                "Wildcard CORS lets any origin read responses credentialed or not "
                "(ZAP rule 10098; CWE-264).")]
        return []

    def _debug_errors(self, r: PassiveResponse) -> list[dict]:
        # 10023 InformationDisclosureDebugErrorsScanRule: response body contains a
        # known debug/error string (case-insensitive substring; text responses only).
        # Risk LOW, CWE-1295, WASC-13.
        ct = r.content_type
        # ZAP HttpHeader.isText(): text/* plus common texty application types.
        if ct and not (ct.startswith("text/") or "json" in ct or "xml" in ct
                       or "javascript" in ct or "yaml" in ct):
            return []
        if len(r.body) == 0:
            return []
        low = r.body.lower()
        for pat in _DEBUG_ERROR_PATTERNS:
            if pat in low:
                start = low.index(pat)
                return [_zap_finding(
                    "Information Disclosure - Debug Error Messages", 10023, r.url,
                    "low", 1295, r.body[start:start + len(pat)],
                    "The response discloses a debug/error message that leaks stack "
                    "traces, SQL fragments or internal paths (ZAP rule 10023; "
                    "CWE-1295).")]
        return []

    def _url_sensitive_info(self, r: PassiveResponse) -> list[dict]:
        # 10024 InformationDisclosureInUrlScanRule: query parameter NAMES that
        # contain a sensitive word (case-insensitive 'contains'), and parameter
        # VALUES that look like emails / credit cards / US SSNs.
        # Risk INFO, CWE-598, WASC-13.
        from urllib.parse import urlsplit, parse_qsl
        query = urlsplit(r.url).query
        if not query:
            return []
        finds: list[dict] = []
        for name, value in parse_qsl(query, keep_blank_values=True):
            n = name.lower()
            for s in _URL_SENSITIVE_NAMES:
                if s in n:
                    finds.append(_zap_finding(
                        "Information Disclosure - Sensitive Information in URL",
                        10024, r.url, "info", 598, f"{name}={value}",
                        f"Query parameter '{name}' carries sensitive information "
                        f"(matched upstream token '{s}'); URLs leak into logs, "
                        "Referer headers and browser history (ZAP rule 10024; "
                        "CWE-598)."))
                    break
            if _EMAIL_RE.search(value):
                finds.append(_zap_finding(
                    "Information Disclosure - Email Address in URL", 10024, r.url,
                    "info", 598, f"{name}={value}",
                    f"Value of parameter '{name}' looks like an email address "
                    "(ZAP rule 10024; CWE-598)."))
            if _CREDIT_CARD_RE.search(value):
                finds.append(_zap_finding(
                    "Information Disclosure - Credit Card in URL", 10024, r.url,
                    "info", 598, f"{name}=*redacted*",
                    f"Value of parameter '{name}' matches a credit card pattern "
                    "(ZAP rule 10024; CWE-598)."))
            if _US_SSN_RE.search(value):
                finds.append(_zap_finding(
                    "Information Disclosure - US SSN in URL", 10024, r.url,
                    "info", 598, f"{name}=*redacted*",
                    f"Value of parameter '{name}' matches a US Social Security "
                    "Number pattern (ZAP rule 10024; CWE-598)."))
        return finds

    def _cookie_samesite(self, r: PassiveResponse) -> list[dict]:
        # 10054 CookieSameSiteScanRule (skip expired cookies):
        #   -1 SameSite attribute missing       Risk LOW, CWE-1275, WASC-13
        #   -2 SameSite=None (not at HIGH threshold)
        #   -3 SameSite with an illegal value
        finds: list[dict] = []
        for value in r.header_values("set-cookie") + r.header_values("set-cookie2"):
            if _cookie_expired(value):
                continue
            ss = _cookie_attr_value(value, "samesite")
            if ss is None:
                finds.append(_zap_finding(
                    "Cookie without SameSite Attribute", 10054, r.url, "low", 1275,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' has no SameSite attribute, so "
                    "it is sent on cross-site requests and is exposed to CSRF "
                    "(ZAP rule 10054-1; CWE-1275)."))
            elif ss.lower() == "none":
                finds.append(_zap_finding(
                    "Cookie with SameSite None", 10054, r.url, "low", 1275,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' uses SameSite=None, sending it "
                    "on every cross-site request (ZAP rule 10054-2; CWE-1275)."))
            elif ss.lower() not in ("strict", "lax", "none"):
                finds.append(_zap_finding(
                    "Cookie with Invalid SameSite Value", 10054, r.url, "low", 1275,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' has an unrecognised SameSite "
                    f"value '{ss}', which browsers treat as unset (ZAP rule "
                    "10054-3; CWE-1275)."))
        return finds

    def _x_frame_options(self, r: PassiveResponse) -> list[dict]:
        # 10020 AntiClickjackingScanRule at ZAP's default (MEDIUM) threshold:
        # HTML, non-empty text body, not an error/redirect. CSP frame-ancestors
        # takes precedence (no alert when present). XFO missing -> alert; XFO
        # value without deny/sameorigin -> malformed; duplicate XFO headers ->
        # multiple-headers alert. Risk MEDIUM, CWE-1021, WASC-15.
        if not r.is_html or len(r.body) == 0:
            return []
        if r.status >= 400 or r.status in (301, 302, 303, 307, 308):
            return []
        csp_vals = r.header_values("content-security-policy")
        if any("frame-ancestors" in c for c in csp_vals):
            return []                # ZAP: CSP frame-ancestors takes precedence
        finds: list[dict] = []
        xfo = r.header_values("x-frame-options")
        if not xfo:
            finds.append(_zap_finding(
                "Anti-clickjacking X-Frame-Options header missing", 10020, r.url,
                "medium", 1021, "(no X-Frame-Options header)",
                "The response does not set X-Frame-Options (or a CSP "
                "frame-ancestors policy), so the page can be embedded in a frame "
                "and used in clickjacking attacks (ZAP rule 10020-1; CWE-1021)."))
        else:
            for v in xfo:
                lv = v.lower()
                if "deny" not in lv and "sameorigin" not in lv:
                    finds.append(_zap_finding(
                        "X-Frame-Options Setting Malformed", 10020, r.url, "medium",
                        1021, v,
                        f"X-Frame-Options value '{v}' is not DENY or SAMEORIGIN "
                        "and will be ignored by browsers (ZAP rule 10020-4; "
                        "CWE-1021)."))
            if len(xfo) > 1:
                finds.append(_zap_finding(
                    "Multiple X-Frame-Options Header Entries", 10020, r.url,
                    "medium", 1021, "; ".join(xfo),
                    "Multiple X-Frame-Options headers are present; browsers apply "
                    "only one, which may not be the secure one (ZAP rule 10020-2; "
                    "CWE-1021)."))
        return finds


# --------------------------------------------------------------------------
# Repo acquisition (GitHub codeload tarball / local walk)
# --------------------------------------------------------------------------
_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}


def github_repo_files(repo_url: str, max_files: int = 400) -> dict[str, str]:
    """Download HEAD tarball of owner/repo and return {relpath: text} for the
    manifests TRIAD scans (trivy-style: manifests anywhere in the tree)."""
    from urllib.parse import urlsplit
    parts = urlsplit(repo_url).path.strip("/").split("/")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    tar_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
    with urllib.request.urlopen(tar_url, timeout=30) as resp:
        blob = resp.read()
    files: dict[str, str] = {}
    with tarfile.open(fileobj=BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.size > 1_000_000:
                continue
            name = os.path.basename(member.name)
            if name not in MANIFEST_PARSERS:
                continue
            rel = "/".join(member.name.split("/")[1:]) or member.name
            if any(seg in _SKIP_DIRS for seg in rel.split("/")):
                continue
            files[rel] = tar.extractfile(member).read().decode("utf-8", "replace")
            if len(files) >= max_files:
                break
    return files


def local_repo_files(root: str, max_files: int = 400) -> dict[str, str]:
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if fname not in MANIFEST_PARSERS:
                continue
            path = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(path) > 1_000_000:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    files[os.path.relpath(path, root)] = fh.read()
            except OSError:
                continue
            if len(files) >= max_files:
                return files
    return files


def response_to_passive(resp: dict) -> PassiveResponse:
    """Adapt a Transport response dict to the PassiveLane input."""
    header_blob, _, body = resp["raw"].partition("\r\n\r\n")
    headers: dict[str, list[str]] = {}
    for line in header_blob.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    return PassiveResponse(
        url=resp["url"], method="GET", status=resp["status"], headers=headers,
        body=body, https=resp["url"].lower().startswith("https://"),
    )


# --------------------------------------------------------------------------
# TRIAD_Scanner
# --------------------------------------------------------------------------
class TRIAD_Scanner:
    """Single-input scanner: GitHub repo URL OR live website URL (or local dir).

    GitHub repo -> Trivy-derived dependency lane.
    Live URL    -> Nuclei-derived template lane, then ZAP-derived passive lane.

    DEMO_MODE mocks the TARGET (fixtures), never the ENGINE: the same matching
    code runs, instantly, with zero network.
    """

    def __init__(self, templates_dir: str = DEFAULT_TEMPLATES,
                 index_path: str = DEFAULT_INDEX, demo_dir: str = DEFAULT_DEMO_DIR,
                 timeout: float = 8.0):
        self.deps = DependencyLane(index_path)
        self.templates = load_templates(templates_dir)
        self.template_lane = TemplateLane(self.templates)
        self.passive_lane = PassiveLane()
        self.demo_dir = demo_dir
        self.timeout = timeout

    # -- public API ---------------------------------------------------------
    def scan(self, target: str, demo: bool | None = None) -> dict:
        demo = (os.environ.get("TRIAD_DEMO_MODE", "0") == "1") if demo is None else demo
        started = time.time()
        kind, normalized = classify_target(target)
        findings: list[dict] = []
        routed_as = kind
        if kind in ("invalid",):
            return self._report(target, routed_as, demo, started, [
                {"cve_id": None, "target_url": target, "severity": "info",
                 "source_tool": "triad-router", "description":
                 f"Input could not be routed (got: {target!r}). Expected a GitHub "
                 "repo URL, an http(s) URL, or an existing directory path.",
                 "cwe": None, "evidence": None, "fix": None}])
        if kind in ("github", "local"):
            routed_as = f"{kind}:trivy-dependencies"
            findings = self._scan_dependencies(normalized, demo)
        elif kind == "web":
            routed_as = "web:nuclei-templates+zap-passive"
            findings = self._scan_web(normalized, demo)
        return self._report(normalized, routed_as, demo, started, findings)

    def to_json(self, target: str, demo: bool | None = None, indent: int | None = 2) -> str:
        return json.dumps(self.scan(target, demo=demo)["findings"], indent=indent)

    # -- lanes --------------------------------------------------------------
    def _scan_dependencies(self, target: str, demo: bool) -> list[dict]:
        if demo:
            files = local_repo_files(self.demo_dir)
            files = {k: v for k, v in files.items() if not k.startswith("web_")}
        elif target.startswith("https://github.com/") or target.startswith("http://github.com/"):
            files = github_repo_files(target)
        else:
            files = local_repo_files(target)
        if not files:
            return [{
                "cve_id": None, "target_url": target, "severity": "info",
                "source_tool": "triad-derived",
                "description": "No dependency manifests (package.json, "
                               "requirements.txt, pyproject.toml) found.",
                "cwe": None, "evidence": None, "fix": None}]
        return self.deps.scan_manifests(files, target)

    def _scan_web(self, target: str, demo: bool) -> list[dict]:
        base = target if target.count("/") > 3 else target.rstrip("/") + "/"
        if demo:
            with open(os.path.join(self.demo_dir, "web_fixture.json"), encoding="utf-8") as fh:
                fixture = json.load(fh)
            transport: Transport = FixtureTransport(fixture)
        else:
            transport = LiveTransport(timeout=self.timeout)
        findings = []
        findings += self.template_lane.scan(base, transport)
        root = transport.get(base)
        if root is not None:
            findings += self.passive_lane.scan(response_to_passive(root))
        if not findings:
            return [{
                "cve_id": None, "target_url": base, "severity": "info",
                "source_tool": "triad-router",
                "description": "Target reachable but no template matched and no "
                               "passive rule fired.",
                "cwe": None, "evidence": None, "fix": None}]
        return findings

    # -- report -------------------------------------------------------------
    @staticmethod
    def _report(target: str, routed_as: str, demo: bool, started: float,
                findings: list[dict]) -> dict:
        findings.sort(key=lambda f: (f.get("severity") != "critical",
                                     f.get("severity") != "high",
                                     f.get("severity") != "medium",
                                     f.get("severity") != "low",
                                     f.get("cve_id") or ""))
        return {
            "target": target,
            "routed_as": routed_as,
            "demo_mode": demo,
            "scan_id": f"triad-{int(started * 1000):013x}",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "duration_ms": int((time.time() - started) * 1000),
            "finding_count": len(findings),
            "findings": findings,
        }


__all__ = [
    "TRIAD_Scanner", "classify_target", "DependencyLane", "TemplateLane",
    "PassiveLane", "LiveTransport", "FixtureTransport", "load_templates",
    "is_vulnerable", "matches_constraints", "PassiveResponse",
]
