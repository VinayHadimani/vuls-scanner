# TRIAD_Scanner

Unified lightweight vulnerability scanner for the **TRIAD** hackathon platform
(Agentic AI Vulnerability Intelligence: `INGEST -> ENRICH (NVD/EPSS) -> FUSE -> EXPLAIN`).
This package is the **INGEST** stage. It merges the core detection mechanisms of three
open-source scanners into one Python module — no Go, no Java, no heavyweight runtimes.

```
trivy 0.76.1     ->  dependency lane   (manifests -> CVE version-range matching)
nuclei 3.11.1    ->  template lane     (YAML templates -> HTTP matchers/extractors)
ZAP (weekly)     ->  passive lane      (HTTP header/cookie/body misconfiguration rules)
```

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# demo-safe API (default: DEMO_MODE=1, instant, zero network)
uvicorn server:app --port 8000
curl -X POST localhost:8000/scan -H 'Content-Type: application/json' \
     -d '{"target":"https://github.com/triad/demo-app"}'

# live scanning
curl -X POST localhost:8000/scan -H 'Content-Type: application/json' \
     -d '{"target":"https://github.com/gothinkster/node-express-realworld-example-app","demo":false}'
curl -X POST localhost:8000/scan -H 'Content-Type: application/json' \
     -d '{"target":"https://your-authorized-target.example","demo":false}'
```

Or as a library:

```python
from triad_scanner import TRIAD_Scanner
scanner = TRIAD_Scanner()
report = scanner.scan("https://github.com/owner/repo")   # demo mode via TRIAD_DEMO_MODE env
print(scanner.to_json("https://example.com"))            # the standardized findings array
```

## Input routing (single input, automatic)

| Input                                  | Routed as                      | Lanes run                        |
|----------------------------------------|--------------------------------|----------------------------------|
| `https://github.com/owner/repo(.git)`  | `github:trivy-dependencies`    | dependency (trivy-derived)       |
| local directory path                   | `local:trivy-dependencies`     | dependency (trivy-derived)       |
| `http(s)://…` or `host.tld`            | `web:nuclei-templates+zap-passive` | template then passive        |

## Output contract

`POST /scan` returns a report envelope; `findings` is the standardized JSON array
TRIAD's ENRICH stage consumes. Every finding **always** carries the five required keys:

```json
{
  "cve_id": "CVE-2021-41773",          // or null (CWE-based passive/template findings)
  "target_url": "https://…",
  "severity": "high",                  // critical|high|medium|low|info|unknown
  "source_tool": "nuclei-derived",     // triad-derived | nuclei-derived | zap-derived
  "description": "…",
  "cwe": "CWE-22",                     // optional enrichment
  "evidence": "root:x:0:0…",           // optional enrichment (feeds EXPLAIN/RAG)
  "fix": "4.17.21"                     // optional enrichment
}
```

`cve_id`-bearing findings are ready for NVD/EPSS queries; `cve_id: null` findings are
CWE-class misconfigurations (ZAP's passive model) — query them by CWE in the ENRICH stage.

## DEMO_MODE

`DEMO_MODE=1` (server default) **mocks the target, never the engine**: the same
matching code runs against built-in fixtures (`data/demo/`) and returns in <100 ms
with no network. The fixture web target is a deliberately misconfigured
Apache/2.4.49 host; the fixture repo pins real historical versions (lodash 4.17.20,
requests 2.25.0, Django 3.2 …). Set `DEMO_MODE=0` or pass `"demo": false` per call
for live scanning.

## Data provenance (no hallucinated vulnerability data)

`data/dep_cve_index.json` is generated from the **live OSV API** by
`scripts/build_dep_index.py` (upstream of trivy-db's own OSV pipeline). 587 advisories
across npm/lodash,express,ws,request,moment and pip/requests,flask,django,pillow,numpy.
Range semantics are a port of trivy-db `pkg/vulnsrc/osv/range.go`
(`introduced -> ">=X"`, `fixed -> "<Y"`, `last_affected -> "<=Z"`).
Provenance (fetch timestamp, counts) is recorded inside the file and served at `/health`.
Re-run the builder any time to refresh.

## Reverse-engineering provenance (per lane)

**Trivy lane** — trivy v0.76.1 (aquasecurity/trivy + aquasecurity/trivy-db):
- manifest parsers: `pkg/dependency/parser/nodejs/packagejson/parse.go`,
  `pkg/dependency/parser/nodejs/npm/parse.go`, `pkg/dependency/parser/python/pip/parse.go`
- detection flow: `pkg/detector/library/driver.go` (`DetectVulnerabilities`)
- matching semantics: `pkg/detector/library/compare/compare.go` (`IsVulnerable`:
  fail-open on empty ranges, vulnerable OR-groups, patched exclusion) with the npm
  comparer (`go-npm-version`, prerelease-enabled full ordering) and PEP 440 comparer
- index build: trivy-db `pkg/vulnsrc/osv/{osv,range}.go`
- REA binary-level confirmation: trivy 0.76.1 embeds `aquasecurity/trivy-db`,
  `aquasecurity/go-version`, `Masterminds/semver/v3`, `blang/semver/v4` (Go 1.27.3)

**Nuclei lane** — nuclei v3.11.1 (projectdiscovery/nuclei):
- matchers-condition default OR: `pkg/operators/operators.go` (Compile)
- word/regex/status matchers, per-matcher conditions, negative, case-insensitive:
  `pkg/operators/matchers/match.go`
- parts mapping (`body` default, `header` -> all headers, `all`, `response`) and the
  response event map: `pkg/protocols/http/operators.go`
- extractors (regex group / kval / json): `pkg/operators/extractors/extract.go`
- `{{BaseURL}}`-style interpolation: `pkg/protocols/http/build_request.go`
- template `classification.cve-id` / `cwe-id` / `severity`: `pkg/model/model.go`

**ZAP lane** — zaproxy weekly + zap-extensions `pscanrules`:
- passive framework: `org.zaproxy.zap.extension.pscan.PassiveScanner` (zaproxy core)
- ported rules (exact trigger conditions, risk levels, CWE ids, plugin ids):
  10036 ServerHeaderInfoLeak, 10037 XPoweredByHeaderInfoLeak, 10010 CookieHttpOnly,
  10011 CookieSecureFlag, 10035 StrictTransportSecurity, 10021 XContentTypeOptions,
  10038 ContentSecurityPolicyMissing, 10015 CacheControl, 10098 CrossDomainMisconfig,
  10023 InformationDisclosureDebugErrors (29 upstream patterns from
  `zapHomeFiles/xml/debug-error-messages.txt`), 10024 InformationDisclosureInUrl
  (name tokens from `URL-information-disclosure-messages.txt` + email/CC/SSN value
  patterns from `InformationDisclosureInUrlScanRule.java`), 10054 CookieSameSite
  (missing/None/invalid-value alert refs), 10020 AntiClickjacking (XFO
  missing/malformed/multiple; CSP `frame-ancestors` precedence)
- cookie attribute/expiry helpers: `addOns/commonlib/.../CookieUtils.java`
- REA artifact-level confirmation: ZAP weekly ships `pscanrules-release-78.zap`,
  `pscan-alpha-0.7.0.zap`, `automation-beta` inside the distribution

## Deliberate subset (lightweight for the hackathon)

- Matchers: `status`, `word`, `regex` (DSL/binary/xpath/LLM matchers out of scope)
- Extractors: `regex` (group), `kval`, `json` (dotted path + `[N]`, not full jq)
- Manifests: `package.json`, `requirements.txt`, `pyproject.toml`; range specs in
  package.json are approximated by their lower bound (exact pins preferred)
- Template engine: GET requests (with per-template custom headers),
  `{{BaseURL}}/{{RootURL}}/{{Host}}/{{Scheme}}`,
  optional redirects with `max-redirects`; raw requests, fuzzing, pipelines excluded
- Passive lane: the fetched root response (ZAP baseline = spider + passive; no active scan)

## Bundled templates (12)

| Template | Severity | Engine features exercised |
|---|---|---|
| apache-path-traversal-cve-2021-41773 | high | word+status AND, regex extractor |
| dot-env-file-exposure | high | word+status AND, regex extractor |
| cors-misconfiguration | medium | custom Origin header, case-insensitive header regex, kval |
| git-config-exposure | medium | word+status AND, regex extractor |
| git-head-exposure | medium | word+status AND |
| phpinfo-exposure | medium | multi-path probes, regex extractor |
| springboot-actuator-exposed | medium | json extractor (dotted paths) |
| tomcat-manager-exposed | medium | status list (200/401), regex extractor |
| open-directory-listing | low | word+status AND |
| jenkins-detection | info | status list (200/401/403), multi-word OR |
| swagger-ui-exposed | info | multi-path, multi-word OR |
| tech-server-header | info | kval extractors |

## Ethics / authorization

The template lane sends a handful of read-only GET requests to the target you name.
Only scan targets you are authorized to scan. The demo fixtures exist so you never
need to point it at anyone else's infrastructure.

## Tests

```bash
python -m pytest tests/ -q      # 51 tests: engines, parsers, rules, live fixture, API
python tests/fixture_server.py  # stand-alone "vulnerable target" for manual demos
```
