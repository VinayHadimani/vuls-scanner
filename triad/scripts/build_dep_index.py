#!/usr/bin/env python3
"""Build triad/data/dep_cve_index.json from LIVE OSV API data.

Provenance: every advisory in the index is fetched from https://api.osv.dev/v1/query
at build time and converted with the same range semantics trivy-db uses
(pkg/vulnsrc/osv/range.go): introduced -> ">=X", fixed -> "<Y",
last_affected -> "<=Z", introduced "0" -> omit lower bound.

No hand-written vulnerability data. Re-run this script any time to refresh:
    python3 scripts/build_dep_index.py
"""
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

OSV_QUERY = "https://api.osv.dev/v1/query"
# OSV ecosystem names (https://osv.dev/list) vs trivy bucket names
OSV_ECOSYSTEM = {"npm": "npm", "pip": "PyPI"}
PACKAGES = {
    # ecosystem bucket names mirror trivy's ecosystem.Type buckets
    "npm": ["lodash", "express", "ws", "request", "moment"],
    "pip": ["requests", "flask", "django", "pillow", "numpy"],
}


def osv_query(ecosystem, name):
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(
        OSV_QUERY, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def range_to_constraints(events):
    """Port of trivy-db pkg/vulnsrc/osv/range.go String() semantics."""
    groups = []
    current = None  # [lower, upper] constraint pieces
    for ev in events:
        if "introduced" in ev:
            if current is not None:
                groups.append(current)
            lower = ev["introduced"]
            current = {"lower": None if lower == "0" else lower, "upper": None, "upper_inclusive": False}
        elif "fixed" in ev:
            current["upper"] = ev["fixed"]
            current["upper_inclusive"] = False
        elif "last_affected" in ev:
            current["upper"] = ev["last_affected"]
            current["upper_inclusive"] = True
    if current is not None:
        groups.append(current)

    constraints = []
    fixed_versions = []
    for g in groups:
        parts = []
        if g["lower"]:
            parts.append(f">={g['lower']}")
        if g["upper"]:
            op = "<=" if g["upper_inclusive"] else "<"
            parts.append(f"{op}{g['upper']}")
            if not g["upper_inclusive"]:
                fixed_versions.append(g["upper"])
        if parts:
            constraints.append(", ".join(parts))
    return constraints, sorted(set(fixed_versions))


def severity_of(vuln):
    ds = vuln.get("database_specific") or {}
    sev = (ds.get("severity") or "").upper()
    mapping = {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium",
               "HIGH": "high", "CRITICAL": "critical"}
    return mapping.get(sev, "unknown")


def first_cve(vuln):
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id")  # fall back to GHSA id


def main():
    out = {"provenance": {}, "advisories": {}}
    total = 0
    errors = []
    for eco, names in PACKAGES.items():
        out["advisories"][eco] = {}
        for name in names:
            try:
                data = osv_query(OSV_ECOSYSTEM[eco], name)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{eco}/{name}: {exc}")
                continue
            entries = []
            for vuln in data.get("vulns", []):
                affected = [
                    a for a in vuln.get("affected", [])
                    if a.get("package", {}).get("name", "").lower() == name.lower()
                    and a.get("package", {}).get("ecosystem", "").lower() == OSV_ECOSYSTEM[eco].lower()
                ]
                constraints, fixed_versions = [], []
                for a in affected:
                    for rng in a.get("ranges", []):
                        if rng.get("type") == "GIT":
                            continue  # trivy-db skips GIT ranges
                        if rng.get("type") in ("SEMVER", "ECOSYSTEM"):
                            c, f = range_to_constraints(rng.get("events", []))
                            constraints += c
                            fixed_versions += f
                    # trivy-db: affected.versions -> "=<version>" constraints
                    for v in a.get("versions", []) or []:
                        constraints.append(f"={v}")
                if not constraints:
                    # advisory with no resolvable ranges for this package: mark affected-all (trivy fail-open)
                    constraints = ["*"]
                entries.append({
                    "vulnerability_id": first_cve(vuln),
                    "aliases": vuln.get("aliases", []),
                    "osv_id": vuln.get("id"),
                    "summary": vuln.get("summary") or (vuln.get("details") or "")[:180],
                    "severity": severity_of(vuln),
                    "vulnerable_versions": constraints,      # OR across entries, AND inside entry
                    "fixed_versions": sorted(set(fixed_versions)),
                    "url": f"https://osv.dev/vulnerability/{vuln.get('id')}",
                })
                total += 1
            # OSV can carry the same CVE from multiple upstreams (GHSA + PYSEC).
            # Dedupe by primary vulnerability_id, preferring records with a known severity.
            entries.sort(key=lambda e: (e["severity"] == "unknown",))
            deduped: dict[str, dict] = {}
            for e in entries:
                key = e["vulnerability_id"]
                if key in deduped:
                    kept = deduped[key]
                    kept["aliases"] = sorted(set(kept["aliases"]) | set(e["aliases"]))
                    kept["fixed_versions"] = sorted(set(kept["fixed_versions"]) | set(e["fixed_versions"]))
                    kept["vulnerable_versions"] = list(dict.fromkeys(
                        kept["vulnerable_versions"] + e["vulnerable_versions"]))
                    if kept["severity"] == "unknown":
                        kept["severity"] = e["severity"]
                else:
                    deduped[key] = e
            entries = list(deduped.values())
            out["advisories"][eco][name] = entries
    out["provenance"] = {
        "source": "OSV API (https://api.osv.dev/v1/query), upstream of trivy-db's OSV pipeline",
        "range_semantics": "trivy-db pkg/vulnsrc/osv/range.go: introduced->'>=X', fixed->'<Y', last_affected->'<=Z', '0' omits lower bound",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "packages_queried": sum(len(v) for v in PACKAGES.values()),
        "advisory_count": total,
        "errors": errors,
    }
    dest = "/home/z/my-project/download/triad/data/dep_cve_index.json"
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
    print(f"wrote {dest}: {total} advisories, errors={errors}")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
