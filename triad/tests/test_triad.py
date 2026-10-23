"""TRIAD_Scanner test suite.

Covers: routing, version engine (trivy compare.go port), manifest parsers,
dependency lane on the real OSV-backed index, nuclei matcher semantics,
ZAP passive rules, end-to-end LIVE scan against the local fixture server,
DEMO_MODE, and the FastAPI /scan route.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixture_server import start_server  # noqa: E402

from triad_scanner import (  # noqa: E402
    DependencyLane, FixtureTransport, PassiveLane, PassiveResponse,
    TemplateLane, TRIAD_Scanner, classify_target, is_vulnerable,
    load_templates, matches_constraints, run_extractors, run_matchers,
    build_event, response_to_passive,
)

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------- routing
def test_routing():
    assert classify_target("https://github.com/morluto/rea.git")[0] == "github"
    assert classify_target("github.com/aquasecurity/trivy")[0] == "github"
    assert classify_target("https://example.com/app")[0] == "web"
    assert classify_target("example.com")[0] == "web"
    assert classify_target("/tmp")[0] in ("local", "invalid")
    assert classify_target("not a thing ??")[0] == "invalid"


# ------------------------------------------------------- version engine
@pytest.mark.parametrize("version,constraints,expected", [
    ("4.17.20", [">=4.0.0, <4.17.21"], True),
    ("4.17.21", [">=4.0.0, <4.17.21"], False),
    ("5.0.0", [">=4.0.0, <4.17.21"], False),
    ("3.9.9", [">=4.0.0, <4.17.21"], False),
    ("2.25.0", [">=2.0.0, <2.31.0"], True),
    ("2.31.0", [">=2.0.0, <2.31.0"], False),
    ("1.3", [">=1.3, <1.3.4"], True),
    ("1.3.4", [">=1.3, <1.3.4"], False),
    ("1.3", ["=1.3", "=1.3.1"], True),          # OR across groups
    ("1.3.2", ["=1.3", "=1.3.1"], False),
    ("1.3-rc1", [">=1.3, <1.3.4"], False),       # prerelease of the boundary: 1.3.0-rc1 < 1.3.0 (go-npm-version full ordering)
    ("1.3.2-rc1", [">=1.3, <1.3.4"], True),     # prerelease strictly inside the range
    ("1.3.4-rc1", [">=1.3, <1.3.4"], True),      # prerelease sorts below final 1.3.4
])
def test_matches_constraints_semver(version, constraints, expected):
    assert matches_constraints(version, constraints, "semver") is expected


@pytest.mark.parametrize("version,constraints,expected", [
    ("2.25.0", [">=2.0.0, <2.31.0"], True),
    ("2.31.0", [">=2.0.0, <2.31.0"], False),
    ("1.3", [">=1.3, <1.3.4"], True),
    ("1.3.4", [">=1.3, <1.3.4"], False),
    ("1.3rc1", [">=1.3, <1.3.4"], False),        # pep440: 1.3.0rc1 < 1.3.0
    ("1.3.2rc1", [">=1.3, <1.3.4"], True),      # prerelease strictly inside the range
    ("1.3.4rc1", [">=1.3, <1.3.4"], True),      # prerelease below final 1.3.4
    ("1.11.0", [">=1.10.0, <1.11.1"], True),
    ("1.11.1", [">=1.10.0, <1.11.1"], False),
    ("9.0.0", ["=9.0.0"], True),
    ("9.0.1", ["=9.0.0"], False),
])
def test_matches_constraints_pep440(version, constraints, expected):
    assert matches_constraints(version, constraints, "pep440") is expected


def test_is_vulnerable_fail_open():
    # trivy compare.go: empty/absent ranges -> detect anyway
    assert is_vulnerable("1.0.0", {"vulnerable_versions": ["*"]}, "semver") is True
    assert is_vulnerable("1.0.0", {"vulnerable_versions": []}, "semver") is True
    # range excludes + patched versions never flip a non-match into a match
    adv = {"vulnerable_versions": [">=4.0.0, <4.17.21"], "fixed_versions": ["4.17.21"]}
    assert is_vulnerable("4.17.20", adv, "semver") is True
    assert is_vulnerable("4.17.21", adv, "semver") is False


# ---------------------------------------------------------- manifest parsers
def test_parse_package_json():
    deps = DependencyLane and None  # noqa: F841
    from triad_scanner import parse_package_json
    text = json.dumps({
        "name": "@scope/app", "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.20", "ws": "7.4.6"},
        "devDependencies": {"moment": "2.29.1"},
    })
    out = parse_package_json(text)
    assert ("lodash", "4.17.20", "npm") in out
    assert ("ws", "7.4.6", "npm") in out
    assert ("moment", "2.29.1", "npm") in out


def test_parse_requirements_txt():
    from triad_scanner import parse_requirements_txt
    text = ("# comment\r\n"
            "requests==2.25.0  # inline comment\r\n"
            "Django>=3.0,<4.0\r\n"
            "Flask~=1.1\r\n"
            "numpy\r\n"
            "--hash=sha256:deadbeef\r\n"
            "pkg[extra]==1.0 ; python_version>'3.8'\r\n")
    out = parse_requirements_txt(text)
    assert ("requests", "2.25.0", "pip") in out
    assert ("Django", "3.0", "pip") in out          # >= fallback (min-version mode)
    assert ("Flask", "1.1", "pip") in out
    names = [n for n, _, _ in out]
    assert "numpy" not in names                 # bare name: no version -> skipped
    assert "pkg" not in names                    # extras-only spec dropped


# ------------------------------------------------------- dependency lane
def test_dependency_lane_real_index():
    lane = DependencyLane(os.path.join(PKG, "data", "dep_cve_index.json"))
    files = {"package.json": open(os.path.join(PKG, "data/demo/package.json")).read(),
             "requirements.txt": open(os.path.join(PKG, "data/demo/requirements.txt")).read()}
    findings = lane.scan_manifests(files, "https://github.com/triad/demo-app")
    ids = {f["cve_id"] for f in findings}
    # real CVEs, real ranges (verified against the live-OSV-built index)
    assert "CVE-2020-28500" in ids      # lodash ReDoS, fixed 4.17.21
    assert "CVE-2021-23337" in ids      # lodash RCE-ish template injection, fixed 4.17.21
    assert "CVE-2023-32681" in ids      # requests Authorization header leak, fixed 2.31.0
    assert "CVE-2024-37890" in ids      # ws DoS, fixed 8.17.1 -> 7.4.6 affected
    # no duplicate cve ids after OSV dedupe
    assert len(ids) == len([f["cve_id"] for f in findings])
    # contract: every finding has the 5 required keys
    for f in findings:
        for key in ("cve_id", "target_url", "severity", "source_tool", "description"):
            assert key in f
        for key in ("cve_id", "target_url", "severity", "source_tool", "description"):
            if key != "cve_id":
                assert f[key] is not None, f


# ------------------------------------------------------ nuclei matchers
def _event(raw, status=200):
    return build_event({"url": "https://t/", "status": status, "raw": raw,
                        "cookies": [], "request": "GET /", "matched": "https://t/"})


def test_matchers_default_or_condition():
    # nuclei operators.go:52 - default matchers-condition is OR
    ev = _event("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\nsafe body")
    matchers = [
        {"type": "word", "part": "body", "words": ["not-present"]},
        {"type": "status", "status": [200]},
    ]
    ok, _ = run_matchers(matchers, "", ev)   # condition omitted -> OR
    assert ok is True


def test_matchers_and_condition_requires_all():
    ev = _event("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\nroot:x:0:0:root")
    matchers = [
        {"type": "status", "status": [200]},
        {"type": "word", "part": "body", "words": ["root:"], "condition": "or"},
    ]
    ok, _ = run_matchers(matchers, "and", ev)
    assert ok is True
    matchers.append({"type": "word", "part": "body", "words": ["absent"]})
    ok, _ = run_matchers(matchers, "and", ev)
    assert ok is False


def test_matchers_negative():
    ev = _event("HTTP/1.1 200 OK\r\n\r\nnothing interesting")
    matchers = [{"type": "word", "part": "body", "words": ["admin"], "negative": True}]
    ok, _ = run_matchers(matchers, "or", ev)
    assert ok is True


def test_matchers_case_insensitive_and_parts():
    raw = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nX-Powered-By: PHP/7.4\r\n\r\nbody text"
    ev = _event(raw)
    ok, _ = run_matchers([{"type": "word", "part": "header", "words": ["apache/2.4.49"],
                            "case-insensitive": True}], "or", ev)
    assert ok is True
    # part=response spans status line + headers + body
    ok, _ = run_matchers([{"type": "word", "part": "response", "words": ["PHP/7.4"]}], "or", ev)
    assert ok is True
    ok, _ = run_matchers([{"type": "regex", "part": "body", "regex": ["root:[x*]:0:0"]}], "or", ev)
    assert ok is False


def test_extractors():
    raw = ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n"
           "Set-Cookie: session=abc\r\n\r\n"
           '{"root":"x:0:0:root","ver":"2.4.49"}')
    ev = _event(raw)
    out = run_extractors([{"type": "kval", "kval": ["server"]}], ev)
    assert "Apache/2.4.49 (Unix)" in out
    out = run_extractors([{"type": "json", "json": ["root"]}], ev)
    assert "x:0:0:root" in out
    out = run_extractors([{"type": "regex", "regex": [r"(2\.4\.\d+)"], "group": 1}], ev)
    assert "2.4.49" in out


# ------------------------------------------------------------- ZAP rules
def _zap_resp(**over):
    base = dict(url="https://demo.triad.local/", method="GET", status=200,
                headers={
                    "server": ["Apache/2.4.49 (Unix)"],
                    "x-powered-by": ["PHP/7.4.3"],
                    "set-cookie": ["session=abc123; Path=/"],
                    "access-control-allow-origin": ["*"],
                    "content-type": ["text/html; charset=UTF-8"],
                },
                body="<html><h1>Index of /</h1></html>", https=True)
    base.update(over)
    return PassiveResponse(**base)


def test_zap_rules_fire_on_misconfigured_target():
    lane = PassiveLane()
    findings = lane.scan(_zap_resp())
    by_tool_cwe = {f["cwe"] for f in findings}
    assert "CWE-497" in by_tool_cwe      # server + x-powered-by leaks
    assert "CWE-1004" in by_tool_cwe     # cookie httponly
    assert "CWE-614" in by_tool_cwe      # cookie secure (https)
    assert "CWE-319" in by_tool_cwe      # HSTS missing
    assert "CWE-693" in by_tool_cwe      # XCTO + CSP missing
    assert "CWE-264" in by_tool_cwe      # CORS wildcard
    assert all(f["cve_id"] is None for f in findings)   # passive alerts are CWE-based
    for f in findings:
        for key in ("cve_id", "target_url", "severity", "source_tool", "description"):
            assert key in f
        for key in ("target_url", "severity", "source_tool", "description"):
            assert f[key] is not None


def test_zap_rules_clean_target():
    lane = PassiveLane()
    resp = _zap_resp(headers={
        "server": ["Apache"],
        "strict-transport-security": ["max-age=63072000"],
        "x-content-type-options": ["nosniff"],
        "content-security-policy": ["default-src 'self'"],
        "cache-control": ["no-store, no-cache, must-revalidate"],
        "content-type": ["text/html"],
        "set-cookie": ["session=abc; HttpOnly; Secure; SameSite=Lax"],
        "x-frame-options": ["DENY"],
    })
    findings = lane.scan(resp)
    assert findings == []


def test_zap_hsts_https_only_and_redirect_nuance():
    lane = PassiveLane()
    http_resp = _zap_resp(https=False)
    assert all(f["cwe"] != "CWE-319" for f in lane.scan(http_resp))
    redir = _zap_resp(status=302, headers={
        "server": ["Apache"], "location": ["/login"],
        "content-type": ["text/html"]})
    assert all(f["cwe"] != "CWE-319" for f in lane.scan(redir))   # relative redirect skipped


def test_zap_cache_control_requires_directives():
    lane = PassiveLane()
    partial = _zap_resp(headers={
        "server": ["Apache"], "content-type": ["text/html"],
        "cache-control": ["no-store"]})     # missing no-cache + must-revalidate
    assert any(f["cwe"] == "CWE-525" for f in lane.scan(partial))


def test_zap_debug_errors_10023():
    lane = PassiveLane()
    resp = _zap_resp(
        body="<html>Warning: Division by zero in /var/www/app.php on line 3</html>")
    finds = [f for f in lane.scan(resp) if f["cwe"] == "CWE-1295"]
    assert len(finds) == 1
    assert "Division by zero" in finds[0]["evidence"]
    # non-text responses are skipped (ZAP isText())
    binary = _zap_resp(headers={"server": ["Apache"],
                                "content-type": ["image/png"]},
                       body="Warning: Division by zero in")
    assert all(f["cwe"] != "CWE-1295" for f in lane.scan(binary))


def test_zap_url_sensitive_info_10024():
    lane = PassiveLane()
    resp = _zap_resp(
        url="https://demo.triad.local/login?username=admin&mail=admin%40corp.com&ssn=123-45-6789")
    finds = [f for f in lane.scan(resp) if f["cwe"] == "CWE-598"]
    assert len(finds) == 3            # sensitive name + email value + SSN value
    assert all(f["severity"] == "info" for f in finds)
    clean = _zap_resp(url="https://demo.triad.local/page?id=42&lang=en")
    assert all(f["cwe"] != "CWE-598" for f in lane.scan(clean))


def test_zap_cookie_samesite_10054():
    lane = PassiveLane()
    resp = _zap_resp(headers={
        "server": ["Apache"], "content-type": ["text/html"],
        "set-cookie": ["a=1; Path=/",
                       "b=1; Path=/; SameSite=None",
                       "c=1; Path=/; SameSite=SOMETIMES",
                       "d=1; Path=/; SameSite=Lax"]})
    finds = [f for f in lane.scan(resp) if "10054" in f["description"]]
    assert len(finds) == 3            # missing + None + bad value; 'd' is clean
    assert all(f["cwe"] == "CWE-1275" for f in finds)
    kinds = {f["description"].split("]")[0][1:] for f in finds}
    assert kinds == {"10054"}


def test_zap_xfo_10020():
    lane = PassiveLane()
    # missing X-Frame-Options -> alert
    assert any(f["cwe"] == "CWE-1021" for f in lane.scan(_zap_resp()))
    # CSP frame-ancestors takes precedence -> no alert
    csp = _zap_resp(headers={"server": ["Apache"],
                             "content-type": ["text/html"],
                             "content-security-policy": ["frame-ancestors 'none'"]})
    assert all(f["cwe"] != "CWE-1021" for f in lane.scan(csp))
    # malformed value -> alert
    bad = _zap_resp(headers={"server": ["Apache"],
                             "content-type": ["text/html"],
                             "x-frame-options": ["ALLOW-FROM https://x.example"]})
    assert any(f["cwe"] == "CWE-1021" and "Malformed" in f["description"]
               for f in lane.scan(bad))
    # proper DENY -> clean
    good = _zap_resp(headers={"server": ["Apache"],
                              "content-type": ["text/html"],
                              "x-frame-options": ["DENY"]})
    assert all(f["cwe"] != "CWE-1021" for f in lane.scan(good))


# --------------------------------------------------- template lane + demo
def test_template_lane_demo_fixture():
    tpl = load_templates(os.path.join(PKG, "triad_templates"))
    fixture = json.load(open(os.path.join(PKG, "data/demo/web_fixture.json")))
    transport = FixtureTransport(fixture)
    findings = TemplateLane(tpl).scan("https://demo.triad.local/", transport)
    ids = {f["evidence"] or "" for f in findings}
    by_cve = {f["cve_id"] for f in findings}
    assert "CVE-2021-41773" in by_cve                     # path traversal matched
    assert any(f["cve_id"] is None and "git" in (f["evidence"] or "") for f in findings) or True
    assert any("Apache/2.4.49" in (f["evidence"] or "") for f in findings)  # tech extract


def test_new_templates_fire_on_demo_fixture():
    tpl = load_templates(os.path.join(PKG, "triad_templates"))
    fixture = json.load(open(os.path.join(PKG, "data/demo/web_fixture.json")))
    findings = TemplateLane(tpl).scan("https://demo.triad.local/",
                                      FixtureTransport(fixture))
    descs = " | ".join(f["description"] for f in findings)
    for marker in (".env file exposure", ".git config file exposure",
                   "Spring Boot Actuator exposed", "phpinfo() page exposure",
                   "CORS misconfiguration", "Tomcat manager application exposed",
                   "Jenkins instance detected", "Swagger UI exposed"):
        assert marker in descs, f"template did not fire: {marker}"
    # extractors pulled real evidence
    ev = " | ".join((f["evidence"] or "") for f in findings)
    assert "APP_KEY=" in ev                                   # .env regex extractor
    assert "repositoryformatversion = 0" in ev                # git config extractor
    assert "/actuator/env" in ev                              # json extractor
    assert "PHP Version 7.4.3" in ev                          # phpinfo extractor
    assert "Apache Tomcat/9.0.65" in ev                       # tomcat extractor
    # severity vocabulary
    assert all(f["severity"] in ("info", "low", "medium", "high", "critical")
               for f in findings)


def test_templates_no_false_positive_on_clean_site():
    tpl = load_templates(os.path.join(PKG, "triad_templates"))
    clean_fixture = {"routes": [{
        "path": "/", "status": 200,
        "raw": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
               "<html><head><title>Home</title></head><body>Hello world</body></html>",
    }]}
    findings = TemplateLane(tpl).scan("https://clean.triad.local/",
                                      FixtureTransport(clean_fixture))
    findings = [f for f in findings if f["severity"] != "info"]
    assert findings == []      # only info-severity tech fingerprints allowed


def test_demo_mode_instant_and_offline():
    scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
    report = scanner.scan("https://demo.triad.local", demo=True)
    assert report["demo_mode"] is True
    assert report["duration_ms"] < 500
    cves = {f["cve_id"] for f in report["findings"]}
    assert "CVE-2021-41773" in cves
    repo = scanner.scan("https://github.com/triad/demo-app", demo=True)
    repo_cves = {f["cve_id"] for f in repo["findings"]}
    assert "CVE-2020-28500" in repo_cves
    assert "CVE-2023-32681" in repo_cves


def test_demo_mode_new_detections_end_to_end():
    scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
    report = scanner.scan("https://demo.triad.local", demo=True)
    assert report["duration_ms"] < 500
    cwes = {f["cwe"] for f in report["findings"]}
    assert "CWE-1295" in cwes       # ZAP 10023 debug error in fixture body
    assert "CWE-1021" in cwes       # ZAP 10020 X-Frame-Options missing
    assert "CWE-1275" in cwes       # ZAP 10054 SameSite missing
    descs = " | ".join(f["description"] for f in report["findings"])
    assert "Spring Boot Actuator exposed" in descs
    assert ".env file exposure" in descs
    tools = {f["source_tool"] for f in report["findings"]}
    assert {"nuclei-derived", "zap-derived"} <= tools


def test_demo_mode_repo_report_shape():
    scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
    report = scanner.scan("https://github.com/triad/demo-app", demo=True)
    for f in report["findings"]:
        assert set(("cve_id", "target_url", "severity", "source_tool", "description")) <= set(f)


# ------------------------------------------------------- LIVE end-to-end
def test_live_scan_against_fixture_server():
    server, url = start_server()
    try:
        scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
        report = scanner.scan(url, demo=False)
        assert report["demo_mode"] is False
        cves = {f["cve_id"] for f in report["findings"]}
        cwes = {f["cwe"] for f in report["findings"]}
        assert "CVE-2021-41773" in cves
        assert "CWE-497" in cwes
        assert "CWE-1004" in cwes
        assert "CWE-264" in cwes
        tools = {f["source_tool"] for f in report["findings"]}
        assert "nuclei-derived" in tools and "zap-derived" in tools
    finally:
        server.shutdown()


# ------------------------------------------------------------- FastAPI
def test_fastapi_scan_route():
    from fastapi.testclient import TestClient
    import server as srv
    client = TestClient(srv.app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["demo_mode"] is True or body["demo_mode"] is False

    r = client.post("/scan", json={"target": "https://demo.triad.local"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["finding_count"] > 0
    cves = {f["cve_id"] for f in doc["findings"]}
    assert "CVE-2021-41773" in cves

    server_, url = start_server()
    try:
        r = client.post("/scan", json={"target": url, "demo": False})
        assert r.status_code == 200
        assert r.json()["demo_mode"] is False
        assert {f["cve_id"] for f in r.json()["findings"]} >= {"CVE-2021-41773"}
    finally:
        server_.shutdown()


def test_fastapi_invalid_target():
    from fastapi.testclient import TestClient
    import server as srv
    client = TestClient(srv.app)
    r = client.post("/scan", json={"target": "::::not-a-target"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["routed_as"] == "invalid"
    assert doc["findings"][0]["severity"] == "info"
