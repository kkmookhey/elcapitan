import http.client
import json
import threading
import urllib.parse
from pathlib import Path

from elcapitan.shadow_control import ShadowFleetControlPlane
from elcapitan.shadow_web import _ShadowServer


FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"


def request(server, method, path, *, body=b"", headers=None):
    connection = http.client.HTTPConnection(*server.server_address, timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    content = response.read()
    result = response.status, dict(response.getheaders()), content
    connection.close()
    return result


def authenticated_server(tmp_path):
    server = _ShadowServer(
        ("127.0.0.1", 0), ShadowFleetControlPlane(tmp_path, host_env={}), "s" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    encoded = urllib.parse.urlencode({"token": "s" * 32})
    status, headers, _ = request(
        server, "POST", "/login", body=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 303
    set_cookie = headers["Set-Cookie"]
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert "Max-Age=28800" in set_cookie
    return server, set_cookie.split(";", 1)[0]


def test_shadow_api_intake_fleet_and_case_detail_are_authenticated(tmp_path):
    server, cookie = authenticated_server(tmp_path)
    try:
        status, _, _ = request(server, "GET", "/api/connectors")
        assert status == 401
        status, headers, content = request(
            server, "GET", "/", headers={"Cookie": cookie})
        assert status == 200
        assert headers["Content-Type"].startswith("text/html")
        assert b"Customer shadow fleet" in content
        assert b'<caption class="sr-only">' in content
        assert b'<th scope="col">Priority</th>' in content
        assert b"Finding and source" in content
        assert b"Normalized scope" in content
        assert b"From scanner signal to controlled change" in content
        assert b"Understand the risk" in content
        assert b"Act safely" in content
        assert b"Human authority boundary" in content
        assert b'aria-labelledby="intake-title"' in content
        assert b'aria-describedby="intake-description"' in content
        assert b'aria-labelledby="detail-title"' in content
        assert b"Start with findings" in content
        assert b"Review import" in content
        assert b"No data saved" in content
        assert b"Back to start" in content
        assert b"Normalized findings" in content
        assert b"What needs attention" in content
        assert b"No cloud checks ready" in content
        assert b"Add per-resource asset context" in content
        assert b"Fallback asset criticality" in content
        status, _, content = request(
            server, "GET", "/fleet.css", headers={"Cookie": cookie})
        assert status == 200
        assert b":focus-visible" in content
        assert b".tenant-control input:focus-visible" in content
        assert b"prefers-reduced-motion:reduce" in content
        assert b"operational text should not require zoom" in content
        assert b".detail-dialog{width:min(1080px" in content
        status, headers, content = request(
            server, "GET", "/fleet.js", headers={"Cookie": cookie})
        assert status == 200
        assert headers["Content-Type"].startswith("text/javascript")
        assert b"Current approval package" in content
        assert b"Superseded history" in content
        assert b"Only records marked CURRENT" in content
        assert b"Evidence grade" in content
        assert b"REAL INPUT" in content
        assert b"SYNTHETIC INPUT" in content
        assert b"Confirmed in cloud" in content
        assert b"No longer detected" in content
        assert b"Not available for this control" in content
        assert b"Keep this finding in the scanner workflow" in content
        assert b'data-label="Priority"' in content
        assert b"finding_sources" in content
        assert b"finding_formats" in content
        assert b"clearToast" in content
        assert b"ready now" in content
        assert b"Supported findings" in content
        assert b"Cloud readiness is shown after import" in content
        assert b"grouped on this resource" in content
        assert b"added to existing resource" in content
        assert b"No asset manifest supplied" in content
        assert b"Asset context" in content
        assert b"Score-driving observation" in content
        assert b"Findings are not added together" in content
        assert b"Check cloud state" in content
        assert b'checkedCases ? `${validatedCases} cases` : "Not run"' in content
        assert b'`${checkedCases} resource cases checked' in content
        assert b'`${readyForPlan} candidates`' in content
        assert b"supported findings are waiting for read-only cloud access" in content
        assert b"/api/intake-preview" in content
        assert b'<h2 id="detail-title">' in content
        assert b'<button type="button"' in content
        headers = {"Cookie": cookie, "Content-Type": "application/json"}
        preview_body = json.dumps({
            "findings": [json.loads(FIXTURE.read_text())],
        }).encode()
        status, _, content = request(
            server, "POST", "/api/intake-preview", body=preview_body,
            headers=headers)
        assert status == 200
        preview = json.loads(content)
        assert preview["accepted_failures"] == 1
        assert preview["supported_findings"] == 1
        assert preview["provider_counts"] == {"azure": 1}
        assert preview["safety_boundary"] == {
            "persistent_writes": False,
            "cloud_requests": False,
            "external_models": False,
            "execution": False,
        }
        status, _, content = request(
            server, "GET", "/api/fleet?tenant=TEN-API", headers={"Cookie": cookie})
        assert status == 200
        assert json.loads(content)["summary"]["total_findings"] == 0
        body = json.dumps({
            "tenant_id": "TEN-API",
            "findings": [json.loads(FIXTURE.read_text())],
            "assets": [{
                "resource_uid": json.loads(FIXTURE.read_text())["resources"][0]["uid"],
                "environment": "production",
                "owner": "storage-team",
                "asset_criticality": .9,
                "internet_exposed": True,
                "reachable": True,
                "runtime_dependency": False,
                "compensating_control_strength": 0,
                "service_ids": ["storage"],
                "context_source": "test-manifest",
                "observed_at": "2026-09-01T20:00:00Z",
                "evidence_references": ["test-evidence"],
                "synthetic_business_context": True,
            }],
            "context": {"asset_criticality": .8, "reachable": True,
                        "service_ids": ["storage"]},
        }).encode()
        status, _, content = request(server, "POST", "/api/intake", body=body,
                                     headers=headers)
        assert status == 200
        intake = json.loads(content)
        case_id = intake["case_ids"][0]
        assert intake["fleet"]["summary"]["total_findings"] == 1

        status, _, content = request(
            server, "GET", "/api/fleet?tenant=TEN-API", headers={"Cookie": cookie})
        assert status == 200
        fleet_case = json.loads(content)["cases"][0]
        assert fleet_case["case_id"] == case_id
        assert fleet_case["finding_sources"] == ["Prowler 5.37.1"]
        assert fleet_case["finding_formats"] == ["OCSF 1.5.0"]
        assert fleet_case["asset_context"]["owner"] == "storage-team"
        assert fleet_case["capabilities"][0]["live_validation"] is True
        assert fleet_case["capabilities"][0]["remediation_planning"] is True
        assert fleet_case["capabilities"][0]["live_execution"] is True
        assert fleet_case["capabilities"][0]["evidence_grade"] == "e2e_measured"

        status, _, content = request(
            server, "GET", f"/api/cases/{case_id}?tenant=TEN-API",
            headers={"Cookie": cookie})
        assert status == 200
        detail = json.loads(content)
        assert detail["safety_boundary"]["execution"] is False
        assert detail["findings"][0]["record"]["raw_event"]["sensitivity"] == "internal"
        assert detail["promotion"]["status"] == "blocked"

        status, _, content = request(
            server, "GET", f"/api/promotions/{case_id}?tenant=TEN-API",
            headers={"Cookie": cookie})
        assert status == 200
        assert json.loads(content)["safety_boundary"]["execution"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_shadow_root_shows_login_page_before_authentication(tmp_path):
    server = _ShadowServer(
        ("127.0.0.1", 0), ShadowFleetControlPlane(tmp_path, host_env={}),
        "s" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, content = request(server, "GET", "/")
        assert status == 200
        assert headers["Content-Type"].startswith("text/html")
        assert b"Access token" in content
        assert b"El Capitan shadow trial" in content
        assert b"Open read-only workspace" in content
        assert b"El Capitan demo" not in content

        status, _, content = request(
            server, "GET", "/?tenant=AZURE-TEST-TRIAL")
        assert status == 200
        assert b"name='next' value='/?tenant=AZURE-TEST-TRIAL'" in content

        encoded = urllib.parse.urlencode({
            "token": "s" * 32, "next": "/?tenant=AZURE-TEST-TRIAL"})
        status, headers, _ = request(
            server, "POST", "/login", body=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        assert headers["Location"] == "/?tenant=AZURE-TEST-TRIAL"

        encoded = urllib.parse.urlencode({
            "token": "s" * 32, "next": "https://attacker.test/"})
        status, headers, _ = request(
            server, "POST", "/login", body=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        assert headers["Location"] == "/"

        status, _, content = request(server, "GET", "/api/connectors")
        assert status == 401
        assert json.loads(content) == {"error": "Authentication required."}
    finally:
        server.shutdown()
        server.server_close()


def test_shadow_api_rejects_cross_origin_and_has_no_action_routes(tmp_path):
    server, cookie = authenticated_server(tmp_path)
    try:
        status, _, _ = request(
            server, "POST", "/api/intake", body=b"{}",
            headers={"Cookie": cookie, "Content-Type": "application/json",
                     "Origin": "https://attacker.test"})
        assert status == 403
        status, _, _ = request(
            server, "POST", "/api/execute", body=b"{}",
            headers={"Cookie": cookie, "Content-Type": "application/json"})
        assert status == 404
    finally:
        server.shutdown()
        server.server_close()


def test_shadow_api_rejects_string_booleans_before_intake(tmp_path):
    server, cookie = authenticated_server(tmp_path)
    try:
        body = json.dumps({
            "tenant_id": "TEN-STRICT",
            "findings": [json.loads(FIXTURE.read_text())],
            "context": {"reachable": "false"},
        }).encode()
        status, _, content = request(
            server, "POST", "/api/intake", body=body,
            headers={"Cookie": cookie, "Content-Type": "application/json"})
        assert status == 409
        assert "must be a boolean" in json.loads(content)["error"]
        status, _, content = request(
            server, "GET", "/api/fleet?tenant=TEN-STRICT",
            headers={"Cookie": cookie})
        assert status == 200
        assert json.loads(content)["summary"]["total_findings"] == 0
    finally:
        server.shutdown()
        server.server_close()
