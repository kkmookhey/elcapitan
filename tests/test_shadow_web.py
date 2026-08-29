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
        assert b'aria-labelledby="intake-title"' in content
        assert b'aria-describedby="intake-description"' in content
        assert b'aria-labelledby="detail-title"' in content
        status, _, content = request(
            server, "GET", "/fleet.css", headers={"Cookie": cookie})
        assert status == 200
        assert b":focus-visible" in content
        assert b"prefers-reduced-motion:reduce" in content
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
        assert b'<h2 id="detail-title">' in content
        assert b'<button type="button"' in content
        body = json.dumps({
            "tenant_id": "TEN-API",
            "findings": [json.loads(FIXTURE.read_text())],
            "context": {"asset_criticality": .8, "reachable": True,
                        "service_ids": ["storage"]},
        }).encode()
        headers = {"Cookie": cookie, "Content-Type": "application/json"}
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
