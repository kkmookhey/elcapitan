import http.client
import json
import threading
import urllib.parse

from elcapitan.review_control import ReviewControlPlane
from elcapitan.review_web import _ReviewServer


def request(server, method, path, *, body=b"", headers=None):
    connection = http.client.HTTPConnection(*server.server_address, timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    content = response.read()
    result = response.status, dict(response.getheaders()), content
    connection.close()
    return result


def authenticated_server(tmp_path):
    server = _ReviewServer(
        ("127.0.0.1", 0), ReviewControlPlane(tmp_path, host_env={}), "r" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    encoded = urllib.parse.urlencode({"token": "r" * 32})
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


def test_review_web_is_authenticated_and_has_no_execution_route(tmp_path):
    server, cookie = authenticated_server(tmp_path)
    try:
        status, _, content = request(server, "GET", "/api/reviews?tenant=TEN")
        assert status == 401
        assert json.loads(content) == {"error": "Authentication required."}

        status, headers, content = request(
            server, "GET", "/", headers={"Cookie": cookie})
        assert status == 200
        assert headers["Content-Type"].startswith("text/html")
        assert b"Human decision gate" in content
        assert b'aria-labelledby="approve-title"' in content
        assert b'aria-describedby="approve-description"' in content
        assert b'aria-labelledby="reject-title"' in content
        assert b'aria-describedby="reject-description"' in content
        assert b'role="status" aria-live="polite"' in content
        status, _, content = request(
            server, "GET", "/review.css", headers={"Cookie": cookie})
        assert status == 200
        assert b":focus-visible" in content
        assert b"prefers-reduced-motion:reduce" in content

        status, _, content = request(
            server, "GET", "/review.js", headers={"Cookie": cookie})
        assert status == 200
        assert b"execution has not started" in content
        assert b'<button type="button"' in content

        status, _, content = request(
            server, "GET", "/api/reviews?tenant=TEN", headers={"Cookie": cookie})
        assert status == 200
        assert json.loads(content)["cases"] == []

        status, _, _ = request(
            server, "POST", "/api/execute", body=b"{}",
            headers={"Cookie": cookie, "Content-Type": "application/json"})
        assert status == 404
    finally:
        server.shutdown()
        server.server_close()


def test_review_web_rejects_cross_origin_decisions(tmp_path):
    server, cookie = authenticated_server(tmp_path)
    try:
        status, _, content = request(
            server, "POST", "/api/decisions/approve", body=b"{}",
            headers={"Cookie": cookie, "Content-Type": "application/json",
                     "Origin": "https://attacker.test"})
        assert status == 403
        assert json.loads(content)["error"] == "Cross-origin requests are not allowed."
    finally:
        server.shutdown()
        server.server_close()
