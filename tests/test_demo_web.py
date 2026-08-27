import http.client
import threading
import urllib.parse

from elcapitan.demo_control import DemoControlPlane
from elcapitan.demo_web import _DemoServer


def request(server, method, path, *, body="", headers=None):
    connection = http.client.HTTPConnection(*server.server_address, timeout=10)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    content = response.read()
    result = response.status, dict(response.getheaders()), content
    connection.close()
    return result


def test_demo_web_requires_token_and_sets_hardened_cookie(tmp_path):
    server = _DemoServer(("127.0.0.1", 0), DemoControlPlane(tmp_path), "a" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, _ = request(server, "GET", "/healthz")
        assert status == 200
        status, _, body = request(server, "GET", "/api/state")
        assert status == 401
        assert b"Authentication required" in body

        encoded = urllib.parse.urlencode({"token": "a" * 32})
        status, headers, _ = request(
            server, "POST", "/login", body=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status == 303
        cookie = headers["Set-Cookie"]
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Strict" in cookie
        status, _, body = request(
            server, "GET", "/api/state",
            headers={"Cookie": cookie.split(";", 1)[0]},
        )
        assert status == 200
        assert b'"phase":"ready"' in body
    finally:
        server.shutdown()
        server.server_close()


def test_demo_web_rejects_cross_origin_writes(tmp_path):
    server = _DemoServer(("127.0.0.1", 0), DemoControlPlane(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = request(
            server, "POST", "/api/reset", body="{}",
            headers={"Content-Type": "application/json", "Origin": "https://attacker.test"},
        )
        assert status == 403
        assert b"Cross-origin" in body
    finally:
        server.shutdown()
        server.server_close()
