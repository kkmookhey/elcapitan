"""Minimal dependency-free HTTP server for the El Capitan product demo."""
from __future__ import annotations

import json
import hashlib
import hmac
import html
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .demo_control import DemoControlError, DemoControlPlane


_ASSETS = files("elcapitan").joinpath("web")


class _DemoServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, control: DemoControlPlane,
                 access_token: str = "", handler_class=None) -> None:
        super().__init__(address, handler_class or DemoRequestHandler)
        self.control = control
        self.authenticated_cookie = (
            hashlib.sha256(f"elcapitan-demo-session:{access_token}".encode()).hexdigest()
            if access_token else ""
        )
        self.access_token = access_token


class DemoRequestHandler(BaseHTTPRequestHandler):
    LOGIN_PAGE_TITLE = "El Capitan · Demo access"
    LOGIN_HEADING = "El Capitan demo"
    LOGIN_DESCRIPTION = (
        "This environment is restricted. Enter the demonstration access token "
        "supplied by the operator.")
    LOGIN_BUTTON = "Enter control plane"

    server: _DemoServer

    def log_message(self, format: str, *args) -> None:
        # Keep the operator console concise while retaining request outcomes.
        print(f"demo-web {self.address_string()} {format % args}")

    def _headers(self, status: HTTPStatus, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'nonce-elcapitan-login'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )
        self.end_headers()

    def _authenticated(self) -> bool:
        expected = self.server.authenticated_cookie
        if not expected:
            return True
        cookies = {}
        for item in self.headers.get("Cookie", "").split(";"):
            name, separator, value = item.strip().partition("=")
            if separator:
                cookies[name] = value
        return hmac.compare_digest(cookies.get("elcapitan_demo", ""), expected)

    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return origin in {f"https://{host}", f"http://{host}"}

    @staticmethod
    def _safe_login_target(value: str) -> str:
        if not value or len(value) > 512 or "\r" in value or "\n" in value:
            return "/"
        parsed = urlparse(value)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            return "/"
        if parsed.path not in {"/", "/index.html"}:
            return "/"
        return parsed.path + (f"?{parsed.query}" if parsed.query else "")

    def _login_page(self, *, failed: bool = False,
                    next_target: str = "") -> None:
        error = "<p class='error'>That access token is not valid.</p>" if failed else ""
        target = self._safe_login_target(next_target or self.path)
        next_input = (
            f"<input type='hidden' name='next' value='{html.escape(target, quote=True)}'>"
            if target != "/" else ""
        )
        body = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{self.LOGIN_PAGE_TITLE}</title><style nonce='elcapitan-login'>
:root{{color-scheme:dark;font-family:Inter,ui-sans-serif,-apple-system,sans-serif}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;
background:#071013;color:#e8eef2}}main{{width:min(430px,calc(100vw - 32px));padding:32px;
border:1px solid #2b5547;border-radius:14px;background:#0d191d}}
.mark{{width:42px;height:42px;display:grid;place-items:center;border:1px solid #36765f;
border-radius:9px;color:#60e6a8;background:#0f2720;font:700 11px monospace}}
p{{color:#8fa0aa;font-size:12px;line-height:1.6}}h1{{font-size:25px;margin:25px 0 8px}}
label{{display:block;color:#8fa0aa;font-size:10px;margin-top:24px}}
input{{width:100%;margin:8px 0 14px;padding:12px;border:1px solid #31464c;border-radius:8px;
background:#071013;color:#e8eef2}}button{{width:100%;padding:12px;border:0;border-radius:8px;
background:#60e6a8;color:#062016;font-weight:700;cursor:pointer}}.error{{color:#ff9d9d}}
</style></head><body><main><div class='mark'>EC</div><h1>{self.LOGIN_HEADING}</h1>
<p>{self.LOGIN_DESCRIPTION}</p>
{error}<form method='post' action='/login'>{next_input}<label>Access token
<input type='password' name='token' required autocomplete='current-password'></label>
<button type='submit'>{self.LOGIN_BUTTON}</button></form></main></body></html>""".encode()
        self._headers(HTTPStatus.UNAUTHORIZED if failed else HTTPStatus.OK,
                      "text/html; charset=utf-8", len(body))
        self.wfile.write(body)

    def _login(self) -> None:
        length = min(int(self.headers.get("Content-Length", "0")), 4096)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = parse_qs(body)
        supplied = fields.get("token", [""])[0]
        target = self._safe_login_target(fields.get("next", [""])[0])
        if not hmac.compare_digest(supplied, self.server.access_token):
            self._login_page(failed=True, next_target=target)
            return
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", target)
        self.send_header(
            "Set-Cookie",
            f"elcapitan_demo={self.server.authenticated_cookie}; Path=/; Max-Age=28800; "
            "HttpOnly; Secure; SameSite=Strict",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _json(self, document, *, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _read_json(self) -> dict:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise DemoControlError("Invalid request length.") from exc
        if length < 0 or length > 16_384:
            raise DemoControlError("Request body is too large.")
        if not length:
            return {}
        try:
            document = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DemoControlError("Request body must be valid JSON.") from exc
        if not isinstance(document, dict):
            raise DemoControlError("Request body must be a JSON object.")
        return document

    def _asset(self, relative: str) -> None:
        if relative not in {"index.html", "app.css", "app.js"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        asset = _ASSETS.joinpath(relative)
        body = asset.read_bytes()
        content_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type == "application/javascript":
            content_type += "; charset=utf-8"
        self._headers(HTTPStatus.OK, content_type, len(body))
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if path == "/healthz":
            self._json({"status": "ok"})
            return
        if path == "/login":
            self._login_page()
            return
        if not self._authenticated():
            if path.startswith("/api/"):
                self._json({"error": "Authentication required."},
                           status=HTTPStatus.UNAUTHORIZED)
            else:
                self._login_page()
            return
        if path in {"/", "/index.html"}:
            self._asset("index.html")
        elif path == "/app.css":
            self._asset("app.css")
        elif path == "/app.js":
            self._asset("app.js")
        elif path == "/api/state":
            self._json(self.server.control.state())
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if path == "/login":
            self._login()
            return
        if not self._authenticated():
            self._json({"error": "Authentication required."},
                       status=HTTPStatus.UNAUTHORIZED)
            return
        if not self._same_origin():
            self._json({"error": "Cross-origin requests are not allowed."},
                       status=HTTPStatus.FORBIDDEN)
            return
        try:
            body = self._read_json()
            if path == "/api/reset":
                result = self.server.control.reset()
            elif path == "/api/prepare":
                result = self.server.control.prepare()
            elif path == "/api/approve":
                result = self.server.control.approve(
                    approver=str(body.get("approver", "Demo Change Manager")))
            elif path == "/api/execute":
                result = self.server.control.execute(
                    outcome=str(body.get("outcome", "success")))
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
        except DemoControlError as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
            return
        except Exception as exc:
            # Do not expose paths, command output, or evidence through HTTP errors.
            print(f"demo-web internal error: {type(exc).__name__}: {exc}")
            self._json(
                {"error": "The demo action failed. Check the operator console."},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )
            return
        self._json(result)


def run_demo_server(*, host: str, port: int, workdir: Path,
                    terraform_bin: str = "terraform",
                    terraform_timeout: float = 120,
                    prepare: bool = False) -> None:
    control = DemoControlPlane(
        workdir,
        terraform_bin=terraform_bin,
        terraform_timeout=terraform_timeout,
    )
    if prepare and control.state()["demo"]["phase"] == "ready":
        control.prepare()
    access_token = os.environ.get("ELCAPITAN_DEMO_ACCESS_TOKEN", "")
    if access_token and len(access_token) < 24:
        raise ValueError("ELCAPITAN_DEMO_ACCESS_TOKEN must be at least 24 characters")
    server = _DemoServer((host, port), control, access_token)
    print(f"El Capitan demo listening on http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
