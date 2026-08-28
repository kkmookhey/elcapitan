"""Authenticated HTTP boundary for human remediation decisions."""
from __future__ import annotations

import json
import mimetypes
import os
from http import HTTPStatus
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .demo_web import DemoRequestHandler, _DemoServer
from .review_control import ReviewControlError, ReviewControlPlane


MAX_REQUEST_BYTES = 32 * 1024
_ASSETS = files("elcapitan").joinpath("review_web_assets")


class _ReviewServer(_DemoServer):
    control: ReviewControlPlane

    def __init__(self, address, control: ReviewControlPlane,
                 access_token: str) -> None:
        super().__init__(address, control, access_token,
                         handler_class=ReviewRequestHandler)


class ReviewRequestHandler(DemoRequestHandler):
    server: _ReviewServer

    def _asset(self, relative: str) -> None:
        if relative not in {"index.html", "review.css", "review.js"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = _ASSETS.joinpath(relative).read_bytes()
        content_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type == "application/javascript":
            content_type += "; charset=utf-8"
        self._headers(HTTPStatus.OK, content_type, len(body))
        self.wfile.write(body)

    def _read_review_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise ReviewControlError("Content-Type must be application/json.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ReviewControlError("Invalid request length.") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ReviewControlError(
                f"Request body must be between 1 byte and {MAX_REQUEST_BYTES} bytes.")
        try:
            document = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReviewControlError("Request body must be valid JSON.") from exc
        if not isinstance(document, dict):
            raise ReviewControlError("Request body must be a JSON object.")
        return document

    @staticmethod
    def _tenant(query: dict) -> str:
        tenant = str(query.get("tenant", [""])[0]).strip()
        if not tenant:
            raise ReviewControlError("tenant query parameter is required")
        return tenant

    def _authorized(self) -> bool:
        if self._authenticated():
            return True
        self._json({"error": "Authentication required."},
                   status=HTTPStatus.UNAUTHORIZED)
        return False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            try:
                self._json(self.server.control.health())
            except Exception as exc:
                print(f"review-web health failure: {type(exc).__name__}: {exc}")
                self._json({"status": "unhealthy"},
                           status=HTTPStatus.SERVICE_UNAVAILABLE)
            return
        if parsed.path == "/login":
            super().do_GET()
            return
        if not self._authenticated():
            if parsed.path.startswith("/api"):
                self._json({"error": "Authentication required."},
                           status=HTTPStatus.UNAUTHORIZED)
            else:
                self._login_page()
            return
        try:
            query = parse_qs(parsed.query)
            if parsed.path in {"/", "/index.html"}:
                self._asset("index.html")
            elif parsed.path == "/review.css":
                self._asset("review.css")
            elif parsed.path == "/review.js":
                self._asset("review.js")
            elif parsed.path == "/api":
                self._json({
                    "service": "elcapitan-human-decision-plane",
                    "endpoints": [
                        "GET /api/reviews?tenant=...",
                        "GET /api/reviews/{case_id}?tenant=...",
                        "POST /api/decisions/approve",
                        "POST /api/decisions/reject",
                    ],
                    "prohibited": ["execution", "cloud mutation", "model dispatch"],
                })
            elif parsed.path == "/api/reviews":
                self._json(self.server.control.queue(
                    tenant_id=self._tenant(query)))
            elif parsed.path.startswith("/api/reviews/"):
                case_id = parsed.path.removeprefix("/api/reviews/")
                if not case_id or "/" in case_id:
                    raise ReviewControlError("one case id is required")
                self._json(self.server.control.detail(
                    tenant_id=self._tenant(query), case_id=case_id))
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
        except (ReviewControlError, KeyError) as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
        except Exception as exc:
            print(f"review-web internal error: {type(exc).__name__}: {exc}")
            self._json(
                {"error": "The review request failed. Check the operator console."},
                status=HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            super().do_POST()
            return
        if not self._authorized():
            return
        if not self._same_origin():
            self._json({"error": "Cross-origin requests are not allowed."},
                       status=HTTPStatus.FORBIDDEN)
            return
        try:
            document = self._read_review_json()
            if parsed.path == "/api/decisions/approve":
                result = self.server.control.approve(document)
            elif parsed.path == "/api/decisions/reject":
                result = self.server.control.reject(document)
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self._json(result)
        except (ReviewControlError, ValueError, KeyError, TypeError) as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
        except Exception as exc:
            print(f"review-web internal error: {type(exc).__name__}: {exc}")
            self._json(
                {"error": "The review decision failed. Check the operator console."},
                status=HTTPStatus.INTERNAL_SERVER_ERROR)


def run_review_server(*, host: str, port: int, workdir: Path) -> None:
    access_token = os.environ.get("ELCAPITAN_REVIEW_ACCESS_TOKEN", "")
    if len(access_token) < 24:
        raise ValueError("ELCAPITAN_REVIEW_ACCESS_TOKEN must be at least 24 characters")
    server = _ReviewServer(
        (host, port), ReviewControlPlane(workdir), access_token)
    print(f"El Capitan review API listening on http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
