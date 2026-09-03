"""Authenticated HTTP API for the read-only customer shadow control plane."""
from __future__ import annotations

import json
import math
import mimetypes
import os
from http import HTTPStatus
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .demo_web import DemoRequestHandler, _DemoServer
from .intake import IntakeContext
from .shadow_control import ShadowControlError, ShadowFleetControlPlane


MAX_REQUEST_BYTES = 10 * 1024 * 1024
_ASSETS = files("elcapitan").joinpath("shadow_web_assets")


class _ShadowServer(_DemoServer):
    control: ShadowFleetControlPlane

    def __init__(self, address, control: ShadowFleetControlPlane,
                 access_token: str) -> None:
        super().__init__(address, control, access_token,
                         handler_class=ShadowRequestHandler)


class ShadowRequestHandler(DemoRequestHandler):
    server: _ShadowServer
    LOGIN_PAGE_TITLE = "El Capitan · Shadow trial access"
    LOGIN_HEADING = "El Capitan shadow trial"
    LOGIN_DESCRIPTION = (
        "This read-only workspace is restricted. Enter the access token "
        "supplied by the operator.")
    LOGIN_BUTTON = "Open read-only workspace"

    def _read_shadow_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise ShadowControlError("Content-Type must be application/json.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ShadowControlError("Invalid request length.") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ShadowControlError(
                f"Request body must be between 1 byte and {MAX_REQUEST_BYTES} bytes.")
        try:
            document = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ShadowControlError("Request body must be valid JSON.") from exc
        if not isinstance(document, dict):
            raise ShadowControlError("Request body must be a JSON object.")
        return document

    @staticmethod
    def _number(document: dict, name: str, default: float = 0) -> float:
        value = document.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ShadowControlError(f"context.{name} must be a number")
        result = float(value)
        if not math.isfinite(result) or not 0 <= result <= 1:
            raise ShadowControlError(f"context.{name} must be between 0 and 1")
        return result

    @staticmethod
    def _boolean(document: dict, name: str, default: bool = False) -> bool:
        value = document.get(name, default)
        if not isinstance(value, bool):
            raise ShadowControlError(f"context.{name} must be a boolean")
        return value

    @staticmethod
    def _optional_boolean(document: dict, name: str) -> bool | None:
        value = document.get(name)
        if value is not None and not isinstance(value, bool):
            raise ShadowControlError(f"context.{name} must be a boolean or null")
        return value

    @staticmethod
    def _service_ids(document: dict) -> tuple[str, ...]:
        value = document.get("service_ids", [])
        if not isinstance(value, list) or len(value) > 100:
            raise ShadowControlError(
                "context.service_ids must be an array of at most 100 strings")
        result = tuple(str(item).strip() for item in value)
        if any(not item or len(item) > 200 for item in result):
            raise ShadowControlError(
                "context.service_ids entries must be 1 to 200 characters")
        return tuple(dict.fromkeys(result))

    @classmethod
    def _context(cls, body: dict) -> IntakeContext:
        raw_context = body.get("context") or {}
        if not isinstance(raw_context, dict):
            raise ShadowControlError("context must be an object")
        return IntakeContext(
            asset_criticality=cls._number(raw_context, "asset_criticality"),
            exploit_probability=cls._number(raw_context, "exploit_probability"),
            internet_exposed=cls._optional_boolean(
                raw_context, "internet_exposed"),
            reachable=cls._boolean(raw_context, "reachable"),
            known_exploited=cls._boolean(raw_context, "known_exploited"),
            active_exploitation=cls._boolean(
                raw_context, "active_exploitation"),
            runtime_dependency=cls._boolean(
                raw_context, "runtime_dependency"),
            compensating_control_strength=cls._number(
                raw_context, "compensating_control_strength"),
            service_ids=cls._service_ids(raw_context),
        )

    @staticmethod
    def _documents(body: dict) -> list:
        supplied = body.get("findings")
        return supplied if isinstance(supplied, list) else [supplied]

    @staticmethod
    def _asset_contexts(body: dict) -> list | None:
        supplied = body.get("assets")
        if supplied is None:
            return None
        if not isinstance(supplied, list):
            raise ShadowControlError("assets must be an array")
        return supplied

    def _asset(self, relative: str) -> None:
        if relative not in {"index.html", "fleet.css", "fleet.js"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = _ASSETS.joinpath(relative).read_bytes()
        content_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type == "application/javascript":
            content_type += "; charset=utf-8"
        self._headers(HTTPStatus.OK, content_type, len(body))
        self.wfile.write(body)

    @staticmethod
    def _tenant(query: dict) -> str:
        tenant = str(query.get("tenant", [""])[0]).strip()
        if not tenant:
            raise ShadowControlError("tenant query parameter is required")
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
                print(f"shadow-web health failure: {type(exc).__name__}: {exc}")
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
            elif parsed.path == "/fleet.css":
                self._asset("fleet.css")
            elif parsed.path == "/fleet.js":
                self._asset("fleet.js")
            elif parsed.path == "/api":
                self._json({
                    "service": "elcapitan-shadow-control-plane",
                    "mode": "read-only",
                    "endpoints": [
                        "GET /api/fleet?tenant=...",
                        "GET /api/connectors",
                        "GET /api/cases/{case_id}?tenant=...",
                        "GET /api/promotions/{case_id}?tenant=...",
                        "POST /api/intake-preview",
                        "POST /api/intake",
                        "POST /api/validate",
                        "POST /api/validate-batch",
                    ],
                    "prohibited": ["approval", "scheduling", "execution"],
                })
            elif parsed.path == "/api/fleet":
                self._json(self.server.control.snapshot(tenant_id=self._tenant(query)))
            elif parsed.path == "/api/connectors":
                self._json(self.server.control.connector_status())
            elif parsed.path.startswith("/api/cases/"):
                case_id = parsed.path.removeprefix("/api/cases/")
                if not case_id or "/" in case_id:
                    raise ShadowControlError("one case id is required")
                self._json(self.server.control.case_detail(
                    tenant_id=self._tenant(query), case_id=case_id))
            elif parsed.path.startswith("/api/promotions/"):
                case_id = parsed.path.removeprefix("/api/promotions/")
                if not case_id or "/" in case_id:
                    raise ShadowControlError("one case id is required")
                self._json(self.server.control.promotion_manifest(
                    tenant_id=self._tenant(query), case_id=case_id))
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
        except (ShadowControlError, KeyError) as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
        except Exception as exc:
            print(f"shadow-web internal error: {type(exc).__name__}: {exc}")
            self._json(
                {"error": "The shadow request failed. Check the operator console."},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

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
            body = self._read_shadow_json()
            if parsed.path == "/api/intake-preview":
                result = self.server.control.preview_intake(
                    documents=self._documents(body),
                    context=self._context(body),
                    asset_contexts=self._asset_contexts(body),
                ).to_dict()
            elif parsed.path == "/api/intake":
                result = self.server.control.intake(
                    tenant_id=str(body.get("tenant_id", "")),
                    documents=self._documents(body),
                    context=self._context(body),
                    identity=str(body.get("identity", "shadow-api-upload")),
                    asset_contexts=self._asset_contexts(body),
                ).to_dict()
            elif parsed.path == "/api/validate":
                result = self.server.control.validate(
                    tenant_id=str(body.get("tenant_id", "")),
                    case_id=str(body.get("case_id", "")),
                )
            elif parsed.path == "/api/validate-batch":
                case_ids = body.get("case_ids")
                if not isinstance(case_ids, list):
                    raise ShadowControlError("case_ids must be an array")
                result = self.server.control.validate_batch(
                    tenant_id=str(body.get("tenant_id", "")),
                    case_ids=case_ids,
                )
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self._json(result)
        except (ShadowControlError, ValueError, KeyError, TypeError) as exc:
            self._json({"error": str(exc)}, status=HTTPStatus.CONFLICT)
        except Exception as exc:
            print(f"shadow-web internal error: {type(exc).__name__}: {exc}")
            self._json(
                {"error": "The shadow request failed. Check the operator console."},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )


def run_shadow_server(*, host: str, port: int, workdir: Path) -> None:
    access_token = os.environ.get("ELCAPITAN_SHADOW_ACCESS_TOKEN", "")
    if len(access_token) < 24:
        raise ValueError("ELCAPITAN_SHADOW_ACCESS_TOKEN must be at least 24 characters")
    server = _ShadowServer(
        (host, port), ShadowFleetControlPlane(workdir), access_token)
    print(f"El Capitan shadow API listening on http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
