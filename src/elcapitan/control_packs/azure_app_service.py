"""Deterministic Azure App Service web-app control definitions.

The truth conditions are pinned to Prowler's Azure ``app`` checks.  This pack
intentionally covers web apps only.  Function-app controls remain a separate
pack because their deployment, public-network, and VNet evidence contracts are
different even though Azure represents both workloads as Microsoft.Web/sites.
"""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _optional_boolean(values, aspect: str):
    value = require(values, aspect)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"live App Service state has invalid {aspect} {value!r}")
    return value


def _client_certificates(values) -> ControlEvaluation:
    enabled = _optional_boolean(values, "app_client_cert_enabled")
    mode = require(values, "app_client_cert_mode")
    if mode is not None and not isinstance(mode, str):
        raise ValueError(
            f"live App Service state has invalid client-certificate mode {mode!r}")
    required = enabled is True and mode == "Required"
    return ControlEvaluation(
        confirmed=not required,
        reason=("client certificates are enabled and required" if required else
                "client certificates are not both enabled and required"),
    )


def _authentication(values) -> ControlEvaluation:
    enabled = _optional_boolean(values, "app_auth_platform_enabled")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("App Service authentication is enabled" if enabled is True else
                "App Service authentication is not enabled"),
    )


def _http20(values) -> ControlEvaluation:
    enabled = _optional_boolean(values, "app_http20_enabled")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("HTTP/2 is enabled" if enabled is True else "HTTP/2 is not enabled"),
    )


def _http_logs(values) -> ControlEvaluation:
    kind = require(values, "app_kind")
    settings = require(values, "app_diagnostic_log_settings")
    if not isinstance(kind, str) or not kind:
        raise ValueError(f"live App Service state has invalid app kind {kind!r}")
    if not isinstance(settings, list):
        raise ValueError("live App Service diagnostic settings are not a list")

    enabled = False
    for position, entry in enumerate(settings):
        if not isinstance(entry, dict):
            raise ValueError(
                f"live App Service diagnostic log entry {position} is not an object")
        if set(entry) != {"setting", "category", "category_group", "enabled"}:
            raise ValueError(
                f"live App Service diagnostic log entry {position} has an invalid shape")
        setting = entry["setting"]
        category = entry["category"]
        category_group = entry["category_group"]
        log_enabled = entry["enabled"]
        if not isinstance(setting, str) or not setting:
            raise ValueError(
                f"live App Service diagnostic log entry {position} has no setting name")
        if category is not None and not isinstance(category, str):
            raise ValueError(
                f"live App Service diagnostic log entry {position} has invalid category")
        if category_group is not None and not isinstance(category_group, str):
            raise ValueError(
                f"live App Service diagnostic log entry {position} has invalid category group")
        if log_enabled is not None and not isinstance(log_enabled, bool):
            raise ValueError(
                f"live App Service diagnostic log entry {position} has invalid enabled state")
        if (log_enabled is True and
                (category == "AppServiceHTTPLogs" or category_group == "allLogs")):
            enabled = True

    # Prowler excludes function apps from this web-app check.  Preserve the
    # exclusion explicitly in case a producer labels a function as sites.
    if "functionapp" in kind:
        return ControlEvaluation(
            confirmed=False,
            reason="Prowler excludes function apps from the web-app HTTP log check",
        )
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("App Service HTTP diagnostic logs are enabled" if enabled else
                "App Service HTTP diagnostic logs are not enabled"),
    )


AZURE_APP_SERVICE_PACK = ControlPack(
    pack_id="azure-app-service",
    controls=(
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_client_certificates_on",
            resource_family="app_service_web_app",
            # Prowler 5.x emits sites/config in OCSF while retaining the parent
            # site ARM id.  Do not generalise that mismatch to unrelated types.
            resource_types=("microsoft.web/sites/config",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_client_cert_enabled", "app_client_cert_mode"),
            evaluator=_client_certificates,
        ),
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_ensure_auth_is_set_up",
            resource_family="app_service_web_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_auth_platform_enabled",),
            evaluator=_authentication,
        ),
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_ensure_using_http20",
            resource_family="app_service_web_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_http20_enabled",),
            evaluator=_http20,
        ),
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_http_logs_enabled",
            resource_family="app_service_web_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_kind", "app_diagnostic_log_settings"),
            evaluator=_http_logs,
        ),
    ),
)
