"""Deterministic Azure App Service and Function App control definitions.

The truth conditions are pinned to Prowler's Azure ``app`` checks.  Web-app and
Function App controls share a bounded ARM collector but retain separate kind
guards and evaluators because their security semantics differ even though Azure
represents both workloads as Microsoft.Web/sites.
"""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _optional_boolean(values, aspect: str):
    value = require(values, aspect)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"live App Service state has invalid {aspect} {value!r}")
    return value


def _kind(values) -> str:
    kind = require(values, "app_kind")
    if not isinstance(kind, str) or not kind:
        raise ValueError(f"live App Service state has invalid app kind {kind!r}")
    return kind


def _web_app(values) -> bool:
    return _kind(values).startswith("app")


def _function_app(values) -> bool:
    return _kind(values).startswith("functionapp")


def _client_certificates(values) -> ControlEvaluation:
    if not _web_app(values):
        return ControlEvaluation(False, "resource is not an App Service web app")
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
    if not _web_app(values):
        return ControlEvaluation(False, "resource is not an App Service web app")
    enabled = _optional_boolean(values, "app_auth_platform_enabled")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("App Service authentication is enabled" if enabled is True else
                "App Service authentication is not enabled"),
    )


def _http20(values) -> ControlEvaluation:
    if not _web_app(values):
        return ControlEvaluation(False, "resource is not an App Service web app")
    enabled = _optional_boolean(values, "app_http20_enabled")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("HTTP/2 is enabled" if enabled is True else "HTTP/2 is not enabled"),
    )


def _http_logs(values) -> ControlEvaluation:
    kind = _kind(values)
    settings = require(values, "app_diagnostic_log_settings")
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
    if not kind.startswith("app"):
        return ControlEvaluation(
            confirmed=False,
            reason="Prowler excludes non-web workloads from the web-app HTTP log check",
        )
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("App Service HTTP diagnostic logs are enabled" if enabled else
                "App Service HTTP diagnostic logs are not enabled"),
    )


def _optional_string(values, aspect: str):
    value = require(values, aspect)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"live App Service state has invalid {aspect} {value!r}")
    return value


def _function_ftps(values) -> ControlEvaluation:
    if not _function_app(values):
        return ControlEvaluation(False, "resource is not an Azure Function App")
    state = _optional_string(values, "app_ftps_state")
    disabled = state == "Disabled"
    return ControlEvaluation(
        confirmed=not disabled,
        reason=("Function App FTPS deployment is disabled" if disabled else
                f"Function App FTPS deployment state is {state!r}"),
    )


def _function_public_access(values) -> ControlEvaluation:
    if not _function_app(values):
        return ControlEvaluation(False, "resource is not an Azure Function App")
    state = _optional_string(values, "app_public_network_access")
    disabled = state == "Disabled"
    return ControlEvaluation(
        confirmed=not disabled,
        reason=("Function App public network access is disabled" if disabled else
                f"Function App public network access is {state!r}"),
    )


def _function_vnet(values) -> ControlEvaluation:
    if not _function_app(values):
        return ControlEvaluation(False, "resource is not an Azure Function App")
    subnet_id = _optional_string(values, "app_virtual_network_subnet_id")
    integrated = bool(subnet_id)
    return ControlEvaluation(
        confirmed=not integrated,
        reason=("Function App has VNet integration" if integrated else
                "Function App has no VNet integration"),
    )


AZURE_APP_SERVICE_PACK = ControlPack(
    pack_id="azure-app-service",
    evidence_grade="e2e_measured",
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
            evidence_aspects=(
                "app_kind", "app_client_cert_enabled", "app_client_cert_mode"),
            evaluator=_client_certificates,
        ),
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_ensure_auth_is_set_up",
            resource_family="app_service_web_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_kind", "app_auth_platform_enabled"),
            evaluator=_authentication,
        ),
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_ensure_using_http20",
            resource_family="app_service_web_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_kind", "app_http20_enabled"),
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
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_function_ftps_deployment_disabled",
            resource_family="azure_function_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_kind", "app_ftps_state"),
            evaluator=_function_ftps,
        ),
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_function_not_publicly_accessible",
            resource_family="azure_function_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_kind", "app_public_network_access"),
            evaluator=_function_public_access,
        ),
        ControlDefinition(
            pack_id="azure-app-service", provider="azure",
            rule_id="app_function_vnet_integration_enabled",
            resource_family="azure_function_app",
            resource_types=("microsoft.web/sites",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("app_kind", "app_virtual_network_subnet_id"),
            evaluator=_function_vnet,
        ),
    ),
)
