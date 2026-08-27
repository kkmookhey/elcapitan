"""Credential names used by scoped, read-only cloud validators."""

AZURE_SCANNER_MANAGED_IDENTITY_CLIENT_ID = (
    "ELCAP_SCANNER_AZURE_MANAGED_IDENTITY_CLIENT_ID")
AZURE_MANAGED_IDENTITY_AUTH_MODE = "managed_identity"

# Explicit host-to-tool mappings prevent ambient credentials and accidental
# provider selection from influencing validation.
SCANNER_ENV_MAPS = {
    "aws": {
        "ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
        "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
        "ELCAP_SCANNER_AWS_SESSION_TOKEN": "AWS_SESSION_TOKEN",
    },
    "azure": {
        "ELCAP_SCANNER_AZURE_CLIENT_ID": "AZURE_CLIENT_ID",
        "ELCAP_SCANNER_AZURE_CLIENT_SECRET": "AZURE_CLIENT_SECRET",
        "ELCAP_SCANNER_AZURE_TENANT_ID": "AZURE_TENANT_ID",
    },
}

OBSERVER_ENV_MAPS = {
    "azure": {
        "ELCAP_OBSERVER_AZURE_CLIENT_ID": "AZURE_CLIENT_ID",
        "ELCAP_OBSERVER_AZURE_CLIENT_SECRET": "AZURE_CLIENT_SECRET",
        "ELCAP_OBSERVER_AZURE_TENANT_ID": "AZURE_TENANT_ID",
    },
}


def scanner_env_map(provider: str) -> dict[str, str]:
    """Return one provider's credential map, rejecting unknown providers."""
    try:
        return SCANNER_ENV_MAPS[provider]
    except KeyError:
        raise ValueError(
            f"no scanner credential map for provider {provider!r} "
            f"(known: {', '.join(sorted(SCANNER_ENV_MAPS))})") from None


def observer_env_map(provider: str) -> dict[str, str]:
    try:
        return OBSERVER_ENV_MAPS[provider]
    except KeyError:
        raise ValueError(
            f"no observability credential map for provider {provider!r} "
            f"(known: {', '.join(sorted(OBSERVER_ENV_MAPS))})") from None
