"""A real `az` executable on PATH, for tests of elcapitan.cloud's Azure path.

The sibling of fake_aws.py, and it exists for the same reason: cloud.py shells
out to `az` the way it shells out to `aws`, so the tests install a real
executable named `az` and let the production code find it the production way —
through PATH, through subprocess, with argv parsed and stdout/stderr/exit code
produced by a separate process.

Every default Storage reply below is a REAL document, captured on 2026-08-21
from the live Eiger deployment (`eigercorpus8dlub3zy` in `eiger-rg`,
subscription `8cd2b4cc-...`) and committed under tests/fixtures/. SQL replies
include both sanitized contract fixtures built from Microsoft's 2023-08-01 REST
schema and sanitized documents measured on 2026-08-28 from a disposable Azure
SQL lab. They contain no customer identifiers or observations. Tests label and
exercise those evidence origins separately. Key Vault replies likewise include
an official-schema contract fixture and a sanitized 2026-08-28 disposable-lab
response whose omitted properties are part of the tested contract.

Three measured facts drove the design of the code this fake exercises, and
none of them would have been guessed:

1. `az storage account blob-service-properties show` does **not** accept
   `--ids`. It requires `-n/--account-name` and `-g/--resource-group`, so the
   ARM resource id has to be parsed apart. Measured: passing `--ids` exits
   non-zero with "the following arguments are required: --account-name/-n".

2. `--query` on a property that does not exist exits **0 with empty stdout** —
   the same silent-green shape as an unset S3 configuration. A misspelled
   query would therefore record `""` forever and compare equal to itself. That
   is why the production code captures whole documents in one call and selects
   aspects by key in Python, where a missing key raises.

3. A resource that is absent exits **3** with `Code: ResourceNotFound` on
   stderr — not the 254 the `aws` CLI uses.
"""
import json
import os
import stat
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"

ACCOUNT_NAME = "eigercorpus8dlub3zy"
RESOURCE_GROUP = "eiger-rg"
SUBSCRIPTION = "8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
RESOURCE_UID = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}"
                f"/providers/Microsoft.Storage/storageAccounts/{ACCOUNT_NAME}")
SQL_SERVER_NAME = "elcap-sql-fixture"
SQL_RESOURCE_GROUP = "elcap-sql-fixture-rg"
SQL_SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
SQL_RESOURCE_UID = (
    f"/subscriptions/{SQL_SUBSCRIPTION}/resourceGroups/{SQL_RESOURCE_GROUP}"
    f"/providers/Microsoft.Sql/servers/{SQL_SERVER_NAME}")
KEY_VAULT_NAME = "elcap-keyvault-fixture"
KEY_VAULT_RESOURCE_GROUP = "elcap-keyvault-fixture-rg"
KEY_VAULT_RESOURCE_UID = (
    f"/subscriptions/{SQL_SUBSCRIPTION}/resourceGroups/{KEY_VAULT_RESOURCE_GROUP}"
    f"/providers/Microsoft.KeyVault/vaults/{KEY_VAULT_NAME}")
NETWORK_SUBNET_RESOURCE_UID = (
    f"/subscriptions/{SQL_SUBSCRIPTION}/resourceGroups/elcap-network-fixture-rg"
    "/providers/Microsoft.Network/virtualNetworks/elcap-vnet-fixture"
    "/subnets/validator-contract")
APP_SERVICE_RESOURCE_UID = (
    f"/subscriptions/{SQL_SUBSCRIPTION}/resourceGroups/elcap-app-fixture-rg"
    "/providers/Microsoft.Web/sites/elcap-app-fixture")
APP_SERVICE_CONFIG_RESOURCE_UID = APP_SERVICE_RESOURCE_UID + "/config/web"
FUNCTION_APP_RESOURCE_UID = (
    f"/subscriptions/{SQL_SUBSCRIPTION}/resourceGroups/elcap-app-fixture-rg"
    "/providers/Microsoft.Web/sites/elcap-function-fixture")
CONTAINER_REGISTRY_RESOURCE_UID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/elcapitan-remediation-lab-rg"
    "/providers/Microsoft.ContainerRegistry/registries/ca7b25e7d425acr")
AZURE_OPENAI_RESOURCE_UID = (
    f"/subscriptions/{SQL_SUBSCRIPTION}/resourceGroups/elcap-openai-fixture-rg"
    "/providers/Microsoft.CognitiveServices/accounts/elcap-openai-fixture")

# The operation key is the leading run of non-flag argv tokens, which is how
# `az` itself names a command ("storage account show"). Building it from argv
# rather than matching whole command lines keeps the fake indifferent to flag
# order, exactly as the real CLI is.
_SCRIPT = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

here = Path(__file__).resolve().parent
responses = json.loads((here / "az-responses.json").read_text())
calls_path = here / "az-calls.jsonl"

argv = sys.argv[1:]
words = []
for token in argv:
    if token.startswith("-"):
        break
    words.append(token)
operation = " ".join(words)

seen = 0
if calls_path.exists():
    for line in calls_path.read_text().splitlines():
        if line.strip() and json.loads(line)["operation"] == operation:
            seen += 1

with calls_path.open("a") as fh:
    fh.write(json.dumps({"argv": argv, "operation": operation,
                         "env": sorted(os.environ)}) + "\\n")

reply = responses.get(operation)
if reply is None:
    sys.stderr.write("ERROR: '%s' is misspelled or not recognized by the system.\\n"
                     % operation)
    sys.exit(2)
if "sequence" in reply:
    sequence = reply["sequence"]
    if seen >= len(sequence):
        sys.stderr.write("ERROR: no configured response %d for %s.\\n" % (seen, operation))
        sys.exit(2)
    reply = sequence[seen]
elif seen and "then" in reply:
    reply = reply["then"]

if reply.get("sleep"):
    import time
    time.sleep(reply["sleep"])

sys.stdout.write(reply.get("stdout", ""))
sys.stderr.write(reply.get("stderr", ""))
sys.exit(reply.get("exit", 0))
'''


def account_document() -> dict:
    """The real `az storage account show` document, measured 2026-08-21."""
    return json.loads((FIXTURES / "azure-storage-account-show.json").read_text())


def blob_document() -> dict:
    """The real `az storage account blob-service-properties show` document."""
    return json.loads((FIXTURES / "azure-blob-service-properties.json").read_text())


def file_service_document() -> dict:
    """Sanitized File Service response measured on the Eiger lab."""
    return json.loads((FIXTURES / "azure-file-service-properties.json").read_text())


def container_registry_document() -> dict:
    """Sanitized response measured from the existing El Capitan lab ACR."""
    return json.loads(
        (FIXTURES / "azure-container-registry-lab-response.json").read_text())


def sql_protector_document() -> dict:
    return json.loads((FIXTURES / "azure-sql-encryption-protector.json").read_text())


def sql_databases_document() -> dict:
    return json.loads((FIXTURES / "azure-sql-databases.json").read_text())


def sql_tde_document() -> dict:
    return json.loads((FIXTURES / "azure-sql-tde-enabled.json").read_text())


def sql_lab_protector_document() -> dict:
    """Sanitized response measured from the disposable SQL validation lab."""
    return json.loads(
        (FIXTURES / "azure-sql-lab-service-managed-protector.json").read_text())


def sql_lab_databases_document() -> dict:
    """Sanitized pageless database response measured from the SQL lab."""
    return json.loads((FIXTURES / "azure-sql-lab-databases.json").read_text())


def sql_lab_tde_document() -> dict:
    """Sanitized user-database TDE response measured from the SQL lab."""
    return json.loads((FIXTURES / "azure-sql-lab-tde-enabled.json").read_text())


def key_vault_document() -> dict:
    """Synthetic fixture pinned to the official 2024-11-01 REST schema."""
    return json.loads((FIXTURES / "azure-key-vault-contract.json").read_text())


def key_vault_lab_document() -> dict:
    """Sanitized response measured from the disposable Key Vault lab."""
    return json.loads((FIXTURES / "azure-key-vault-lab-response.json").read_text())


def network_subnet_document() -> dict:
    """Sanitized response measured from the disposable subnet lab."""
    return json.loads(
        (FIXTURES / "azure-network-subnet-lab-response.json").read_text())


def app_site_document() -> dict:
    """Sanitized response measured from the disposable App Service lab."""
    return json.loads((FIXTURES / "azure-app-site-contract.json").read_text())


def app_web_config_document() -> dict:
    return json.loads((FIXTURES / "azure-app-web-config-contract.json").read_text())


def app_auth_v2_document() -> dict:
    return json.loads((FIXTURES / "azure-app-auth-v2-contract.json").read_text())


def app_diagnostic_settings_document() -> dict:
    return json.loads(
        (FIXTURES / "azure-app-diagnostic-settings-contract.json").read_text())


def function_site_lab_document() -> dict:
    return json.loads(
        (FIXTURES / "azure-function-site-lab-response.json").read_text())


def function_web_config_lab_document() -> dict:
    return json.loads(
        (FIXTURES / "azure-function-web-config-lab-response.json").read_text())


def function_auth_v2_lab_document() -> dict:
    return json.loads(
        (FIXTURES / "azure-function-auth-v2-lab-response.json").read_text())


def metrics_populated() -> str:
    """A REAL Transactions window containing measured activity: 15 one-minute
    points, one of them 1.0 — the health check's corpus blob read."""
    return (FIXTURES / "azure-metrics-transactions-populated.json").read_text()


def metrics_all_zero() -> str:
    """A REAL Transactions window over a quiet period. THE DANGEROUS SHAPE:
    15 points, every one `total: 0.0`, none missing the key. Identical to what
    a window that has not finished ingesting returns, which is why the
    collector cannot decide populated-vs-not by asking whether the query
    worked."""
    return (FIXTURES / "azure-metrics-transactions-allzero.json").read_text()


def logs_populated() -> str:
    """REAL ContainerAppConsoleLogs_CL rows: the GET /health and POST /api/kb
    that the corpus read shows up as."""
    return (FIXTURES / "azure-logs-containerapp-populated.json").read_text()


def logs_empty() -> str:
    """MEASURED: a quiet log window really does return zero rows — unlike
    metrics, logs ARE distinguishable populated-vs-empty by shape."""
    return "[]"


def default_responses(account: dict | None = None,
                      blob: dict | None = None,
                      file_service: dict | None = None,
                      metrics: str | None = None,
                      logs: str | None = None) -> dict:
    return {
        # `az login --service-principal` prints the subscription list on
        # success. The production code ignores stdout here and only checks the
        # exit code, so the body is deliberately minimal.
        "login": {"stdout": "[]", "exit": 0},
        "logout": {"stdout": "", "exit": 0},
        "storage account show": {
            "stdout": json.dumps(account_document() if account is None else account),
            "exit": 0},
        "storage account blob-service-properties show": {
            "stdout": json.dumps(blob_document() if blob is None else blob),
            "exit": 0},
        "storage account file-service-properties show": {
            "stdout": json.dumps(
                file_service_document() if file_service is None else file_service),
            "exit": 0},
        "monitor metrics list": {
            "stdout": metrics_populated() if metrics is None else metrics, "exit": 0},
        "monitor log-analytics query": {
            "stdout": logs_populated() if logs is None else logs, "exit": 0},
    }


def sql_responses(*, protector: dict | None = None,
                  databases: dict | None = None,
                  tde: dict | None = None) -> dict:
    return {
        "login": {"stdout": "[]", "exit": 0},
        "rest": {"sequence": [
            {"stdout": json.dumps(
                sql_protector_document() if protector is None else protector), "exit": 0},
            {"stdout": json.dumps(
                sql_databases_document() if databases is None else databases), "exit": 0},
            {"stdout": json.dumps(
                sql_tde_document() if tde is None else tde), "exit": 0},
        ]},
    }


def sql_lab_responses() -> dict:
    return sql_responses(
        protector=sql_lab_protector_document(),
        databases=sql_lab_databases_document(),
        tde=sql_lab_tde_document(),
    )


def key_vault_responses(*, vault: dict | None = None) -> dict:
    return {
        "login": {"stdout": "[]", "exit": 0},
        "rest": {"stdout": json.dumps(
            key_vault_document() if vault is None else vault), "exit": 0},
    }


def key_vault_lab_responses() -> dict:
    return key_vault_responses(vault=key_vault_lab_document())


def network_subnet_responses(*, subnet: dict | None = None) -> dict:
    return {
        "login": {"stdout": "[]", "exit": 0},
        "rest": {"stdout": json.dumps(
            network_subnet_document() if subnet is None else subnet), "exit": 0},
    }


def app_service_responses(*, site: dict | None = None,
                          web_config: dict | None = None,
                          auth: dict | None = None,
                          diagnostics: dict | None = None) -> dict:
    return {
        "login": {"stdout": "[]", "exit": 0},
        "rest": {"sequence": [
            {"stdout": json.dumps(
                app_site_document() if site is None else site), "exit": 0},
            {"stdout": json.dumps(
                app_web_config_document() if web_config is None else web_config),
             "exit": 0},
            {"stdout": json.dumps(
                app_auth_v2_document() if auth is None else auth), "exit": 0},
            {"stdout": json.dumps(
                app_diagnostic_settings_document()
                if diagnostics is None else diagnostics), "exit": 0},
        ]},
    }


def function_app_lab_responses() -> dict:
    return app_service_responses(
        site=function_site_lab_document(),
        web_config=function_web_config_lab_document(),
        auth=function_auth_v2_lab_document(),
    )


def container_registry_responses(*, registry: dict | None = None) -> dict:
    return {
        "login": {"stdout": "[]", "exit": 0},
        "rest": {"stdout": json.dumps(
            container_registry_document() if registry is None else registry),
            "exit": 0},
    }


def azure_openai_document() -> dict:
    """Sanitized contract fixture based on Accounts - Get 2025-06-01."""
    return json.loads((FIXTURES / "azure-openai-account-contract.json").read_text())


def azure_openai_responses(*, account: dict | None = None) -> dict:
    return {
        "login": {"stdout": "[]", "exit": 0},
        "rest": {"stdout": json.dumps(
            azure_openai_document() if account is None else account), "exit": 0},
    }


def observer_credentials() -> dict:
    """The OBSERVABILITY credential, which is a different principal from the
    scanner: reading metrics needs Monitoring Reader and reading the workspace
    needs Log Analytics Reader, neither of which the scanner's Reader role
    grants over log data. Never real — the fake ignores them."""
    return {"ELCAP_OBSERVER_AZURE_CLIENT_ID": "00000000-0000-0000-0000-0000000obsv",
            "ELCAP_OBSERVER_AZURE_CLIENT_SECRET": "fake-observer-secret",
            "ELCAP_OBSERVER_AZURE_TENANT_ID": "017c6f31-f951-4bda-a50a-c168c0e6f815"}


def with_account_property(name: str, value) -> dict:
    """Default replies, with one account property changed — how a test makes
    the resource *actually* differ between two captures."""
    account = account_document()
    account[name] = value
    return default_responses(account=account)


def not_found() -> dict:
    """MEASURED: an absent resource exits 3, with `Code: ResourceNotFound`."""
    return {"stdout": "", "exit": 3,
            "stderr": "ERROR: (ResourceNotFound) The Resource "
                      "'Microsoft.Storage/storageAccounts/nosuchacct999' under resource "
                      "group 'eiger-rg' was not found. For more details please go to "
                      "https://aka.ms/ARMResourceNotFoundFix\n"
                      "Code: ResourceNotFound\n"}


def install(bin_dir: Path, responses: dict | None = None) -> Path:
    """Write an executable `az` into bin_dir. Returns bin_dir."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "az-responses.json").write_text(
        json.dumps(default_responses() if responses is None else responses))
    script = bin_dir / "az"
    script.write_text(_SCRIPT)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


def calls(bin_dir: Path) -> list[dict]:
    path = Path(bin_dir) / "az-calls.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def scanner_credentials() -> dict:
    """Host-side ELCAP_SCANNER_AZURE_* values. Not real, and never sent
    anywhere: the fake `az` ignores them entirely — they exist so that
    cloud.verification_env's all-or-nothing credential rule is satisfied the
    same way a real run satisfies it."""
    return {"ELCAP_SCANNER_AZURE_CLIENT_ID": "00000000-0000-0000-0000-00000000fake",
            "ELCAP_SCANNER_AZURE_CLIENT_SECRET": "fake-secret",
            "ELCAP_SCANNER_AZURE_TENANT_ID": "017c6f31-f951-4bda-a50a-c168c0e6f815"}


def env_with(bin_dir: Path, extra: dict | None = None) -> dict:
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "HOME": os.environ.get("HOME", "/tmp")}
    env.update(scanner_credentials())
    env.update(extra or {})
    return env
