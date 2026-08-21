"""A real `az` executable on PATH, for tests of elcapitan.cloud's Azure path.

The sibling of fake_aws.py, and it exists for the same reason: cloud.py shells
out to `az` the way it shells out to `aws`, so the tests install a real
executable named `az` and let the production code find it the production way —
through PATH, through subprocess, with argv parsed and stdout/stderr/exit code
produced by a separate process.

**Every default reply below is a REAL document**, captured on 2026-08-21 from
the live Eiger deployment (`eigercorpus8dlub3zy` in `eiger-rg`, subscription
`8cd2b4cc-...`) and committed under tests/fixtures/. It is not hand-written
JSON shaped like what Azure might return. This project's dominant defect class
is a check that passes against a synthetic artifact and fails against the real
one, and a fake cloud is precisely where that class breeds.

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
if seen and "then" in reply:
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


def default_responses(account: dict | None = None,
                      blob: dict | None = None) -> dict:
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
    }


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
