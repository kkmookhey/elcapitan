"""A real `aws` executable on PATH, for tests of elcapitan.cloud.

cloud.py shells out to `aws` exactly as repo.py shells out to `git`. repo.py's
tests use a real git repository; there is no offline equivalent of an AWS
account, so these tests install a real executable named `aws` and let the
production code find it the production way — through PATH, through
subprocess, with argv parsed and stdout/stderr/exit code produced by a
separate process. argv construction, empty-stdout handling, the
absent-vs-denied distinction and the environment scrubbing are therefore all
genuinely exercised; only the account is fake.

The defaults below are not invented. Every one is what the real
`elcapitan-anna-scanner` role returned for the real Anna decks bucket on
2026-08-09 — including the two that matter most and would never have been
guessed: an unset configuration exits 0 with EMPTY stdout (not "{}"), and an
absent object-lock configuration exits 254 with
`ObjectLockConfigurationNotFoundError`.

The script deliberately locates its own response file relative to __file__
rather than through an environment variable, because cloud.verification_env
scrubs the environment down to PATH, HOME and the three AWS credentials — a
fake that needed anything else would not run under the code it is testing.
"""
import json
import os
import stat
from pathlib import Path

BUCKET_ARN = "arn:aws:s3:::anna-assets"
BUCKET = "anna-assets"

_SCRIPT = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

here = Path(__file__).resolve().parent
responses = json.loads((here / "aws-responses.json").read_text())
calls_path = here / "aws-calls.jsonl"

argv = sys.argv[1:]
operation = argv[1] if len(argv) > 1 else ""

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
    sys.stderr.write("aws: [ERROR]: An error occurred (FakeAwsNoStub) when calling "
                     "the %s operation: no stubbed reply\\n" % operation)
    sys.exit(254)
if seen and "then" in reply:
    reply = reply["then"]

if reply.get("sleep"):
    import time
    time.sleep(reply["sleep"])

sys.stdout.write(reply.get("stdout", ""))
sys.stderr.write(reply.get("stderr", ""))
sys.exit(reply.get("exit", 0))
'''


def default_responses() -> dict:
    """Measured against the real account; see the module docstring."""
    return {
        # exit 0 with EMPTY stdout — an unversioned bucket's real answer.
        "get-bucket-versioning": {"stdout": "", "exit": 0},
        "get-bucket-logging": {"stdout": "", "exit": 0},
        "get-bucket-notification-configuration": {"stdout": "", "exit": 0},
        "get-bucket-encryption": {"stdout": json.dumps({
            "ServerSideEncryptionConfiguration": {"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}),
            "exit": 0},
        "get-public-access-block": {"stdout": json.dumps({
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}), "exit": 0},
        "get-bucket-policy": {"stdout": json.dumps({"Policy": "{\"Version\":\"2012-10-17\"}"}),
                              "exit": 0},
        "get-bucket-acl": {"stdout": json.dumps(
            {"Owner": {"ID": "abc"}, "Grants": []}), "exit": 0},
        "get-bucket-tagging": {"stdout": json.dumps(
            {"TagSet": [{"Key": "aws:cloudformation:stack-name", "Value": "Stack"}]}),
            "exit": 0},
        # exit 254 with a known "genuinely not configured" code.
        "get-object-lock-configuration": {
            "stdout": "", "exit": 254,
            "stderr": "\naws: [ERROR]: An error occurred "
                      "(ObjectLockConfigurationNotFoundError) when calling the "
                      "GetObjectLockConfiguration operation: Object Lock "
                      "configuration does not exist for this bucket\n"},
    }


def denied(operation_error="AccessDenied") -> dict:
    return {"stdout": "", "exit": 254,
            "stderr": f"\naws: [ERROR]: An error occurred ({operation_error}) when "
                      f"calling the GetBucketVersioning operation: not authorized\n"}


def install(bin_dir: Path, responses: dict | None = None) -> Path:
    """Write an executable `aws` into bin_dir. Returns bin_dir."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "aws-responses.json").write_text(
        json.dumps(default_responses() if responses is None else responses))
    script = bin_dir / "aws"
    script.write_text(_SCRIPT)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


def calls(bin_dir: Path) -> list[dict]:
    path = Path(bin_dir) / "aws-calls.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def scanner_credentials() -> dict:
    """Host-side ELCAP_SCANNER_* values. Not real, and never sent anywhere:
    the fake `aws` ignores them entirely — they exist so that
    cloud.verification_env's all-or-nothing credential rule is satisfied the
    same way a real run satisfies it."""
    return {"ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "ASIAFAKEFAKEFAKEFAKE",
            "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "fake-secret",
            "ELCAP_SCANNER_AWS_SESSION_TOKEN": "fake-token"}


def env_with(bin_dir: Path, extra: dict | None = None) -> dict:
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "HOME": os.environ.get("HOME", "/tmp")}
    env.update(scanner_credentials())
    env.update(extra or {})
    return env
