"""Black-box smoke tests against the real image. `ELCAP_SMOKE=1` to run.

Unit-testing generated argv proves nothing about whether a container runs.
Worse, per docs/spike-findings.md §6, a container that did nothing at all
still exits 0 — so a test that asserts only on exit status reproduces the
exact defect the spike found, one layer down. Every test here therefore
asserts on **evidence that the work happened**: version strings the tools
actually printed, files that actually appeared on the host, a directory that
actually got populated.

## The Linux capability question

`container.HARDENING` adds `--cap-add=SETUID --cap-add=SETGID` on top of
`--cap-drop=ALL`, verified on macOS + Docker Desktop only — see that tuple's
own comment. Docker Desktop's bind-mount layer masks the ownership and
permission failures that `--cap-drop=ALL` causes by also dropping
CAP_CHOWN/CAP_FOWNER/CAP_DAC_OVERRIDE. `--tmpfs /opt/data` is a real Linux
filesystem inside the Docker VM with real Linux permission semantics, and it
is what makes the failure visible from a Mac.

`test_hardened_container_populates_opt_data_on_a_real_linux_filesystem` is
the detector, and **it is expected to FAIL** until the capability set is
resolved. That is deliberate: the alternative is a green suite over a runtime
that does not work outside one developer's laptop.
`test_opt_data_initialisation_needs_chown_fowner_and_dac_override` is the
diagnosis: the identical run with those three capabilities restored succeeds,
which is what makes "the capability set is wrong" a measurement rather than a
guess. Resolving it is not this task's job; detecting it is.

Measured on macOS/Docker Desktop (arm64), image elcapitan-lab:0.1.0, four
mount kinds for /opt/data under the same HARDENING tuple:

| /opt/data is | result |
|---|---|
| bind mount (what the harness uses) | populated, 16 entries — Docker Desktop masks it |
| `--tmpfs` (root-owned, default mode) | **empty**, exit 0, 16 `Permission denied` lines |
| `--tmpfs ...,mode=0777` | populated — proves the blocker is write access, not the tmpfs |
| named volume pre-chowned to 10000 | `main-wrapper.sh: cd: can't cd to /opt/data`, exit 2 |

and the last two rows both become clean runs once CHOWN, FOWNER and
DAC_OVERRIDE are added back.
"""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from elcapitan.container import HARDENING, engineer_spec

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "runtime.lock.json").read_text())
IMAGE = LOCK["runtime_image_id"]

# Every wording the image's init actually produced when the capability set was
# insufficient — measured, not imagined: "mkdir: cannot create directory
# '/opt/data': Permission denied", "[supervise-perms] could not chown ...",
# "PermissionError: [Errno 13] Permission denied: '/opt/data/...'".
PERMISSION_FAILURE = re.compile(
    r"permission denied|operation not permitted|could not chown", re.IGNORECASE)

pytestmark = pytest.mark.skipif(os.environ.get("ELCAP_SMOKE") != "1",
                                reason="set ELCAP_SMOKE=1 to run container smoke tests")


def docker(*args, timeout=300) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout)


def combined(result: subprocess.CompletedProcess) -> str:
    """s6 init writes to both streams; the interesting failures land on
    stderr while the command's own output lands on stdout."""
    return result.stdout + result.stderr


def opt_data_entry_count(output: str) -> int:
    match = re.search(r"OPT_DATA_ENTRIES=(\d+)", output)
    assert match, f"marker never printed; the container did not reach the command:\n{output[-3000:]}"
    return int(match.group(1))


# --- the image under test is the pinned one -------------------------------

def test_the_pinned_image_id_exists_locally():
    """Every other test here runs `docker run <runtime_image_id>`. If that id
    is not present, `docker run` would try to pull it and fail in a way that
    looks like a container defect rather than a missing build."""
    result = docker("image", "inspect", IMAGE, "--format", "{{index .RepoTags 0}}")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == LOCK["runtime_image_ref"]


def test_pinned_tools_are_present_at_the_pinned_versions():
    """Asserting exit 0 alone would pass on an image where every one of these
    printed a version nobody pinned."""
    result = docker("run", "--rm", "--network=none", IMAGE, "sh", "-lc",
                    "terraform version; trivy --version; prowler --version; "
                    "aws --version; az version")
    output = combined(result)
    versions = LOCK["tool_versions"]
    for expected in (f"Terraform v{versions['terraform']}",
                     f"Version: {versions['trivy']}",
                     f"Prowler {versions['prowler']}",
                     f"aws-cli/{versions['awscli']}",
                     f'"azure-cli": "{versions["azure-cli"]}"'):
        assert expected in output, f"{expected!r} not in output:\n{output[-3000:]}"


# --- the capability set, on a real Linux filesystem ------------------------

def _run_init_with(caps_and_flags, mount_flags):
    return docker("run", "--rm", "--network=none", *caps_and_flags, *mount_flags,
                  IMAGE, "sh", "-lc",
                  'echo "OPT_DATA_ENTRIES=$(ls -A /opt/data 2>/dev/null | wc -l)"')


def test_hardened_container_populates_opt_data_on_a_real_linux_filesystem():
    """The detector. HARDENING is imported, not restated, so this tracks the
    real flag set rather than a copy of it.

    Note what is deliberately NOT asserted: the exit status. The measured
    failure mode is exit 0 with fifteen `mkdir: cannot create directory
    '/opt/data': Permission denied` lines and an empty /opt/data — asserting
    on the exit code would score that green.
    """
    result = _run_init_with(HARDENING, ("--tmpfs", "/opt/data"))
    output = combined(result)

    assert opt_data_entry_count(output) > 0, (
        "the container started and exited "
        f"{result.returncode} with /opt/data empty — s6 init never populated the "
        f"Hermes home, so no agent could run in it:\n{output[-3000:]}")
    failures = [line for line in output.splitlines() if PERMISSION_FAILURE.search(line)]
    assert not failures, (
        "container init hit permission failures under HARDENING:\n"
        + "\n".join(failures[:20]))


def test_opt_data_initialisation_needs_chown_fowner_and_dac_override():
    """The diagnosis for the test above. Identical run, three capabilities
    restored on top of the same --cap-drop=ALL baseline. It passing while the
    test above fails is what identifies the cause as the capability set rather
    than the image, the tmpfs, or the command."""
    result = _run_init_with(
        (*HARDENING, "--cap-add=CHOWN", "--cap-add=FOWNER", "--cap-add=DAC_OVERRIDE"),
        ("--tmpfs", "/opt/data"))
    output = combined(result)

    assert opt_data_entry_count(output) > 0, output[-3000:]
    failures = [line for line in output.splitlines() if PERMISSION_FAILURE.search(line)]
    assert not failures, "\n".join(failures[:20])


# --- the mounts the harness actually generates -----------------------------

def test_engineer_spec_argv_really_launches_and_honours_its_mounts(tmp_path):
    """The harness's own spec, run for real. Three genuinely distinct paths:
    container.py rejects run_dir == canonical_repo == host_hermes_home, and
    rejects any spec whose own paths nest."""
    run_dir, repo, home = tmp_path / "run", tmp_path / "repo", tmp_path / "home"
    for directory in (run_dir, repo, home):
        directory.mkdir()
    (repo / "main.tf").write_text("original\n")

    spec = engineer_spec(
        runtime_image_id=IMAGE, run_dir=run_dir, canonical_repo=repo,
        host_hermes_home=home, env_passthrough=[],
        command=["sh", "-lc",
                 "cat /work/canonical/main.tf > /work/run/seen.txt; "
                 "echo mutated > /work/canonical/main.tf; "
                 "echo ok > /work/run/done.txt"])

    result = subprocess.run(spec.to_argv(), capture_output=True, text=True, timeout=300)

    # Writable run mount: the file the container created is on the host.
    assert (run_dir / "done.txt").is_file(), combined(result)[-3000:]
    # Read-only canonical mount: readable inside...
    assert (run_dir / "seen.txt").read_text() == "original\n"
    # ...and the write did not land. The mount is the enforcement.
    assert (repo / "main.tf").read_text() == "original\n"


def test_read_only_mount_is_actually_read_only(tmp_path):
    (tmp_path / "f.txt").write_text("original")
    result = docker("run", "--rm", "--network=none",
                    f"--mount=type=bind,source={tmp_path},target=/ro,readonly",
                    IMAGE, "sh", "-lc", "echo mutated > /ro/f.txt")
    assert result.returncode != 0
    assert (tmp_path / "f.txt").read_text() == "original"


# --- network isolation -----------------------------------------------------

def test_curl_is_present_so_the_egress_test_is_not_vacuous():
    """Without this, test_network_none_blocks_egress passes just as happily
    against an image with no curl in it — a nonzero exit for the wrong
    reason, which is the whole defect class this file exists to avoid."""
    result = docker("run", "--rm", "--network=none", IMAGE, "sh", "-lc",
                    "command -v curl")
    assert "/curl" in result.stdout, combined(result)[-2000:]


def test_network_none_blocks_egress():
    result = docker("run", "--rm", "--network=none", IMAGE, "sh", "-lc",
                    "curl -sS --max-time 5 https://example.com")
    assert result.returncode != 0
    # A resolution/connection failure, not "curl: command not found" — the
    # companion test above pins curl's presence, this pins the reason.
    assert PERMISSION_FAILURE.search(result.stderr) or "curl:" in result.stderr, \
        combined(result)[-2000:]
