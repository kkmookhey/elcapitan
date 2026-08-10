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
CAP_CHOWN/CAP_FOWNER/CAP_DAC_OVERRIDE, so on a Mac the runtime looks fine
while being broken everywhere else.

Reproducing that from a Mac needs a real Linux filesystem inside the Docker
VM. Two are used here, in decreasing order of fidelity to what the harness
actually does:

- **A named volume `chown`ed to the host uid/gid and `chmod 700`, with
  `HERMES_UID`/`HERMES_GID` passed** — this is what `mktemp -d` +
  `seed_hermes_home` + `bin/agent-run.sh` produce on a Linux host, and it is
  therefore the *primary* detector. An earlier revision of this file called
  the remap a possible escape ("HERMES_UID might save it"); measurement closed
  that question in the other direction — the remap itself needs the dropped
  capabilities.
- **`--tmpfs /opt/data`** — cruder (root-owned, and the harness never mounts a
  tmpfs there), kept as a secondary case because it fails in a *different
  shape* and a partial fix could satisfy one while leaving the other broken.

Measured on macOS/Docker Desktop (arm64), image elcapitan-lab:0.1.0, same
HARDENING tuple, varying only what `/opt/data` is:

| `/opt/data` is | under `HARDENING` | `+ CHOWN,FOWNER,DAC_OVERRIDE` |
|---|---|---|
| bind mount (Docker Desktop) | populated, 16 entries — masked | n/a |
| **named volume, `chown` host uid/gid, `chmod 700`, `HERMES_UID`/`GID` set** | **exit 2**, `PermissionError: '/opt/data/gateway_state.json'`, `main-wrapper.sh: cd: can't cd to /opt/data` | exit 0, `uid=…(hermes)`, 19 entries |
| `--tmpfs` (root-owned, default mode) | **exit 0**, empty, 16 × `Permission denied` | exit 0, 16 entries, clean |
| `--tmpfs …,mode=0777` | populated — so the blocker is write access, not the tmpfs | n/a |
| named volume `chown`ed to 10000, `chmod 755` | `cd: can't cd to /opt/data`, exit 2 | exit 0, `uid=10000(hermes)`, 19 entries |

Note the two failure shapes: the production-faithful case exits **2**, the
tmpfs case exits **0**. Either alone would be a partial detector.

Both detectors are `xfail(strict=True)`, not hard failures. The smoke suite is
the operator's go/no-go check before the first scored trial on Linux, and a
permanently-red suite cannot serve as one: a second, genuine regression would
be indistinguishable at a glance. Strict xfail keeps the suite green, and
flips to a **failure** the moment someone fixes the capability set — the
transition signal a hard failure cannot give. Their companions (the same runs
with the three capabilities restored) are ordinary passing tests, and that
pairing is what makes "the capability set is wrong" a measurement rather than
a guess. Resolving it is not this task's job; detecting it is.
"""
import contextlib
import json
import os
import re
import subprocess
import uuid
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

# The three the image's s6 init needs and `--cap-drop=ALL` takes away. Not
# added to container.HARDENING here: CAP_DAC_OVERRIDE bypasses every file
# permission check, which is a real reduction in the isolation boundary and a
# decision for a human, not a side effect of a test file.
RESTORED_CAPS = ("--cap-add=CHOWN", "--cap-add=FOWNER", "--cap-add=DAC_OVERRIDE")
XFAIL_REASON = ("container.HARDENING drops CHOWN/FOWNER/DAC_OVERRIDE; see "
                ".superpowers/sdd/2026-08-08-probe-substrate-and-shakedown/"
                "task-12-report.md §6. If this XPASSes, the capability set was "
                "fixed — delete the marker.")
MARKER_COMMAND = 'id; echo "OPT_DATA_ENTRIES=$(ls -A /opt/data 2>/dev/null | wc -l)"'


def _run_init_with(caps_and_flags, mount_flags, env_flags=()):
    return docker("run", "--rm", "--network=none", *env_flags, *caps_and_flags,
                  *mount_flags, IMAGE, "sh", "-lc", MARKER_COMMAND)


def assert_the_container_did_the_work(result, *, label):
    """Never asserts on exit status. The two measured failures are exit 0 with
    an empty /opt/data (tmpfs) and exit 2 with `cd: can't cd to /opt/data`
    (volume) — an exit-status assertion scores the first green and blames the
    second on the wrong thing."""
    output = combined(result)
    assert opt_data_entry_count(output) > 0, (
        f"{label}: container exited {result.returncode} with /opt/data empty or "
        f"unreachable — s6 init never populated the Hermes home, so no agent "
        f"could run in it:\n{output[-3000:]}")
    failures = [line for line in output.splitlines() if PERMISSION_FAILURE.search(line)]
    assert not failures, (f"{label}: container init hit permission failures:\n"
                          + "\n".join(failures[:20]))


@contextlib.contextmanager
def linux_hermes_home_volume(uid, gid, mode="700"):
    """A named docker volume owned and permissioned the way `mktemp -d` +
    `seed_hermes_home` leave a host directory on a Linux box.

    A named volume lives on the Docker VM's own Linux filesystem, so it has
    real Linux ownership semantics — unlike a bind mount from macOS, whose
    virtiofs layer is exactly what has been masking this failure. The `chown`
    runs in a container with default capabilities (`--entrypoint sh`, so s6
    init is bypassed and it costs ~0.3s); the container under test still gets
    the hardened set.
    """
    name = f"elcap-smoke-{uuid.uuid4().hex[:12]}"
    created = docker("volume", "create", name)
    assert created.returncode == 0, created.stderr
    try:
        prepared = docker("run", "--rm", "--entrypoint", "sh", "-v", f"{name}:/d",
                          IMAGE, "-c", f"chown {uid}:{gid} /d && chmod {mode} /d")
        assert prepared.returncode == 0, combined(prepared)
        yield name
    finally:
        docker("volume", "rm", "-f", name)


@pytest.mark.xfail(strict=True, reason=XFAIL_REASON)
def test_hardened_container_initialises_a_production_shaped_hermes_home():
    """**The primary detector**, and the one closest to production: a real
    Linux filesystem owned by the invoking user at mode 700, with
    HERMES_UID/HERMES_GID passed exactly as bin/agent-run.sh passes them.

    That remap was the open question in this task's first revision — whether
    it might let the harness work on Linux despite the capability set.
    Measured: it does not. The remap itself needs the dropped capabilities,
    and this configuration fails *harder* than the tmpfs case below (exit 2,
    `main-wrapper.sh: cd: can't cd to /opt/data`, rather than exit 0 with an
    empty directory).

    HARDENING is imported, not restated, so this tracks the real flag set.
    """
    uid, gid = os.getuid(), os.getgid()
    with linux_hermes_home_volume(uid, gid) as volume:
        result = _run_init_with(HARDENING, ("-v", f"{volume}:/opt/data"),
                                ("-e", f"HERMES_UID={uid}", "-e", f"HERMES_GID={gid}"))
    assert_the_container_did_the_work(result, label="production-shaped home")


def test_production_shaped_home_works_once_chown_fowner_dac_override_return():
    """The diagnosis for the detector above. Identical run — same volume
    ownership, same remap, same command — with three capabilities restored on
    top of the same --cap-drop=ALL baseline. This passing while the detector
    xfails is what identifies the cause as the capability set rather than the
    image, the filesystem, the remap, or the command."""
    uid, gid = os.getuid(), os.getgid()
    with linux_hermes_home_volume(uid, gid) as volume:
        result = _run_init_with((*HARDENING, *RESTORED_CAPS),
                                ("-v", f"{volume}:/opt/data"),
                                ("-e", f"HERMES_UID={uid}", "-e", f"HERMES_GID={gid}"))
    assert_the_container_did_the_work(result, label="production-shaped home + caps")
    assert f"uid={uid}" in combined(result), (
        "the HERMES_UID remap did not take effect, so this run is not the "
        "configuration it claims to be")


@pytest.mark.xfail(strict=True, reason=XFAIL_REASON)
def test_hardened_container_populates_a_tmpfs_hermes_home():
    """Secondary detector. Cruder than the one above — the harness never
    mounts a tmpfs at /opt/data — but kept because it fails in a *different
    shape*: exit 0 with an empty directory and 16 `mkdir: cannot create
    directory '/opt/data': Permission denied` lines, where the production
    case exits 2. A partial fix to the capability set could satisfy one and
    leave the other broken, so both are checked."""
    result = _run_init_with(HARDENING, ("--tmpfs", "/opt/data"))
    assert_the_container_did_the_work(result, label="tmpfs home")


def test_tmpfs_home_works_once_chown_fowner_dac_override_return():
    """The diagnosis for the secondary detector."""
    result = _run_init_with((*HARDENING, *RESTORED_CAPS), ("--tmpfs", "/opt/data"))
    assert_the_container_did_the_work(result, label="tmpfs home + caps")


# --- the mounts the harness actually generates -----------------------------

def test_engineer_spec_argv_really_launches_and_honours_its_mounts(tmp_path):
    """The harness's own spec, run for real. Three genuinely distinct paths:
    container.py rejects run_dir == canonical_repo == host_hermes_home, and
    rejects any spec whose own paths nest.

    Scope note for whoever sees this fail on Linux: what it checks is the two
    /work mounts. The host_hermes_home it passes is an unseeded empty
    directory and the network is `bridge` (engineer_spec's own settings), so on
    a Linux host this will *also* break for the capability reason the two
    detectors above cover — and it will read as a mount defect, which it is
    not. Fix the capability set first, then re-run this.
    """
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
