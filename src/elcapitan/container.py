"""Ephemeral container specs — the experiment's isolation boundary.

Hermes profiles isolate config, sessions, skills and memory, but the docs are
explicit that "a profile does not stop it from accessing folders outside the
profile directory", and profiles are not a security boundary. Containers are.

Secret VALUES never appear here. `--env NAME` passes a value through from the
docker client's environment, so nothing sensitive lands in argv, exceptions,
logs, or test strings.
"""
from dataclasses import dataclass, field
from pathlib import PurePosixPath

GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")
VALID_ARMS = ("A", "B")
HARDENING = ("--cap-drop=ALL", "--security-opt=no-new-privileges",
             "--pids-limit=512", "--memory=4g", "--cpus=2")

@dataclass(frozen=True)
class Mount:
    source: str
    target: str
    read_only: bool

    def to_flag(self) -> str:
        suffix = ",readonly" if self.read_only else ""
        return f"--mount=type=bind,source={self.source},target={self.target}{suffix}"

@dataclass(frozen=True)
class ContainerSpec:
    image: str
    mounts: list[Mount]
    env_passthrough: list[str]     # NAMES ONLY — never values
    host_hermes_home: str          # host path; the mountpoint is always /opt/data
    network: str
    command: list[str] = field(default_factory=list)
    hardening: tuple[str, ...] = HARDENING

    def to_argv(self) -> list[str]:
        argv = ["docker", "run", "--rm", f"--network={self.network}", *self.hardening]
        # No --user: s6-overlay is PID 1 and drops to the hermes user itself.
        argv += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"]
        argv += [m.to_flag() for m in self.mounts]
        for name in self.env_passthrough:
            argv += ["--env", name]
        argv += [self.image, *self.command]
        return argv

def _reject_ground_truth(mounts: list[Mount]) -> None:
    for mount in mounts:
        haystack = f"{mount.source} {mount.target}".lower()
        if any(marker in haystack for marker in GROUND_TRUTH_MARKERS):
            raise ValueError(f"refusing to mount ground truth into an agent container: "
                             f"{mount.source}")

def engineer_spec(*, runtime_image_id, run_dir, canonical_repo, host_hermes_home,
                  env_passthrough, extra_mounts=None, command=None) -> ContainerSpec:
    mounts = [
        Mount(str(canonical_repo), "/work/canonical", True),
        Mount(str(run_dir), "/work/run", False),
        Mount(str(host_hermes_home), "/opt/data", False),
        *(extra_mounts or []),
    ]
    _reject_ground_truth(mounts)
    return ContainerSpec(image=runtime_image_id, mounts=mounts,
                         env_passthrough=list(env_passthrough),
                         host_hermes_home=str(host_hermes_home),
                         network="bridge", command=command or [])

def challenger_spec(*, runtime_image_id, run_dir, bundle_path, host_hermes_home,
                    arm, env_passthrough, command=None) -> ContainerSpec:
    if arm not in VALID_ARMS:
        raise ValueError(f"unknown arm {arm!r}; expected one of {VALID_ARMS}")
    for name in env_passthrough:
        if name.startswith(("AWS_", "AZURE_", "ARM_")):
            raise ValueError(
                f"challenger must hold no cloud credentials; got {name}. "
                "The evidence collector holds the observer credential.")
    mounts = [
        Mount(str(bundle_path), "/work/bundle", True),
        Mount(str(PurePosixPath(run_dir) / "verdict"), "/work/out", False),
        Mount(str(host_hermes_home), "/opt/data", False),
    ]
    _reject_ground_truth(mounts)
    return ContainerSpec(image=runtime_image_id, mounts=mounts,
                         env_passthrough=list(env_passthrough),
                         host_hermes_home=str(host_hermes_home),
                         network="none", command=command or [])
