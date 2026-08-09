"""Ephemeral container specs — the experiment's isolation boundary.

Hermes profiles isolate config, sessions, skills and memory, but the docs are
explicit that "a profile does not stop it from accessing folders outside the
profile directory", and profiles are not a security boundary. Containers are.

Secret VALUES never appear here. `--env NAME` passes a value through from the
docker client's environment, so nothing sensitive lands in argv, exceptions,
logs, or test strings.
"""
import itertools
import posixpath
from dataclasses import dataclass
from pathlib import PurePosixPath

from .constants import GROUND_TRUTH_MARKERS

VALID_ARMS = ("A", "B")
# Every well-known host path for the docker control socket. Mounting any of
# them — or any directory that lexically contains one — hands the container
# full control of the host daemon, which is a complete escape from the
# isolation boundary this module exists to draw.
DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
HARDENING = ("--cap-drop=ALL", "--security-opt=no-new-privileges",
             "--pids-limit=512", "--memory=4g", "--cpus=2")
# Both characters are docker `--mount` option separators. Letting either
# through a path would let a mount source/target inject extra mount options
# (e.g. smuggling in `readonly` on a mount meant to be writable, or vice versa).
FORBIDDEN_MOUNT_CHARS = (",", "=")

@dataclass(frozen=True)
class Mount:
    source: str
    target: str
    read_only: bool

    def __post_init__(self) -> None:
        for value, label in ((self.source, "source"), (self.target, "target")):
            if any(ch in value for ch in FORBIDDEN_MOUNT_CHARS):
                raise ValueError(
                    f"mount {label} must not contain ',' or '=' — both are docker "
                    f"--mount option separators: {value!r}")

    def to_flag(self) -> str:
        suffix = ",readonly" if self.read_only else ""
        return f"--mount=type=bind,source={self.source},target={self.target}{suffix}"

@dataclass(frozen=True)
class ContainerSpec:
    image: str
    mounts: tuple[Mount, ...]
    env_passthrough: tuple[str, ...]   # NAMES ONLY — never values
    host_hermes_home: str              # host path; the mountpoint is always /opt/data
    network: str
    command: tuple[str, ...] = ()
    hardening: tuple[str, ...] = HARDENING
    arm: str | None = None             # which experimental arm this spec was built for

    def to_argv(self) -> list[str]:
        argv = ["docker", "run", "--rm", f"--network={self.network}", *self.hardening]
        # No --user: s6-overlay is PID 1 and drops to the hermes user itself.
        argv += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"]
        argv += [m.to_flag() for m in self.mounts]
        for name in self.env_passthrough:
            argv += ["--env", name]
        argv += [self.image, *self.command]
        return argv

def _normalize(path: str) -> str:
    """Lexical normalization only — no filesystem access. At spec-build time
    these paths may not exist yet (tests never create them), so anything that
    touches the real tree (resolving symlinks, checking existence) is out of
    scope here; see `_reject_overbroad_mounts` for what that limits."""
    return posixpath.normpath(str(path))

def _is_ancestor(candidate: str, other: str) -> bool:
    c = PurePosixPath(_normalize(candidate))
    o = PurePosixPath(_normalize(other))
    return c == o or c in o.parents

def _reject_ground_truth(mounts) -> None:
    for mount in mounts:
        haystack = f"{_normalize(mount.source)} {_normalize(mount.target)}".lower()
        if any(marker in haystack for marker in GROUND_TRUTH_MARKERS):
            raise ValueError(f"refusing to mount ground truth into an agent container: "
                             f"{mount.source}")

def _reject_docker_socket(mounts) -> None:
    """Reject the socket by name *and* by containment.

    A substring check on "docker.sock" alone only sees the socket when the
    mount names it: `Mount("/var/run", "/var/run", False)` mounts the very
    same socket through its parent directory and the substring never appears.
    That is the identical parent-directory trick `_reject_overbroad_mounts`
    already had to close for this spec's own paths, so the ancestor test is
    applied here too, against the well-known socket locations.
    """
    for mount in mounts:
        for value in (mount.source, mount.target):
            normalized = _normalize(value)
            if "docker.sock" in normalized or any(
                    _is_ancestor(normalized, sock) for sock in DOCKER_SOCKETS):
                raise ValueError(
                    f"refusing to mount the docker socket into an agent container "
                    f"(this is a full escape from the container boundary): {value}")


def _reject_writable_remount(mounts, read_only_paths) -> None:
    """Reject any mount that would hand the container a writable view of a
    path this spec deliberately mounts read-only.

    "Canonical repository is mounted read-only. The mount is the enforcement."
    — so a second mount of the same source without `readonly` deletes the
    enforcement while the read-only mount is still there to look at. The
    ancestor guard cannot catch it: it skips when source *equals* a protected
    path (it has to, or the spec's own canonical mount would reject itself),
    which makes an exact re-mount the one case never checked, and it never
    consults `read_only` at all.

    Equality is the case the review found; descendants are covered by the same
    argument (nothing beneath a read-only tree may be writable) and cost
    nothing extra, since this spec never mounts anything under those paths
    writable itself.
    """
    for mount in mounts:
        for protected in read_only_paths:
            if _is_ancestor(protected, mount.source) and not mount.read_only:
                raise ValueError(
                    f"refusing a writable mount of {mount.source!r}: this spec mounts "
                    f"{protected!r} read-only and the read-only mount IS the "
                    f"enforcement — a writable second mount of the same source would "
                    f"silently undo it")


def _require_disjoint_spec_paths(**named_paths) -> None:
    """The spec's own configured paths must not nest inside one another.

    This is a documented precondition on the factories, not a check on the
    caller's extra_mounts, and it is stated separately so the error names the
    real problem. Previously a host_hermes_home *inside* run_dir made
    engineer_spec unconstructable with "refusing overly broad mount", blaming
    the caller for two mandatory mounts the factory itself built.

    It is stated as a precondition rather than waived because waiving it —
    exempting the spec's own mounts from each other — would also accept
    run_dir="/w" with canonical_repo="/w/repos/anna": mounting the whole
    workspace writable, exposing every sibling (including any ground-truth
    directory) and making the canonical repository writable through the run
    mount. That is precisely what `_reject_overbroad_mounts` exists to stop.
    Supporting a per-trial hermes home under the run dir needs the mount set
    reasoned about as a set (which mount wins, in which order); that belongs
    to a later plan. Until then: give the trial a hermes home outside the run
    directory.
    """
    for (name_a, path_a), (name_b, path_b) in itertools.permutations(named_paths.items(), 2):
        if _normalize(path_a) != _normalize(path_b) and _is_ancestor(path_a, path_b):
            raise ValueError(
                f"this spec's own paths must be disjoint, but {name_a}={path_a!r} is an "
                f"ancestor of {name_b}={path_b!r}: mounting one would also expose the "
                f"other, and the two mounts' read-only flags would contradict each "
                f"other. Place {name_b} outside {name_a}.")

def _reject_overbroad_mounts(mounts, protected_paths) -> None:
    """Reject any mount whose source is a lexical ancestor of one of this
    spec's other configured paths (run_dir, canonical_repo, bundle_path,
    host_hermes_home, ...).

    This is a partial mitigation, not a general solution. It catches mounting
    a parent directory (e.g. mounting "/w" when run_dir is "/w/runs/R1")
    which would also expose any sibling directory nearby — including, but not
    limited to, a ground-truth directory that `_reject_ground_truth`'s
    marker-substring check can't see because the mount's own path string
    never contains "ground-truth".

    It does NOT catch an unrelated mount source that happens to contain a
    copy of ground truth somewhere with no ancestor/descendant relationship
    to any path this module already knows about. Closing that fully would
    require either (a) an explicit ground-truth path threaded into
    engineer_spec/challenger_spec so it can be checked directly — no caller
    currently provides one — or (b) resolving mount sources against the real
    filesystem at spec-build time, which introduces TOCTOU risk (the tree can
    change between spec-build and container-start) and breaks when paths
    don't exist yet, as in every test in this suite. Neither is implemented
    here; treat the general case as open.
    """
    for mount in mounts:
        for protected in protected_paths:
            if _normalize(mount.source) != _normalize(protected) and _is_ancestor(mount.source, protected):
                raise ValueError(
                    f"refusing overly broad mount: {mount.source!r} is an ancestor "
                    f"of {protected!r} already used by this spec, and would also "
                    f"expose anything else nearby (including any ground-truth "
                    f"directory) to the container")

def engineer_spec(*, runtime_image_id, run_dir, canonical_repo, host_hermes_home,
                  env_passthrough, extra_mounts=None, command=None) -> ContainerSpec:
    """Precondition: run_dir, canonical_repo and host_hermes_home must be
    mutually disjoint host paths (see `_require_disjoint_spec_paths`)."""
    _require_disjoint_spec_paths(run_dir=str(run_dir), canonical_repo=str(canonical_repo),
                                 host_hermes_home=str(host_hermes_home))
    mounts = [
        Mount(str(canonical_repo), "/work/canonical", True),
        Mount(str(run_dir), "/work/run", False),
        Mount(str(host_hermes_home), "/opt/data", False),
        *(extra_mounts or []),
    ]
    _reject_ground_truth(mounts)
    _reject_docker_socket(mounts)
    _reject_writable_remount(mounts, [str(canonical_repo)])
    _reject_overbroad_mounts(mounts, [str(run_dir), str(canonical_repo), str(host_hermes_home)])
    return ContainerSpec(image=runtime_image_id, mounts=tuple(mounts),
                         env_passthrough=tuple(env_passthrough),
                         host_hermes_home=str(host_hermes_home),
                         network="bridge", command=tuple(command or []))

def challenger_spec(*, runtime_image_id, run_dir, bundle_path, host_hermes_home,
                    arm, env_passthrough, command=None) -> ContainerSpec:
    if arm not in VALID_ARMS:
        raise ValueError(f"unknown arm {arm!r}; expected one of {VALID_ARMS}")
    for name in env_passthrough:
        if name.startswith(("AWS_", "AZURE_", "ARM_")):
            raise ValueError(
                f"challenger must hold no cloud credentials; got {name}. "
                "The evidence collector holds the observer credential.")
    verdict_dir = str(PurePosixPath(str(run_dir)) / "verdict")
    _require_disjoint_spec_paths(bundle_path=str(bundle_path), verdict_dir=verdict_dir,
                                 host_hermes_home=str(host_hermes_home))
    mounts = [
        Mount(str(bundle_path), "/work/bundle", True),
        Mount(verdict_dir, "/work/out", False),
        Mount(str(host_hermes_home), "/opt/data", False),
    ]
    _reject_ground_truth(mounts)
    _reject_docker_socket(mounts)
    _reject_writable_remount(mounts, [str(bundle_path)])
    _reject_overbroad_mounts(mounts, [str(bundle_path), verdict_dir, str(host_hermes_home)])
    return ContainerSpec(image=runtime_image_id, mounts=tuple(mounts),
                         env_passthrough=tuple(env_passthrough),
                         host_hermes_home=str(host_hermes_home),
                         network="none", command=tuple(command or []), arm=arm)
