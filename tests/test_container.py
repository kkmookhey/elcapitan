import pytest
from elcapitan.container import Mount, engineer_spec, challenger_spec

IMAGE = "sha256:" + "e" * 64
NAMES = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY"]

def eng(tmp="/tmp/h1", **kw):
    return engineer_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                         canonical_repo="/w/repos/anna", host_hermes_home=tmp,
                         env_passthrough=NAMES, **kw)

def ch(arm="A"):
    return challenger_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a",
                           host_hermes_home="/tmp/h2", arm=arm,
                           env_passthrough=["ANTHROPIC_API_KEY"])

def ch_with(env_passthrough, arm="A"):
    return challenger_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a",
                           host_hermes_home="/tmp/h2", arm=arm,
                           env_passthrough=env_passthrough)

# --- secrets never enter argv (finding 2: strengthened) ---

def test_secret_values_never_appear_in_argv():
    argv = " ".join(eng().to_argv())
    assert "AWS_SECRET_ACCESS_KEY" in argv          # the name is fine
    assert "=" not in argv.split("AWS_SECRET_ACCESS_KEY")[1][:1]  # no '=value'

def test_no_secret_value_or_extra_token_ever_follows_an_env_name(monkeypatch):
    # A structural check, not a string search: whatever actually sits in the
    # environment must never leak into argv, AND nothing may ever appear
    # between an --env NAME pair and the next --env/--mount/image token. This
    # is what catches a mutation like `argv += ["--env", name, some_value]` —
    # a value-search alone can miss it if the leaked string doesn't match
    # whatever sentinel the test happens to look for.
    secret = "s3kr1t-should-never-appear-in-argv-9f3a"
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    spec = eng()
    argv = spec.to_argv()
    assert secret not in " ".join(argv)
    for i, tok in enumerate(argv):
        if tok == "--env":
            name = argv[i + 1]
            assert name in NAMES
            trailing = argv[i + 2] if i + 2 < len(argv) else None
            assert (trailing is None or trailing == "--env"
                    or trailing.startswith("--mount") or trailing == spec.image)

def test_env_flags_are_name_only():
    argv = eng().to_argv()
    idx = argv.index("--env")
    assert argv[idx + 1] in NAMES

def test_spec_stores_no_secret_values():
    spec = eng()
    assert not hasattr(spec, "env_values")
    assert all(isinstance(n, str) for n in spec.env_passthrough)

def test_host_hermes_home_is_distinct_per_container():
    assert eng("/tmp/h1").host_hermes_home != eng("/tmp/h2").host_hermes_home

def test_container_mountpoint_for_hermes_home_is_always_opt_data():
    assert any(m.target == "/opt/data" for m in eng().mounts)

# finding 4: assert the mount SOURCE, not just that some /opt/data target exists
def test_hermes_home_mount_source_matches_host_hermes_home():
    spec = eng()
    mount = next(m for m in spec.mounts if m.target == "/opt/data")
    assert mount.source == spec.host_hermes_home

def test_challenger_hermes_home_mount_source_matches_host_hermes_home():
    spec = ch()
    mount = next(m for m in spec.mounts if m.target == "/opt/data")
    assert mount.source == spec.host_hermes_home

def test_image_referenced_by_built_image_id():
    assert eng().to_argv()[-1] == IMAGE or IMAGE in eng().to_argv()

# finding 6: position, not just membership — exercised with a non-empty command
def test_image_position_precedes_command_and_follows_all_flags():
    spec = eng(command=["python3", "run.py"])
    argv = spec.to_argv()
    img_idx = argv.index(spec.image)
    assert argv[img_idx:] == [spec.image, "python3", "run.py"]
    assert all(not tok.startswith("--") for tok in argv[img_idx:])
    assert any(tok.startswith("--") for tok in argv[:img_idx])

def test_no_user_flag_is_passed():
    # s6-overlay is PID 1 and drops to the hermes user itself; forcing --user
    # can bypass init. See spike findings Q5.
    assert "--user" not in eng().to_argv()

def test_canonical_repo_is_read_only():
    assert next(m for m in eng().mounts if m.target.endswith("/canonical")).read_only

def test_run_dir_is_writable():
    assert not next(m for m in eng().mounts if m.target.endswith("/run")).read_only

def test_container_is_removed_on_exit():
    assert "--rm" in eng().to_argv()

def test_no_docker_socket_mounted():
    assert all("docker.sock" not in m.source for m in eng().mounts)

# finding 8: active rejection, not just "the default construction happens not to have one"
def test_docker_socket_extra_mount_is_rejected():
    with pytest.raises(ValueError, match="docker socket"):
        eng(extra_mounts=[Mount("/var/run/docker.sock", "/var/run/docker.sock", False)])

def test_ground_truth_mount_is_rejected():
    with pytest.raises(ValueError, match="ground truth"):
        eng(extra_mounts=[Mount("/w/ground-truth", "/gt", True)])

# the same parent-directory trick applied to the socket itself: no path string
# here contains "docker.sock", but /var/run holds it
def test_parent_directory_of_the_docker_socket_is_rejected():
    with pytest.raises(ValueError, match="docker socket"):
        eng(extra_mounts=[Mount("/var/run", "/var/run", False)])

def test_alternate_docker_socket_location_parent_is_rejected():
    with pytest.raises(ValueError, match="docker socket"):
        eng(extra_mounts=[Mount("/run", "/host-run", False)])

def test_root_mount_is_rejected_because_it_contains_the_socket():
    with pytest.raises(ValueError, match="docker socket"):
        eng(extra_mounts=[Mount("/", "/host", True)])

# finding 9: substring matching alone can't catch a parent-directory mount
def test_ancestor_of_run_dir_mount_is_rejected():
    with pytest.raises(ValueError, match="ancestor"):
        eng(extra_mounts=[Mount("/w", "/work/all", False)])

# "Canonical repository is mounted read-only. The mount is the enforcement."
# An exact re-mount is the one case the ancestor guard never checks: it skips
# when source == protected (it must, or the spec's own mounts reject each
# other), and it never consults read_only at all.
def test_writable_remount_of_the_canonical_repo_is_rejected():
    with pytest.raises(ValueError, match="read-only"):
        eng(extra_mounts=[Mount("/w/repos/anna", "/work/rw", False)])

def test_writable_remount_of_a_path_inside_the_canonical_repo_is_rejected():
    with pytest.raises(ValueError, match="read-only"):
        eng(extra_mounts=[Mount("/w/repos/anna/modules", "/work/rw", False)])

def test_a_second_read_only_mount_of_the_canonical_repo_is_allowed():
    # The objection is to writability, not to the second mount as such.
    spec = eng(extra_mounts=[Mount("/w/repos/anna", "/work/canonical2", True)])
    assert all(m.read_only for m in spec.mounts if m.source == "/w/repos/anna")

def test_writable_remount_of_the_challenger_bundle_is_rejected():
    with pytest.raises(ValueError, match="read-only"):
        challenger_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                        bundle_path="/w/runs/R1/verdict", host_hermes_home="/tmp/h2",
                        arm="A", env_passthrough=[])

# The spec's own paths are a documented precondition, and the error must name
# it rather than blaming the caller's extra_mounts for the factory's own mounts.
def test_hermes_home_nested_under_the_run_dir_names_the_precondition():
    with pytest.raises(ValueError, match="own paths must be disjoint"):
        engineer_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                      canonical_repo="/w/repos/anna",
                      host_hermes_home="/w/runs/R1/hermes", env_passthrough=NAMES)

def test_run_dir_containing_the_canonical_repo_names_the_precondition():
    with pytest.raises(ValueError, match="own paths must be disjoint"):
        engineer_spec(runtime_image_id=IMAGE, run_dir="/w",
                      canonical_repo="/w/repos/anna", host_hermes_home="/tmp/h1",
                      env_passthrough=NAMES)

def test_hardening_flags_present():
    argv = eng().to_argv()
    for flag in ("--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--pids-limit", "--memory", "--cpus"):
        assert any(a.startswith(flag) for a in argv), f"missing {flag}"

def test_hardening_tuple_grants_only_setuid_and_setgid():
    """Pins the exact HARDENING tuple (review Finding 5). --cap-drop=ALL by
    itself breaks Hermes's s6-overlay init (see the comment above HARDENING
    in container.py for the reproduction); SETUID/SETGID is the minimum
    that was confirmed to fix it on macOS/Docker Desktop, and that minimum
    must not silently drift wider. Both of these must fail this test:
    HARDENING = ("--cap-drop=ALL", ...)                                   # cap-adds removed -> s6-applyuidgid fails again
    HARDENING = ("--cap-drop=ALL", "--cap-add=ALL", "--privileged", ...)  # hardening gutted
    """
    from elcapitan.container import HARDENING
    assert HARDENING == ("--cap-drop=ALL", "--cap-add=SETUID", "--cap-add=SETGID",
                         "--security-opt=no-new-privileges",
                         "--pids-limit=512", "--memory=4g", "--cpus=2")
    argv = eng().to_argv()
    assert "--privileged" not in argv
    assert "--cap-add=ALL" not in argv

# finding 7: Mount must not accept characters that let a path inject mount options
def test_mount_rejects_comma_in_source_or_target():
    with pytest.raises(ValueError):
        Mount("/data,readonly=false", "/work/x", False)
    with pytest.raises(ValueError):
        Mount("/data", "/work/run,readonly", False)

def test_mount_rejects_equals_in_source_or_target():
    with pytest.raises(ValueError):
        Mount("/data=x", "/work/x", False)
    with pytest.raises(ValueError):
        Mount("/data", "/work/x=y", False)

def test_readonly_mount_flag_ends_with_readonly_suffix():
    assert Mount("/a", "/b", True).to_flag().endswith(",readonly")

def test_writable_mount_flag_has_no_readonly_suffix():
    assert not Mount("/a", "/b", False).to_flag().endswith(",readonly")

# finding 10: frozen dataclass with list fields is not really immutable
def test_mounts_and_env_passthrough_are_immutable_tuples():
    spec = eng()
    assert isinstance(spec.mounts, tuple)
    assert isinstance(spec.env_passthrough, tuple)
    with pytest.raises(AttributeError):
        spec.mounts.append(Mount("/var/run/docker.sock", "/x", False))
    with pytest.raises(AttributeError):
        spec.env_passthrough.append("AWS_SECRET_ACCESS_KEY")

# --- challenger ---

def test_challenger_holds_no_cloud_credentials():
    assert all(not n.startswith("AWS_") and not n.startswith("AZURE_")
               for n in ch().env_passthrough)

# finding 1: the credential guard must actually be exercised, not just
# asserted over the test's own unmodified input
def test_challenger_rejects_aws_credential_names():
    with pytest.raises(ValueError, match="cloud credentials"):
        ch_with(["AWS_ACCESS_KEY_ID"])

def test_challenger_rejects_azure_credential_names():
    with pytest.raises(ValueError, match="cloud credentials"):
        ch_with(["AZURE_CLIENT_SECRET"])

def test_challenger_rejects_arm_credential_names():
    with pytest.raises(ValueError, match="cloud credentials"):
        ch_with(["ARM_CLIENT_SECRET"])

def test_challenger_is_not_on_a_general_network():
    # This asserted network == "none" until 2026-08-24, when the first live
    # run measured that "none" cannot work: the challenger is a model-backed
    # agent and needs api.anthropic.com. The property being protected was
    # never "no network" — it was "cannot fetch evidence" — so the assertion
    # now names what actually protects it. What must NOT come back is the
    # engineer's general bridge.
    from elcapitan.egress import NETWORK_NAME

    assert ch().network == NETWORK_NAME
    assert ch().network not in ("bridge", "host", "")

# finding 3: docker reads argv, not the dataclass field
def test_challenger_network_is_in_argv():
    from elcapitan.egress import NETWORK_NAME

    assert f"--network={NETWORK_NAME}" in ch().to_argv()

def test_challenger_bundle_is_read_only():
    assert next(m for m in ch().mounts if m.target.endswith("/bundle")).read_only

# finding 5: check source too, and pin down the exact mount set
def test_challenger_cannot_see_the_canonical_repo():
    spec = ch()
    assert all("canonical" not in m.target and "canonical" not in m.source
               for m in spec.mounts)
    assert {m.target for m in spec.mounts} == {"/work/bundle", "/work/out", "/opt/data"}

def test_unknown_arm_rejected():
    with pytest.raises(ValueError, match="arm"):
        ch(arm="C")

# finding 11: arm must be recorded, not validated and discarded
def test_challenger_spec_records_its_arm():
    assert ch("A").arm == "A"
    assert ch("B").arm == "B"

def test_engineer_spec_has_no_arm():
    # By design the engineer container is identical across both arms — the
    # arm difference lives entirely in which bundle the challenger receives.
    assert eng().arm is None


def test_the_engineer_may_hold_an_azure_scanner_credential():
    # The asymmetry is the design, and it is easy to "tidy away": the
    # CHALLENGER holds no cloud credential and runs --network=none, while the
    # ENGINEER holds the scoped read-only scanner credential because it is the
    # side that reads the cloud. Copying the challenger's guard into
    # engineer_spec would break every Eiger trial at once.
    names = ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
             "ANTHROPIC_API_KEY"]
    spec = engineer_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                         canonical_repo="/w/repos/eiger", host_hermes_home="/tmp/h1",
                         env_passthrough=names)
    assert set(names) <= set(spec.env_passthrough)


def test_the_engineer_may_hold_an_arm_credential():
    spec = engineer_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                         canonical_repo="/w/repos/eiger", host_hermes_home="/tmp/h1",
                         env_passthrough=["ARM_CLIENT_ID", "ARM_SUBSCRIPTION_ID"])
    assert "ARM_CLIENT_ID" in spec.env_passthrough


# --- the challenger's network is an allowlist, not an absence ---------------

def test_the_challenger_runs_on_the_internal_egress_network():
    # It used to be network="none", which cannot work: the challenger is a
    # model-backed agent and must reach api.anthropic.com. MEASURED — with no
    # network it exits 0 having produced no verdict. The property that
    # mattered was never "no network", it was "cannot fetch evidence", and
    # that is now an internal network plus a one-host allowlist.
    from elcapitan.egress import NETWORK_NAME

    spec = challenger_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a",
                           host_hermes_home="/tmp/h2", arm="A",
                           env_passthrough=["ANTHROPIC_API_KEY"])
    assert spec.network == NETWORK_NAME
    assert "--network=" + NETWORK_NAME in spec.to_argv()


def test_the_engineer_is_untouched_by_the_egress_change():
    # The engineer needs a general network — it reads the cloud. Quietly
    # moving it onto the challenger's allowlist would break every trial.
    assert eng().network == "bridge"


def test_the_challenger_still_refuses_a_cloud_credential_on_the_new_network():
    # The network changed; the credential rule did not. This is the guard that
    # actually keeps the arms apart.
    with pytest.raises(ValueError, match="cloud credentials"):
        ch_with(["AZURE_CLIENT_ID"])
