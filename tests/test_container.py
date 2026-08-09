import pytest
from elcapitan.container import Mount, engineer_spec, challenger_spec

IMAGE = "sha256:" + "e" * 64
NAMES = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY"]

def eng(tmp="/tmp/h1", **kw):
    return engineer_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                         canonical_repo="/w/repos/anna", host_hermes_home=tmp,
                         env_passthrough=NAMES, **kw)

def test_secret_values_never_appear_in_argv():
    argv = " ".join(eng().to_argv())
    assert "AWS_SECRET_ACCESS_KEY" in argv          # the name is fine
    assert "=" not in argv.split("AWS_SECRET_ACCESS_KEY")[1][:1]  # no '=value'

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

def test_image_referenced_by_built_image_id():
    assert eng().to_argv()[-1] == IMAGE or IMAGE in eng().to_argv()

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

def test_ground_truth_mount_is_rejected():
    with pytest.raises(ValueError, match="ground truth"):
        eng(extra_mounts=[Mount("/w/ground-truth", "/gt", True)])

def test_hardening_flags_present():
    argv = eng().to_argv()
    for flag in ("--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--pids-limit", "--memory", "--cpus"):
        assert any(a.startswith(flag) for a in argv), f"missing {flag}"

# --- challenger ---

def ch(arm="A"):
    return challenger_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a",
                           host_hermes_home="/tmp/h2", arm=arm,
                           env_passthrough=["ANTHROPIC_API_KEY"])

def test_challenger_holds_no_cloud_credentials():
    assert all(not n.startswith("AWS_") and not n.startswith("AZURE_")
               for n in ch().env_passthrough)

def test_challenger_network_is_disabled():
    assert ch().network == "none"

def test_challenger_bundle_is_read_only():
    assert next(m for m in ch().mounts if m.target.endswith("/bundle")).read_only

def test_challenger_cannot_see_the_canonical_repo():
    assert all("canonical" not in m.target for m in ch().mounts)

def test_unknown_arm_rejected():
    with pytest.raises(ValueError, match="arm"):
        ch(arm="C")
