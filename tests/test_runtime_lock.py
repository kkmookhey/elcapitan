import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "runtime.lock.json"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
BARE = re.compile(r"^[0-9a-f]{64}$")

def test_required_keys_present():
    lock = json.loads(LOCK.read_text())
    for key in ("base_image_ref", "base_image_digest", "runtime_image_ref",
                "runtime_image_id", "dockerfile_sha256", "uv_lock_sha256",
                "tool_versions"):
        assert key in lock, f"missing {key}"

def test_base_and_runtime_identities_are_distinct():
    lock = json.loads(LOCK.read_text())
    assert lock["base_image_ref"] != lock["runtime_image_ref"], \
        "derived image must have its own repository identity"
    assert lock["base_image_digest"] != lock["runtime_image_id"], \
        "a digest from the base image cannot identify the derived image"

def test_both_image_identities_are_sha256():
    lock = json.loads(LOCK.read_text())
    assert SHA256.match(lock["base_image_digest"])
    assert SHA256.match(lock["runtime_image_id"])

def test_dockerfile_hash_matches_the_file_on_disk():
    import hashlib
    lock = json.loads(LOCK.read_text())
    actual = hashlib.sha256((ROOT / "docker" / "Dockerfile").read_bytes()).hexdigest()
    assert lock["dockerfile_sha256"] == actual, "Dockerfile changed without re-pinning"

def test_uv_lock_exists_and_hash_matches():
    import hashlib
    lock = json.loads(LOCK.read_text())
    uv_lock = ROOT / "uv.lock"
    assert uv_lock.is_file(), "a real resolver lock is required; a pyproject hash is not a lock"
    assert lock["uv_lock_sha256"] == hashlib.sha256(uv_lock.read_bytes()).hexdigest()

def test_dockerfile_contains_no_unresolved_placeholders():
    text = (ROOT / "docker" / "Dockerfile").read_text()
    assert "<" not in text and ">" not in text, "Dockerfile still contains template placeholders"

def test_dockerfile_pins_every_tool_it_installs():
    lock = json.loads(LOCK.read_text())
    text = (ROOT / "docker" / "Dockerfile").read_text()
    assert lock["tool_versions"], "at least one tool must be pinned"
    for tool, version in lock["tool_versions"].items():
        assert version[0].isdigit(), f"{tool} version {version!r} must be exact"
        assert version in text, f"{tool}=={version} must appear in the Dockerfile"

def test_no_floating_specifiers_anywhere():
    for token in (">=", "<=", "^", "~", ":latest", ":main"):
        assert token not in LOCK.read_text(), f"floating specifier {token!r}"


def test_the_egress_proxy_is_pinned_and_its_files_match_disk():
    """The challenger's boundary is part of the experiment's identity.

    An unpinned proxy means a batch could run behind a different allowlist
    than the one recorded, and nothing afterwards could tell. The config and
    filter are hashed separately from the Dockerfile because either can widen
    the boundary without the Dockerfile changing at all.
    """
    import hashlib

    lock = json.loads(LOCK.read_text())
    egress = lock["egress_proxy"]
    assert SHA256.match(egress["image_id"])
    assert egress["allowed_hosts"] == ["api.anthropic.com"]
    ctx = ROOT / "docker" / "egress-proxy"
    for key, name in (("dockerfile_sha256", "Dockerfile"),
                      ("config_sha256", "tinyproxy.conf"),
                      ("filter_sha256", "filter")):
        actual = hashlib.sha256((ctx / name).read_bytes()).hexdigest()
        assert egress[key] == actual, f"{name} changed without re-pinning"
