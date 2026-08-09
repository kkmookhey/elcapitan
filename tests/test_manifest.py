import pytest
from elcapitan.manifest import build_manifest, bundle_hash
from elcapitan.paths import PathEscape

BASE = dict(repository_commit="c"*40, runtime_image_id="sha256:"+"d"*64,
            runtime_lock_sha256="e"*64, profile_config_sha256="f"*64,
            environment_adapter_sha256="0"*64)

def write(tmp_path, name, data):
    p = tmp_path / name; p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data); return name

def test_manifest_lists_path_size_and_hash(tmp_path):
    write(tmp_path, "inputs/finding.json", b'{"a":1}')
    m = build_manifest(tmp_path, files=["inputs/finding.json"], **BASE)
    entry = m["files"][0]
    assert entry["path"] == "inputs/finding.json"
    assert entry["size"] == 7 and len(entry["sha256"]) == 64

def test_boundary_ambiguity_is_resolved(tmp_path):
    # Concatenation would make these two file sets identical.
    a = tmp_path / "a"; a.mkdir()
    write(a, "inputs/x", b"AB"); write(a, "inputs/y", b"C")
    b = tmp_path / "b"; b.mkdir()
    write(b, "inputs/x", b"A"); write(b, "inputs/y", b"BC")
    ma = build_manifest(a, files=["inputs/x", "inputs/y"], **BASE)
    mb = build_manifest(b, files=["inputs/x", "inputs/y"], **BASE)
    assert bundle_hash(ma) != bundle_hash(mb)

def test_hash_changes_when_the_commit_changes(tmp_path):
    write(tmp_path, "inputs/f", b"x")
    m1 = build_manifest(tmp_path, files=["inputs/f"], **BASE)
    m2 = build_manifest(tmp_path, files=["inputs/f"], **{**BASE, "repository_commit": "a"*40})
    assert bundle_hash(m1) != bundle_hash(m2)

def test_hash_changes_when_the_image_changes(tmp_path):
    write(tmp_path, "inputs/f", b"x")
    m1 = build_manifest(tmp_path, files=["inputs/f"], **BASE)
    m2 = build_manifest(tmp_path, files=["inputs/f"],
                        **{**BASE, "runtime_image_id": "sha256:" + "9"*64})
    assert bundle_hash(m1) != bundle_hash(m2)

def test_file_order_does_not_affect_the_hash(tmp_path):
    write(tmp_path, "inputs/x", b"1"); write(tmp_path, "inputs/y", b"2")
    m1 = build_manifest(tmp_path, files=["inputs/x", "inputs/y"], **BASE)
    m2 = build_manifest(tmp_path, files=["inputs/y", "inputs/x"], **BASE)
    assert bundle_hash(m1) == bundle_hash(m2)

def test_prompt_is_a_first_class_input(tmp_path):
    write(tmp_path, "prompt.md", b"do the thing")
    m = build_manifest(tmp_path, files=["prompt.md"], **BASE)
    assert m["files"][0]["path"] == "prompt.md"

def test_rejects_traversal_path(tmp_path):
    write(tmp_path, "inputs/f", b"x")
    with pytest.raises(PathEscape):
        build_manifest(tmp_path, files=["../outside"], **BASE)

def test_rejects_absolute_path(tmp_path):
    write(tmp_path, "inputs/f", b"x")
    with pytest.raises(PathEscape):
        build_manifest(tmp_path, files=["/absolute/path"], **BASE)
