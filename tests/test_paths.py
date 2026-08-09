import pytest
from elcapitan.paths import safe_resolve, PathEscape

def test_accepts_a_contained_relative_path(tmp_path):
    (tmp_path / "evidence").mkdir(); (tmp_path / "evidence" / "a.bin").write_bytes(b"x")
    assert safe_resolve(tmp_path, "evidence/a.bin").is_file()

def test_rejects_parent_traversal(tmp_path):
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "../outside")

def test_rejects_absolute_path(tmp_path):
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "/etc/passwd")

def test_rejects_symlinked_file(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "link").symlink_to("/etc/passwd")
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "evidence/link")

def test_rejects_symlinked_parent_directory(tmp_path):
    outside = tmp_path.parent / "outside"; outside.mkdir(exist_ok=True)
    (tmp_path / "evidence").symlink_to(outside, target_is_directory=True)
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "evidence/anything")

def test_rejects_embedded_traversal_that_still_lands_inside(tmp_path):
    # Normalises back inside, but the intent is suspicious: reject on '..' outright.
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "evidence/../evidence/a.bin")
