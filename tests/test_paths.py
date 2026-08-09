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

# --- The two guards must be independently pinned ---------------------------
#
# safe_resolve has two guards: the per-component is_symlink() loop and the
# final is_relative_to(root) check. Every symlink test above points *outside*
# the root, so is_relative_to catches those cases on its own — deleting the
# symlink loop left the whole suite green, and deleting is_relative_to left it
# green too (the other cases are caught by the '..'/absolute check or the
# symlink loop). The two tests below each fail if their own guard is removed.
# This function is the primitive every containment claim in the repo delegates
# to, so neither guard may be deletable in silence.

def test_rejects_a_symlink_that_points_back_inside_the_root(tmp_path):
    # Kills the "delete the is_symlink loop" mutant specifically:
    # resolve() lands on tmp_path/evidence/a.bin, which IS relative_to(root),
    # so guard 2 has nothing to say. Only the symlink loop rejects this.
    # It must still be rejected: evidence is addressed by the path the agent
    # wrote, and a link means the bytes hashed are not the bytes at that name.
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "a.bin").write_bytes(b"x")
    (tmp_path / "evidence" / "link").symlink_to(tmp_path / "evidence" / "a.bin")
    with pytest.raises(PathEscape, match="symlink"):
        safe_resolve(tmp_path, "evidence/link")

def test_containment_check_still_rejects_an_escape_when_the_symlink_loop_misses_it(
        tmp_path, monkeypatch):
    # Kills the "delete is_relative_to" mutant specifically. is_symlink() is a
    # separate syscall from resolve(), so a link created between the two (or
    # one lstat does not observe) is a real TOCTOU window; this forces that
    # window open by making is_symlink report False, and asserts the escape is
    # still caught. Defence in depth is the claim — so it has to be tested as
    # depth, with the outer layer disabled.
    from pathlib import Path as _Path
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "link").symlink_to("/etc/passwd")
    monkeypatch.setattr(_Path, "is_symlink", lambda self: False)
    with pytest.raises(PathEscape, match="escapes run directory"):
        safe_resolve(tmp_path, "evidence/link")

def test_missing_root_is_a_path_escape_not_a_file_not_found(tmp_path):
    # Uniform error contract: callers in validate.py catch PathEscape to turn
    # containment failures into structured failure strings. A root that does
    # not exist used to escape as FileNotFoundError and crash them.
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path / "does-not-exist", "evidence/a.bin")
