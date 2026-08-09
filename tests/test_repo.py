import subprocess
import pytest
from elcapitan.repo import capture_repo_state, assert_unchanged

def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True)

@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"; r.mkdir()
    git(r, "init", "-q"); git(r, "config", "user.email", "t@t"); git(r, "config", "user.name", "t")
    (r / "main.tf").write_text("resource {}\n")
    git(r, "add", "-A"); git(r, "commit", "-qm", "init")
    return r

def test_clean_repo_reports_no_changes(repo):
    before = capture_repo_state(repo)
    assert assert_unchanged(repo, before) == []

def test_detects_a_tracked_file_edit(repo):
    before = capture_repo_state(repo)
    (repo / "main.tf").write_text("resource { changed = true }\n")
    failures = assert_unchanged(repo, before)
    assert any("main.tf" in f for f in failures)

def test_detects_an_untracked_file(repo):
    before = capture_repo_state(repo)
    (repo / "sneaky.tf").write_text("x\n")
    assert any("sneaky.tf" in f for f in assert_unchanged(repo, before))

def test_detects_a_staged_change(repo):
    before = capture_repo_state(repo)
    (repo / "main.tf").write_text("y\n"); git(repo, "add", "-A")
    assert assert_unchanged(repo, before) != []

def test_detects_a_new_commit(repo):
    before = capture_repo_state(repo)
    (repo / "main.tf").write_text("z\n")
    git(repo, "add", "-A"); git(repo, "commit", "-qm", "sneak")
    assert any("commit" in f.lower() for f in assert_unchanged(repo, before))

def test_tolerates_a_repo_that_was_already_dirty(repo):
    (repo / "preexisting.txt").write_text("was here first\n")
    before = capture_repo_state(repo)
    assert assert_unchanged(repo, before) == []
    (repo / "new.txt").write_text("added during run\n")
    assert any("new.txt" in f for f in assert_unchanged(repo, before))

def test_unborn_branch_raises_a_clear_error(tmp_path):
    r = tmp_path / "empty"; r.mkdir(); git(r, "init", "-q")
    with pytest.raises(ValueError, match="no commits"):
        capture_repo_state(r)

def test_non_git_directory_does_not_claim_unborn_branch(tmp_path):
    r = tmp_path / "notgit"; r.mkdir()
    with pytest.raises(ValueError, match="not a usable git repository"):
        capture_repo_state(r)

def test_nonexistent_path_does_not_claim_unborn_branch(tmp_path):
    r = tmp_path / "does" / "not" / "exist"
    with pytest.raises(ValueError, match="not a usable git repository"):
        capture_repo_state(r)

def test_missing_git_binary_raises_value_error_not_file_not_found(repo, monkeypatch):
    # subprocess.run raises FileNotFoundError when `git` is not on PATH — an
    # exception type no caller of this module expects, and one that escaped
    # the validator's `except ValueError` before this guard. Everything that
    # can go wrong in _git leaves as ValueError.
    def no_git(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "git")

    monkeypatch.setattr("elcapitan.repo.subprocess.run", no_git)
    with pytest.raises(ValueError, match="git could not be executed"):
        capture_repo_state(repo)

def test_dirty_files_is_immutable(repo):
    before = capture_repo_state(repo)
    with pytest.raises(AttributeError):
        before.dirty_files.append("x")
