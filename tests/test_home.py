import pytest
from pathlib import Path
from elcapitan.home import seed_hermes_home, BASELINE_FILES

def test_seeds_all_required_baseline_files(tmp_path):
    home = seed_hermes_home(tmp_path / "h1", model="m", provider="p")
    for name in BASELINE_FILES:
        assert (home / name).is_file(), f"{name} missing — Hermes will not start"

def test_env_contains_no_secret_values(tmp_path):
    home = seed_hermes_home(tmp_path / "h1", model="m", provider="p")
    text = (home / ".env").read_text()
    for marker in ("AKIA", "sk-", "PRIVATE KEY", "SECRET_ACCESS_KEY="):
        assert marker not in text, f"baseline .env must not carry secrets ({marker})"

def test_two_seeds_are_independent_directories(tmp_path):
    a = seed_hermes_home(tmp_path / "a", model="m", provider="p")
    b = seed_hermes_home(tmp_path / "b", model="m", provider="p")
    assert a != b
    (a / "skills").mkdir(exist_ok=True)
    (a / "skills" / "learned.md").write_text("x")
    assert not (b / "skills" / "learned.md").exists(), \
        "self-authored skills must not carry between trials"

def test_model_and_provider_are_written_into_config(tmp_path):
    home = seed_hermes_home(tmp_path / "h1", model="claude-opus-5", provider="anthropic")
    config = (home / "config.yaml").read_text()
    assert "claude-opus-5" in config and "anthropic" in config

def test_refuses_to_overwrite_an_existing_home(tmp_path):
    seed_hermes_home(tmp_path / "h1", model="m", provider="p")
    with pytest.raises(FileExistsError):
        seed_hermes_home(tmp_path / "h1", model="m", provider="p")
