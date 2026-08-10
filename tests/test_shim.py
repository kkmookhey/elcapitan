"""Tests for elcapitan.shim — the only place Hermes is invoked.

The plan's own test helper (docs/superpowers/plans/2026-08-08-probe-substrate-
and-shakedown.md, Task 11) used
`run_dir=canonical_repo=host_hermes_home=str(tmp_path)`, which
`elcapitan.container.engineer_spec` now rejects — mounting one host path
read-only at /work/canonical and writable at /work/run was a real defect
closed in Task 10's review (`_require_disjoint_spec_paths`). Every spec built
here uses three distinct subdirectories.
"""
from pathlib import Path

import pytest

from elcapitan.container import engineer_spec
from elcapitan.session import EMPTY_SESSION
from elcapitan.shim import MODEL_ENV_MAP, SCANNER_ENV_MAP, resolve_secret_env, run_agent

IMAGE = "sha256:" + "f" * 64
MODEL = "anthropic/claude-sonnet-5"


def spec(tmp_path, **kw):
    run_dir = tmp_path / "run"
    canonical_repo = tmp_path / "canonical"
    hermes_home = tmp_path / "home"
    for d in (run_dir, canonical_repo, hermes_home):
        d.mkdir(parents=True, exist_ok=True)
    return engineer_spec(runtime_image_id=IMAGE, run_dir=str(run_dir),
                         canonical_repo=str(canonical_repo),
                         host_hermes_home=str(hermes_home),
                         env_passthrough=list(SCANNER_ENV_MAP.values()) +
                                        list(MODEL_ENV_MAP.values()), **kw)


# --- resolve_secret_env: name translation, never the double-prefix bug ---

def test_scanner_prefix_is_translated_to_the_aws_name():
    host = {"ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "AKIA_X",
            "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "s",
            "ELCAP_SCANNER_AWS_SESSION_TOKEN": "t"}
    resolved = resolve_secret_env(host, SCANNER_ENV_MAP)
    assert resolved["AWS_ACCESS_KEY_ID"] == "AKIA_X"
    assert resolved["AWS_SECRET_ACCESS_KEY"] == "s"
    assert resolved["AWS_SESSION_TOKEN"] == "t"
    assert not any(k.startswith("ELCAP_") for k in resolved)


def test_model_prefix_is_translated_to_the_anthropic_name():
    resolved = resolve_secret_env({"ELCAP_MODEL_API_KEY": "sk-x"}, MODEL_ENV_MAP)
    assert resolved == {"ANTHROPIC_API_KEY": "sk-x"}


def test_missing_required_secret_raises_by_name():
    with pytest.raises(KeyError, match="ELCAP_SCANNER_AWS_ACCESS_KEY_ID"):
        resolve_secret_env({}, SCANNER_ENV_MAP)


# --- run_agent with a stub: argv, prompt, secrets, artifacts ---

def test_stub_receives_argv_and_prompt(tmp_path):
    p = tmp_path / "p.md"
    p.write_text("do the thing")
    seen = {}

    def stub(argv, text, env):
        seen.update(argv=argv, text=text, env=env)
        return 0, "ok"

    run_agent(spec(tmp_path), p, secret_env={"AWS_ACCESS_KEY_ID": "v"}, model=MODEL, stub=stub)
    assert seen["argv"][0] == "docker"
    assert "do the thing" in seen["text"]


def test_invocation_matches_the_proven_spike_argv(tmp_path):
    """docs/spike-findings.md §2: `chat -q "<prompt>" -t terminal --yolo
    --ignore-user-config -m <model>`. There is no --prompt-file."""
    p = tmp_path / "p.md"
    p.write_text("count files")
    seen = {}
    run_agent(spec(tmp_path), p, secret_env={}, model=MODEL,
             stub=lambda a, t, e: (seen.update(argv=a) or (0, "")))
    argv = seen["argv"]
    assert "--prompt-file" not in argv
    assert argv[argv.index("chat") + 1:argv.index("chat") + 3] == ["-q", "count files"]
    assert "-t" in argv and argv[argv.index("-t") + 1] == "terminal"
    assert "--yolo" in argv
    assert "--ignore-user-config" in argv
    assert "-m" in argv and argv[argv.index("-m") + 1] == MODEL


def test_secret_values_are_not_in_argv(tmp_path):
    p = tmp_path / "p.md"
    p.write_text("x")
    seen = {}
    run_agent(spec(tmp_path), p, secret_env={"AWS_SECRET_ACCESS_KEY": "SUPERSECRET"},
             model=MODEL, stub=lambda a, t, e: (seen.update(argv=a) or (0, "")))
    assert "SUPERSECRET" not in " ".join(seen["argv"])


def test_secret_env_is_passed_to_the_invocation_not_argv(tmp_path):
    p = tmp_path / "p.md"
    p.write_text("x")
    seen = {}
    run_agent(spec(tmp_path), p, secret_env={"AWS_SECRET_ACCESS_KEY": "SUPERSECRET"},
             model=MODEL, stub=lambda a, t, e: (seen.update(env=e) or (0, "")))
    assert seen["env"]["AWS_SECRET_ACCESS_KEY"] == "SUPERSECRET"


def test_stdout_written_to_run_dir(tmp_path):
    s = spec(tmp_path)
    p = tmp_path / "p.md"
    p.write_text("x")
    run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "hello stdout"))
    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    assert (run_dir / "stdout.log").read_text() == "hello stdout"


def test_transcript_written_to_run_dir_when_no_state_db(tmp_path):
    """No state.db exists in this stub scenario, so read_session degrades to
    EMPTY_SESSION rather than raising — transcript.log still gets written,
    just empty, and the result still reports a structured failure."""
    s = spec(tmp_path)
    p = tmp_path / "p.md"
    p.write_text("x")
    result = run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "hello"))
    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    assert (run_dir / "transcript.log").read_text() == ""
    assert result.succeeded is False
    assert result.session_id == ""


def test_nonzero_exit_propagates(tmp_path):
    p = tmp_path / "p.md"
    p.write_text("x")
    result = run_agent(spec(tmp_path), p, secret_env={}, model=MODEL,
                       stub=lambda a, t, e: (3, "boom"))
    assert result.exit_code == 3


def test_missing_prompt_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_agent(spec(tmp_path), tmp_path / "nope.md", secret_env={}, model=MODEL,
                  stub=lambda a, t, e: (0, ""))


# --- exit code 0 must never be the success verdict on its own ---

def test_exit_zero_with_no_session_is_not_success(tmp_path):
    """docs/spike-findings.md §6: a run with no API key exits 0 and still
    writes a sessions row with no assistant reply. Simulated here by a stub
    that exits 0 with no state.db at all — the harder real case (state.db
    present but finish_reason empty) is covered end-to-end in test_session.py
    against the real fixture; this test pins the shim's own predicate."""
    p = tmp_path / "p.md"
    p.write_text("x")
    result = run_agent(spec(tmp_path), p, secret_env={}, model=MODEL,
                       stub=lambda a, t, e: (0, ""))
    assert result.exit_code == 0
    assert result.succeeded is False


def test_succeeded_reflects_a_real_session_not_exit_code(tmp_path, monkeypatch):
    """Point read_session at a fabricated 'good' session via monkeypatch to
    prove succeeded is genuinely derived from the session, not exit_code."""
    import elcapitan.shim as shim_module
    from elcapitan.session import SessionRecord

    good = SessionRecord(session_id="S1", finish_reason="stop", tool_call_count=1,
                         transcript="did the thing", usage={"model": "x"})
    monkeypatch.setattr(shim_module, "read_session", lambda db_path: good)

    p = tmp_path / "p.md"
    p.write_text("x")
    # exit_code 0 here is incidental; the point is succeeded tracks the
    # (monkeypatched) session, and would be True even if exit_code were
    # nonzero, since AgentResult.succeeded is documented as session-derived.
    result = run_agent(spec(tmp_path), p, secret_env={}, model=MODEL,
                       stub=lambda a, t, e: (0, "some stdout"))
    assert result.succeeded is True
    assert result.session_id == "S1"
    assert result.transcript == "did the thing"
    assert result.usage == {"model": "x"}


# --- three distinct paths: the trap this task's brief calls out explicitly ---

def test_spec_requires_three_distinct_paths(tmp_path):
    with pytest.raises(ValueError):
        engineer_spec(runtime_image_id=IMAGE, run_dir=str(tmp_path),
                      canonical_repo=str(tmp_path), host_hermes_home=str(tmp_path),
                      env_passthrough=[])
