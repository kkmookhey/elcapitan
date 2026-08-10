"""Tests for elcapitan.shim — the only place Hermes is invoked.

The plan's own test helper (docs/superpowers/plans/2026-08-08-probe-substrate-
and-shakedown.md, Task 11) used
`run_dir=canonical_repo=host_hermes_home=str(tmp_path)`, which
`elcapitan.container.engineer_spec` now rejects — mounting one host path
read-only at /work/canonical and writable at /work/run was a real defect
closed in Task 10's review (`_require_disjoint_spec_paths`). Every spec built
here uses three distinct subdirectories.
"""
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from elcapitan.container import engineer_spec
from elcapitan.session import SessionRecord
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


def _write_real_state_db(path: Path) -> None:
    """A minimal but real, single-session state.db — one tool call, a real
    finish_reason='stop', and a session_model_usage row — so tests that
    exercise persistence (Finding 1) have actual commands/usage to persist,
    not just an empty session."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE sessions (id TEXT, started_at REAL)")
    con.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, "
                "role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, "
                "tool_name TEXT, timestamp REAL, finish_reason TEXT)")
    con.execute("CREATE TABLE session_model_usage (session_id TEXT, model TEXT, "
                "input_tokens INTEGER)")
    con.execute("INSERT INTO sessions VALUES ('S1', 1.0)")
    tool_calls = json.dumps([{"id": "c1", "function": {
        "name": "terminal", "arguments": json.dumps({"command": "echo hi"})}}])
    con.execute("INSERT INTO messages VALUES "
               "(1, 'S1', 'assistant', '', NULL, ?, NULL, 1.0, 'tool_calls')",
               (tool_calls,))
    con.execute("INSERT INTO messages VALUES "
               "(2, 'S1', 'tool', ?, 'c1', NULL, 'terminal', 2.0, NULL)",
               (json.dumps({"output": "hi", "exit_code": 0, "error": None}),))
    con.execute("INSERT INTO messages VALUES "
               "(3, 'S1', 'assistant', 'done', NULL, NULL, NULL, 3.0, 'stop')")
    con.execute("INSERT INTO session_model_usage VALUES ('S1', 'claude-sonnet-5', 42)")
    con.commit()
    con.close()


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


# --- succeeded requires BOTH conjuncts (review Finding 2): the three real
# fixture sessions can't prove either conjunct is independently necessary,
# since both failure sessions lack both properties together. Pinned here at
# the shim layer specifically (not just in test_session.py) so a regression
# in shim.py's own use of session_succeeded is caught even if session.py's
# predicate itself is fine. ---

def _run_with_fabricated_session(tmp_path, session, monkeypatch):
    import elcapitan.shim as shim_module
    monkeypatch.setattr(shim_module, "read_session", lambda db_path: session)
    p = tmp_path / "p.md"
    p.write_text("x")
    return run_agent(spec(tmp_path), p, secret_env={}, model=MODEL,
                     stub=lambda a, t, e: (0, ""))


def test_succeeded_false_when_died_mid_loop_after_a_tool_call(tmp_path, monkeypatch):
    died_mid_loop = SessionRecord(session_id="x", finish_reason="tool_calls",
                                  tool_call_count=1, transcript="")
    result = _run_with_fabricated_session(tmp_path, died_mid_loop, monkeypatch)
    assert result.succeeded is False


def test_succeeded_false_when_model_stopped_without_acting(tmp_path, monkeypatch):
    refused_without_acting = SessionRecord(session_id="x", finish_reason="stop",
                                           tool_call_count=0, transcript="")
    result = _run_with_fabricated_session(tmp_path, refused_without_acting, monkeypatch)
    assert result.succeeded is False


# --- state.db and the structured record must survive the caller's own
# cleanup (review Finding 1): bin/agent-run.sh deletes any host_hermes_home
# it seeded itself, on EXIT, on success as much as on failure. Before this
# fix, state.db — this module's own docstring calls it "the real record" —
# was gone the moment a successful run finished, and SessionRecord.commands
# / usage were computed and then discarded (AgentResult had no `commands`
# field and nothing ever wrote usage to disk). ---

def test_state_db_copied_into_run_dir(tmp_path):
    s = spec(tmp_path)
    home = Path(s.host_hermes_home)
    _write_real_state_db(home / "state.db")
    p = tmp_path / "p.md"
    p.write_text("x")
    run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "ok"))
    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    assert (run_dir / "state.db").is_file()
    # A real copy of the actual bytes, not a placeholder.
    con = sqlite3.connect(f"file:{run_dir / 'state.db'}?mode=ro", uri=True)
    row = con.execute("SELECT id FROM sessions").fetchone()
    con.close()
    assert row == ("S1",)


def test_missing_state_db_does_not_raise_on_capture(tmp_path):
    """A stub run (or a real run that never got far enough to write
    anything) has no state.db to copy — that must degrade silently, the
    same way read_session itself does, not raise."""
    s = spec(tmp_path)
    p = tmp_path / "p.md"
    p.write_text("x")
    run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "ok"))
    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    assert not (run_dir / "state.db").exists()


def test_session_json_carries_commands_and_usage(tmp_path):
    """session.json is the structured, non-forgeable record: it is built
    from messages.tool_calls / tool-response content JSON directly, unlike
    transcript.log, which is free text an agent's own tool output could
    contain lines resembling (e.g. output containing the literal text
    "  exit_code: 0")."""
    s = spec(tmp_path)
    home = Path(s.host_hermes_home)
    _write_real_state_db(home / "state.db")
    p = tmp_path / "p.md"
    p.write_text("x")
    result = run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "ok"))

    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    payload = json.loads((run_dir / "session.json").read_text())
    assert payload["session_id"] == "S1"
    assert payload["finish_reason"] == "stop"
    assert payload["usage"] == {"session_id": "S1", "model": "claude-sonnet-5",
                                "input_tokens": 42}
    assert len(payload["commands"]) == 1
    assert payload["commands"][0]["tool"] == "terminal"
    assert payload["commands"][0]["exit_code"] == 0
    assert payload["commands"][0]["argv"] == ["echo hi"]

    # AgentResult itself carries the same structured commands — not just the
    # file on disk — so an in-process caller (not only a downstream reader
    # of run_dir) gets the structured record too.
    assert len(result.commands) == 1
    assert result.commands[0].tool == "terminal"
    assert result.usage["model"] == "claude-sonnet-5"


def test_state_db_survives_host_hermes_home_deletion(tmp_path):
    """The exact scenario Finding 1 was about: bin/agent-run.sh's `trap
    cleanup EXIT` runs `rm -rf "$HOST_HERMES_HOME"` after a successful run
    as much as a failed one. This simulates that ordering directly: delete
    host_hermes_home immediately after run_agent returns, and prove the
    run_dir's copies are unaffected because run_agent captured them before
    returning — not relying on the caller to do it, and not relying on
    cleanup happening to run late."""
    s = spec(tmp_path)
    home = Path(s.host_hermes_home)
    _write_real_state_db(home / "state.db")
    p = tmp_path / "p.md"
    p.write_text("x")
    result = run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "ok"))
    assert result.succeeded is True

    shutil.rmtree(home)  # simulates agent-run.sh's cleanup trap

    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    assert (run_dir / "state.db").is_file()
    assert (run_dir / "session.json").is_file()
    assert json.loads((run_dir / "session.json").read_text())["session_id"] == "S1"


# --- three distinct paths: the trap this task's brief calls out explicitly ---

def test_spec_requires_three_distinct_paths(tmp_path):
    with pytest.raises(ValueError):
        engineer_spec(runtime_image_id=IMAGE, run_dir=str(tmp_path),
                      canonical_repo=str(tmp_path), host_hermes_home=str(tmp_path),
                      env_passthrough=[])
