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
import os
import shutil
import sqlite3
import time
from pathlib import Path

import pytest

import elcapitan.shim as shim
from elcapitan.container import engineer_spec
from elcapitan.session import SessionRecord
from elcapitan.shim import (
    MODEL_ENV_MAP,
    SCANNER_ENV_MAP,
    _capture_state_db,
    resolve_secret_env,
    run_agent,
)

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


def _write_wal_state_db(path: Path) -> sqlite3.Connection:
    """Same session shape as _write_real_state_db, but in WAL mode with the
    writer connection deliberately kept open and returned (not closed) by
    this helper — reproducing the actual disk shape of a real Hermes
    state.db (re-review Finding 1): WAL mode, never checkpointed.

    Closing this test's own connection here would silently undo the exact
    shape this fixture exists to reproduce — SQLite auto-checkpoints and
    folds the WAL back into the main file when the last connection to a
    WAL-mode database closes cleanly (confirmed directly: with a plain
    `sqlite3.connect(...).close()`, the main file ends up 8192 bytes and
    fully readable on its own, and the bug this fixture is supposed to
    catch cannot reproduce at all — every earlier state.db fixture in this
    suite, including `_write_real_state_db` above, used a connection that
    gets closed, which is exactly why the original F1 bug shipped past the
    first review pass: a rollback-journal-shaped fixture cannot fail on a
    WAL-mode bug).

    Caller must close the returned connection when done with it.
    """
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
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
    return con


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


def test_state_db_capture_reads_wal_data_not_a_checkpoint_husk(tmp_path):
    """Re-review Finding 1: a byte-level copy of just the main .db file
    (the original implementation, `shutil.copy2`) silently archives a
    near-empty husk when the source is WAL-mode and un-checkpointed — which
    real Hermes state.db files are. Confirmed directly against a real run
    in review: main file 4096 bytes / zero tables, while `session.json`
    right next to it correctly said `succeeded: true`. This test uses a
    genuinely WAL-mode fixture with an un-checkpointed, still-open writer
    connection — the shape `_write_real_state_db` (plain sqlite3.connect,
    closed, rollback-journal mode) cannot produce, which is exactly why
    that fixture could not catch this bug the first time.
    """
    s = spec(tmp_path)
    home = Path(s.host_hermes_home)
    writer = _write_wal_state_db(home / "state.db")
    try:
        # Sanity-check the fixture itself: if the WAL sidecar isn't
        # non-trivially sized at this point, this test can't possibly
        # exercise the bug, and would be worse than no test at all.
        wal_path = home / "state.db-wal"
        assert wal_path.is_file() and wal_path.stat().st_size > 0, (
            "fixture is not actually WAL-mode-with-unmerged-data; this "
            "test cannot catch the F1 regression it exists to catch")

        p = tmp_path / "p.md"
        p.write_text("x")
        result = run_agent(s, p, secret_env={}, model=MODEL,
                           stub=lambda a, t, e: (0, "ok"))
        assert result.succeeded is True  # read_session reads the WAL correctly

        run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
        captured = run_dir / "state.db"
        assert captured.is_file()
        con = sqlite3.connect(f"file:{captured}?mode=ro", uri=True)
        try:
            assert con.execute("SELECT id FROM sessions").fetchone() == ("S1",)
            assert con.execute("SELECT count(*) FROM messages").fetchone()[0] == 3
        finally:
            con.close()
        assert result.state_db_captured is True
    finally:
        writer.close()


# --- second re-review: the guard around backup() itself, and the second
# unescaped file: URI it introduced on the capture path ---

def test_malformed_source_state_db_does_not_raise(tmp_path):
    """A state.db that exists but is not a valid SQLite file (truncated,
    corrupted, or simply garbage) must degrade the same way an absent one
    does — NOT raise out of run_agent. Reproduced directly against
    sqlite3.Connection.backup() before writing this test:
    `sqlite3.DatabaseError: file is not a database`, with a 0-byte
    destination file already created by `sqlite3.connect(dest)` before the
    failure. read_session succeeding moments earlier in the same run_agent
    call proves nothing about this source being readable — read_session's
    own contract is to swallow exactly this exception class and return
    EMPTY_SESSION, so its successful return is equally consistent with "the
    database is fine" and "the database is garbage."
    """
    s = spec(tmp_path)
    home = Path(s.host_hermes_home)
    (home / "state.db").write_bytes(
        b"not a sqlite database, just garbage bytes here, long enough to " * 4)
    p = tmp_path / "p.md"
    p.write_text("x")

    result = run_agent(s, p, secret_env={}, model=MODEL,
                       stub=lambda a, t, e: (0, "ok"))  # must not raise

    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    assert (run_dir / "session.json").is_file()  # not lost along with the archive
    assert not (run_dir / "state.db").exists()  # no 0-byte husk left behind
    assert result.state_db_captured is False


def test_run_dir_not_writable_state_db_capture_does_not_raise(tmp_path):
    """Same contract violation as the malformed-source case, different
    trigger: sqlite3.connect(dest) itself raises OperationalError when
    run_dir can't be written to. Reproduced directly:
    `sqlite3.OperationalError: unable to open database file`. Tests
    _capture_state_db directly rather than through run_agent — run_agent
    writes stdout.log/transcript.log into run_dir before ever reaching the
    capture step, so making the whole run_dir read-only would fail earlier
    and not isolate this guard."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    run_dir.chmod(0o500)
    try:
        captured = _capture_state_db(home, run_dir)  # must not raise
    finally:
        run_dir.chmod(0o700)  # restore so pytest can clean up tmp_path
    assert captured is False
    assert not (run_dir / "state.db").exists()


def test_zero_byte_source_state_db_captures_successfully(tmp_path):
    """A zero-byte state.db is a valid empty SQLite database, not a
    malformed one — SQLite treats an empty file as an empty database. This
    must NOT be treated as a capture failure."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (home / "state.db").touch()  # zero bytes

    captured = _capture_state_db(home, run_dir)

    assert captured is True
    assert (run_dir / "state.db").is_file()


def test_wal_source_missing_shm_sidecar_still_captures(tmp_path):
    """The realistic "container was killed" shape: a WAL sidecar with
    unmerged data, but no live -shm (a hard kill can orphan the WAL file
    without a shared-memory index next to it). SQLite recreates the shared-
    memory index as needed when the WAL is present, so this must still
    capture correctly, not degrade."""
    s = spec(tmp_path)
    home = Path(s.host_hermes_home)
    writer = _write_wal_state_db(home / "state.db")
    try:
        shm = home / "state.db-shm"
        assert shm.is_file()
        os.remove(shm)  # simulate the process being killed hard

        p = tmp_path / "p.md"
        p.write_text("x")
        result = run_agent(s, p, secret_env={}, model=MODEL,
                           stub=lambda a, t, e: (0, "ok"))

        assert result.state_db_captured is True
        run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
        con = sqlite3.connect(f"file:{run_dir / 'state.db'}?mode=ro", uri=True)
        try:
            assert con.execute("SELECT id FROM sessions").fetchone() == ("S1",)
        finally:
            con.close()
    finally:
        writer.close()


def test_capture_escapes_special_characters_in_hermes_home_path(tmp_path):
    """Both run_dir and host_hermes_home are caller-supplied argv in
    bin/agent-run.sh. An f-string URI (`f"file:{source}?mode=ro"`) leaves a
    literal '?' in the path unescaped, which SQLite then parses as the
    start of URI query parameters rather than as part of the path —
    confirmed directly to connect successfully to the WRONG resource,
    completing with no exception and writing a 4096-byte destination whose
    sqlite_master is empty: a second, silent route to the exact F1 symptom.
    Path.as_uri() percent-encodes '?', naming the real file regardless."""
    home = tmp_path / "weird?home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")

    captured = _capture_state_db(home, run_dir)

    assert captured is True
    con = sqlite3.connect(f"file:{run_dir / 'state.db'}?mode=ro", uri=True)
    try:
        assert con.execute("SELECT id FROM sessions").fetchone() == ("S1",)
    finally:
        con.close()


def test_missing_state_db_does_not_raise_on_capture(tmp_path):
    """A stub run (or a real run that never got far enough to write
    anything) has no state.db to copy — that must degrade silently, the
    same way read_session itself does, not raise."""
    s = spec(tmp_path)
    p = tmp_path / "p.md"
    p.write_text("x")
    result = run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "ok"))
    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    assert not (run_dir / "state.db").exists()
    assert result.state_db_captured is False


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


def test_session_json_survives_a_blob_in_the_usage_row(tmp_path):
    """session_model_usage is `SELECT *` on Hermes's own schema (session.py's
    _read), not ours — the same reasoning that justified
    _MALFORMED_DB_ERRORS there. A BLOB-typed column comes back from sqlite3
    as `bytes`, which json.dumps rejects by default. Reproduced: without
    default=str, this raises TypeError *after* the container has already
    run, discarding the whole AgentResult and leaving session.json
    unwritten — a crash on a schema this project doesn't control, exactly
    what the never-raise posture elsewhere in this module exists to avoid.
    """
    s = spec(tmp_path)
    home = Path(s.host_hermes_home)
    db_path = home / "state.db"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE sessions (id TEXT, started_at REAL)")
    con.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, "
                "role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, "
                "tool_name TEXT, timestamp REAL, finish_reason TEXT)")
    con.execute("CREATE TABLE session_model_usage (session_id TEXT, model TEXT, "
                "raw_response BLOB)")
    con.execute("INSERT INTO sessions VALUES ('S1', 1.0)")
    con.execute("INSERT INTO messages VALUES "
               "(1, 'S1', 'assistant', 'done', NULL, NULL, NULL, 1.0, 'stop')")
    con.execute("INSERT INTO session_model_usage VALUES ('S1', 'claude-sonnet-5', ?)",
               (b"\x00\x01\xff binary",))
    con.commit()
    con.close()

    p = tmp_path / "p.md"
    p.write_text("x")
    result = run_agent(s, p, secret_env={}, model=MODEL, stub=lambda a, t, e: (0, "ok"))
    assert isinstance(result.usage["raw_response"], bytes)  # unchanged in-process

    run_dir = Path(next(m.source for m in s.mounts if m.target == "/work/run"))
    payload = json.loads((run_dir / "session.json").read_text())  # must not have raised
    assert payload["usage"]["raw_response"] == str(b"\x00\x01\xff binary")


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


# --- fourth review: the capture's failure path was itself a mutation of an
# agent-controlled path. /work/run is a writable bind mount and the agent runs
# --yolo (the spike transcript has it running `mkdir -p /work/run`), so
# run_dir/state.db is attacker-influenced. _capture_state_db now backs up to a
# private `.state.db.partial-<pid>` and os.replace's it onto state.db, so its
# recovery path only ever touches a path it created itself. ---

def _lock_exclusively(db_path: Path) -> sqlite3.Connection:
    """Hold a genuine EXCLUSIVE lock on db_path. Caller must roll back/close.

    Measured against this exact shape before it became a test: an unbounded
    `backup()` was still running when killed at 20 s, and a `signal.alarm(6)`
    installed around it never fired — backup()'s SQLITE_BUSY retry runs in a C
    loop no Python signal handler interrupts. A hang is strictly worse than a
    crash for a harness, which is why the budget exists.
    """
    locker = sqlite3.connect(db_path, isolation_level=None)
    locker.execute("BEGIN EXCLUSIVE")
    return locker


def test_dest_pre_existing_as_a_directory_does_not_raise(tmp_path):
    """N1, primary trigger. The agent can create anything under /work/run,
    including a directory named state.db. The source is perfectly valid, so
    the backup itself succeeds; it is the handler that used to explode:
    `dest.unlink(missing_ok=True)` on a directory raises PermissionError on
    macOS (IsADirectoryError on Linux), which escaped run_agent entirely and
    left session.json unwritten — destroying the evidence this function
    exists to save, since agent-run.sh's `trap cleanup EXIT` still deletes
    host_hermes_home on the way out.
    """
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    (run_dir / "state.db").mkdir()  # agent-planted directory at the archive path

    captured = _capture_state_db(home, run_dir)  # must not raise

    assert captured is False
    # The agent's directory is left exactly as it was: this function's
    # recovery path must not mutate a path it did not create.
    assert (run_dir / "state.db").is_dir()
    assert not any(p.name.startswith(".state.db.partial") for p in run_dir.iterdir())


def test_run_dir_not_writable_with_existing_dest_does_not_raise(tmp_path):
    """N1, second trigger — the one the shipped test could not reach. The
    existing not-writable test creates no destination, so the handler's
    `dest.unlink(missing_ok=True)` was a no-op that could never fail. With a
    destination actually present in a 0o500 directory, unlink raises
    PermissionError [Errno 13] (measured directly)."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    _write_real_state_db(run_dir / "state.db")  # a previous, good archive
    run_dir.chmod(0o500)
    try:
        captured = _capture_state_db(home, run_dir)  # must not raise
    finally:
        run_dir.chmod(0o700)  # restore so pytest can clean up tmp_path

    assert captured is False
    # And the previously good archive is still there and still readable — a
    # failed capture must not destroy a successful earlier one.
    con = sqlite3.connect(f"file:{run_dir / 'state.db'}?mode=ro", uri=True)
    try:
        assert con.execute("SELECT id FROM sessions").fetchone() == ("S1",)
    finally:
        con.close()


def test_dest_pre_existing_junk_file_is_replaced_by_real_evidence(tmp_path):
    """N3. The agent plants a junk file at run_dir/state.db. Writing the
    backup straight into it made `backup()` fail on the *destination*
    (`sqlite3.DatabaseError: file is not a database`, measured), the junk got
    deleted, the real evidence was never archived, and nothing recorded why.
    Backing up to a private temp name and renaming makes the junk irrelevant:
    it is simply replaced by the real record."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    (run_dir / "state.db").write_bytes(b"junk planted by the agent " * 40)

    captured = _capture_state_db(home, run_dir)

    assert captured is True
    con = sqlite3.connect(f"file:{run_dir / 'state.db'}?mode=ro", uri=True)
    try:
        assert con.execute("SELECT id FROM sessions").fetchone() == ("S1",)
        assert con.execute("SELECT count(*) FROM messages").fetchone()[0] == 3
    finally:
        con.close()
    assert not any(p.name.startswith(".state.db.partial") for p in run_dir.iterdir())


def test_truncated_source_state_db_does_not_raise(tmp_path):
    """A real SQLite file cut off mid-page — the shape a container killed
    mid-write leaves behind. Distinct from the all-garbage case: the header
    is valid, so SQLite gets further before failing."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    full = (home / "state.db").read_bytes()
    assert full.startswith(b"SQLite format 3\x00")  # a genuinely valid header
    (home / "state.db").write_bytes(full[: len(full) // 2 + 100])

    captured = _capture_state_db(home, run_dir)  # must not raise

    assert captured is False
    assert not (run_dir / "state.db").exists()
    assert not any(p.name.startswith(".state.db.partial") for p in run_dir.iterdir())


def test_source_state_db_that_is_a_directory_does_not_raise(tmp_path):
    """host_hermes_home is caller-supplied argv; a directory at state.db is
    reachable both by a mis-seeded home and by the agent itself."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (home / "state.db").mkdir()

    captured = _capture_state_db(home, run_dir)  # must not raise

    assert captured is False
    assert list(run_dir.iterdir()) == []


def test_locked_source_returns_within_the_budget_rather_than_hanging(tmp_path):
    """N2. `Connection.backup()` retries SQLITE_BUSY/SQLITE_LOCKED in an
    unbounded C loop that no Python signal handler can interrupt — measured:
    still running at 20 s against an EXCLUSIVE-locked source, with a
    signal.alarm(6) that never fired. read_session degrades on the same input
    in 5.4 s; the capture hung indefinitely, which for a harness is strictly
    worse than crashing. Only backup()'s progress callback runs Python code
    on every retry, so raising from it is the sole available bound.

    The budget is monkeypatched down purely to keep this test fast — the
    mechanism under test is the deadline, not the specific number, and the
    shipped number is pinned separately below.
    """
    monkey_budget = 0.5
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    locker = _lock_exclusively(home / "state.db")
    original = shim._BACKUP_BUDGET_SECONDS
    shim._BACKUP_BUDGET_SECONDS = monkey_budget
    try:
        started = time.monotonic()
        captured = _capture_state_db(home, run_dir)  # must return, not hang
        elapsed = time.monotonic() - started
    finally:
        shim._BACKUP_BUDGET_SECONDS = original
        locker.rollback()
        locker.close()

    assert captured is False
    # Generous ceiling relative to the 0.5 s budget: the assertion that
    # matters is "bounded at all", and the unbounded version does not finish.
    assert elapsed < 5.0, f"capture took {elapsed:.1f}s — the deadline did not bound it"
    assert not (run_dir / "state.db").exists()
    assert not any(p.name.startswith(".state.db.partial") for p in run_dir.iterdir())


def test_backup_budget_is_finite_and_bounded():
    """The test above monkeypatches the budget for speed, so pin the shipped
    value here: a budget that grew without limit would silently restore the
    hang N2 is about."""
    assert 0 < shim._BACKUP_BUDGET_SECONDS <= 10.0
    # The per-retry busy timeout must stay well under the budget, or the
    # deadline can only be checked once per busy timeout — measured: with the
    # 5 s default, a 2.0 s budget was not honoured until 5.4 s.
    assert shim._BACKUP_BUSY_TIMEOUT_SECONDS < shim._BACKUP_BUDGET_SECONDS / 2
    # A bounded page count is what makes the callback fire during a long copy
    # at all; the sqlite3 default of -1 copies everything in a single step.
    assert shim._BACKUP_PAGES_PER_STEP > 0


def test_cleanup_of_its_own_temp_file_cannot_raise(tmp_path):
    """The recovery path of a never-raise function must be at least as
    unfailable as its happy path — the gap the previous round left open. Even
    the private temp name lives in an agent-writable directory, so unlink can
    still fail on it: a directory planted at exactly that path makes
    sqlite3.connect fail (OperationalError) and then Path.unlink fail
    (PermissionError, measured). Without the nested guard the second
    exception escapes run_agent and the AgentResult is lost."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    (run_dir / f".state.db.partial-{os.getpid()}").mkdir()

    captured = _capture_state_db(home, run_dir)  # must not raise

    assert captured is False
    assert not (run_dir / "state.db").exists()


def test_failed_capture_does_not_destroy_a_previous_archive(tmp_path):
    """Writing straight to run_dir/state.db meant a later failed capture
    unlinked an earlier good one. With temp-then-rename, state.db is only
    ever touched by the final atomic rename after a complete backup."""
    home = tmp_path / "home"
    home.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_real_state_db(home / "state.db")
    assert _capture_state_db(home, run_dir) is True  # a good archive exists

    (home / "state.db").write_bytes(b"the next run wrote garbage " * 20)
    assert _capture_state_db(home, run_dir) is False

    con = sqlite3.connect(f"file:{run_dir / 'state.db'}?mode=ro", uri=True)
    try:
        assert con.execute("SELECT id FROM sessions").fetchone() == ("S1",)
    finally:
        con.close()


def test_agent_run_sh_summary_surfaces_state_db_captured():
    """N4. AgentResult records state_db_captured, but bin/agent-run.sh's
    summary JSON emitted only exit_code/succeeded/session_id/finish_reason/
    tool_call_count/usage/arm — so a silent capture failure was invisible to
    anyone running the script, which is the only way this is run in
    production. A text-level pin: the summary is built inside a heredoc that
    invokes docker, so it cannot be exercised in-process here."""
    script = (Path(__file__).resolve().parents[1] / "bin" / "agent-run.sh").read_text()
    summary = script.split("summary = {", 1)[1].split("}", 1)[0]
    assert '"state_db_captured": result.state_db_captured,' in summary


# --- three distinct paths: the trap this task's brief calls out explicitly ---

def test_spec_requires_three_distinct_paths(tmp_path):
    with pytest.raises(ValueError):
        engineer_spec(runtime_image_id=IMAGE, run_dir=str(tmp_path),
                      canonical_repo=str(tmp_path), host_hermes_home=str(tmp_path),
                      env_passthrough=[])
