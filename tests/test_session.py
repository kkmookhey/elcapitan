"""Tests for elcapitan.session — the state.db reader.

The fixture (tests/fixtures/spike-state.db) is a REAL state.db copied from
the Task 0 spike runs against the actual Hermes image. It holds three
sessions, which is exactly the discrimination this module must get right:

  20260809_224012_eabbff   message_count=4  tool_call_count=1   successful run
  20260809_224135_f660ef   message_count=1  tool_call_count=0   no API key
  20260809_224215_8ec72b   message_count=1  tool_call_count=0   bad model (9x 404)

`sessions.end_reason` is EMPTY for all three, confirmed by direct inspection
of the fixture — do not rely on it. `finish_reason` lives on `messages`:
"tool_calls" on the assistant row that issues a call, "stop" on the row that
completes the reply. The two failed sessions have exactly one message (the
user's own prompt) and never got an assistant reply at all, so their
finish_reason is "" and tool_call_count is 0.
"""
import json
import sqlite3
from pathlib import Path

import pytest

import elcapitan.session as session_module
from elcapitan.session import (
    EMPTY_SESSION,
    MultipleSessionsError,
    SessionRecord,
    read_session,
    session_succeeded,
)

FIXTURE = Path(__file__).parent / "fixtures" / "spike-state.db"

SUCCESS_ID = "20260809_224012_eabbff"
NO_API_KEY_ID = "20260809_224135_f660ef"
BAD_MODEL_ID = "20260809_224215_8ec72b"


def _single_session_db(tmp_path, keep_id: str) -> Path:
    """Copy the fixture but delete every session except `keep_id`.

    Production points read_session at a state.db from a single, fresh
    HERMES_HOME, which the spike's shared fixture is not — it holds three
    sessions from three separate container runs sharing one home. This
    builds the single-session shape production actually sees, from real
    fixture data, so the default (strict) code path gets exercised against
    real rows rather than only ever through allow_multiple=True.
    """
    import shutil

    tmp_path.mkdir(parents=True, exist_ok=True)
    dest = tmp_path / "state.db"
    shutil.copy(FIXTURE, dest)
    con = sqlite3.connect(dest)
    try:
        con.execute("DELETE FROM messages WHERE session_id != ?", (keep_id,))
        con.execute("DELETE FROM session_model_usage WHERE session_id != ?", (keep_id,))
        con.execute("DELETE FROM sessions WHERE id != ?", (keep_id,))
        con.commit()
    finally:
        con.close()
    return dest


# --- discrimination across the three real fixture sessions (the core assertion) ---

def test_successful_session_reads_stop_and_one_tool_call(tmp_path):
    db = _single_session_db(tmp_path, SUCCESS_ID)
    record = read_session(db)
    assert record.session_id == SUCCESS_ID
    assert record.finish_reason == "stop"
    assert record.tool_call_count == 1


def test_no_api_key_session_has_no_finish_reason_and_no_tool_calls(tmp_path):
    db = _single_session_db(tmp_path, NO_API_KEY_ID)
    record = read_session(db)
    assert record.finish_reason == ""
    assert record.tool_call_count == 0


def test_bad_model_session_has_no_finish_reason_and_no_tool_calls(tmp_path):
    db = _single_session_db(tmp_path, BAD_MODEL_ID)
    record = read_session(db)
    assert record.finish_reason == ""
    assert record.tool_call_count == 0


def test_succeeded_predicate_discriminates_all_three_fixture_sessions(tmp_path):
    """The single most important assertion in this task: a failed trial must
    never score as a successful one just because the process exited 0.

    Uses `session_succeeded` — the production predicate imported from
    elcapitan.session, the one `shim.run_agent` actually calls — rather than
    a locally redeclared copy. A local redeclaration here would test this
    test's own logic, not production's; it would not fail if
    `session_succeeded` (or shim.py's use of it) regressed.
    """
    success = read_session(_single_session_db(tmp_path / "s", SUCCESS_ID))
    no_key = read_session(_single_session_db(tmp_path / "k", NO_API_KEY_ID))
    bad_model = read_session(_single_session_db(tmp_path / "m", BAD_MODEL_ID))

    assert session_succeeded(success) is True
    assert session_succeeded(no_key) is False
    assert session_succeeded(bad_model) is False


def test_succeeded_requires_stop_even_with_a_tool_call():
    """A session that made a tool call and then died mid-loop never reaches
    "stop" — it reports "tool_calls" forever. The three real fixture
    sessions can't prove tool_call_count alone is insufficient (both
    failures have tool_call_count == 0 too), so this is constructed
    directly."""
    died_mid_loop = SessionRecord(session_id="x", finish_reason="tool_calls",
                                  tool_call_count=1, transcript="")
    assert session_succeeded(died_mid_loop) is False


def test_succeeded_requires_a_tool_call_even_with_stop():
    """A model that replies "I can't do that" and stops without ever acting
    reaches a real "stop" with zero tool calls — exactly the failed-trial
    shape this task exists to stop from scoring green. The three real
    fixture sessions can't prove finish_reason alone is insufficient (both
    failures also lack "stop"), so this is constructed directly."""
    refused_without_acting = SessionRecord(session_id="x", finish_reason="stop",
                                           tool_call_count=0, transcript="")
    assert session_succeeded(refused_without_acting) is False


def test_readonly_connection_rejects_writes(tmp_path):
    """Proves the mode=ro guarantee directly, through the module's own
    connection path — not by inference from "the fixture's bytes didn't
    change" (test_read_only_open_never_writes_to_the_fixture, below),
    which stays green even if read_session switched to a plain read-write
    connection that simply never happens to issue a write. Mutating
    _connect_readonly to `sqlite3.connect(str(db_path))` makes this test
    fail immediately; the hash-comparison test alone would not catch it.
    """
    db = _single_session_db(tmp_path, SUCCESS_ID)
    con = session_module._connect_readonly(db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            con.execute("UPDATE sessions SET model = 'tampered'")
    finally:
        con.close()


# --- parsing detail on the real successful session ---

def test_transcript_contains_the_real_command_and_exit_code(tmp_path):
    db = _single_session_db(tmp_path, SUCCESS_ID)
    record = read_session(db)
    assert "mkdir -p /work/run" in record.transcript
    # Not "0" in record.transcript / "exit_code" in record.transcript.lower()
    # — both are vacuously true (RFC3339 timestamps on every line guarantee
    # a "0" digit; "exit_code" is the literal label this reader itself
    # writes regardless of the value). Assert the actual pairing instead.
    assert "exit_code: 0" in record.transcript


def test_commands_parsed_from_tool_calls_json(tmp_path):
    db = _single_session_db(tmp_path, SUCCESS_ID)
    record = read_session(db)
    assert len(record.commands) == 1
    cmd = record.commands[0]
    assert cmd.tool == "terminal"
    assert "mkdir -p /work/run" in cmd.argv[0]
    assert cmd.exit_code == 0
    assert cmd.output == "3"
    assert cmd.error is None
    assert cmd.command_id.startswith("CMD-")


def test_usage_populated_for_successful_session(tmp_path):
    db = _single_session_db(tmp_path, SUCCESS_ID)
    record = read_session(db)
    assert record.usage["model"] == "claude-sonnet-5"
    assert record.usage["billing_provider"] == "anthropic"
    assert record.usage["input_tokens"] == 4
    assert record.usage["output_tokens"] == 147
    assert record.usage["estimated_cost_usd"] == pytest.approx(0.0144368)


def test_usage_empty_dict_when_no_usage_row(tmp_path):
    db = _single_session_db(tmp_path, NO_API_KEY_ID)
    record = read_session(db)
    assert record.usage == {}


# --- the fixture's real shape: three sessions in one database ---

def _fixture_copy(tmp_path) -> Path:
    """A plain copy of the fixture, untouched. Every test in this module
    reads a copy rather than tests/fixtures/spike-state.db directly, so the
    checked-in fixture can never accumulate SQLite's WAL-mode sidecar files
    (-shm/-wal) as a side effect of merely running the suite."""
    import shutil

    dest = tmp_path / "spike-state.db"
    shutil.copy(FIXTURE, dest)
    return dest


def test_multiple_sessions_raises_by_default(tmp_path):
    with pytest.raises(MultipleSessionsError):
        read_session(_fixture_copy(tmp_path))


def test_allow_multiple_takes_the_latest_by_started_at(tmp_path):
    record = read_session(_fixture_copy(tmp_path), allow_multiple=True)
    assert record.session_id == BAD_MODEL_ID  # latest started_at of the three


# --- never raise on malformed, absent, locked, or non-SQLite input ---

def test_missing_database_returns_empty_record(tmp_path):
    record = read_session(tmp_path / "does-not-exist.db")
    assert record == EMPTY_SESSION
    assert record.finish_reason == ""
    assert record.tool_call_count == 0


def test_non_sqlite_file_returns_empty_record(tmp_path):
    junk = tmp_path / "state.db"
    junk.write_bytes(b"not a sqlite database at all")
    record = read_session(junk)
    assert record == EMPTY_SESSION


def test_empty_sessions_table_returns_empty_record(tmp_path):
    db = tmp_path / "state.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE sessions (id TEXT, started_at REAL)")
    con.execute("CREATE TABLE messages (id INTEGER, session_id TEXT, role TEXT, "
                "content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT, "
                "timestamp REAL, finish_reason TEXT)")
    con.execute("CREATE TABLE session_model_usage (session_id TEXT)")
    con.commit()
    con.close()
    record = read_session(db)
    assert record == EMPTY_SESSION


def test_directory_instead_of_file_returns_empty_record(tmp_path):
    d = tmp_path / "state.db"
    d.mkdir()
    record = read_session(d)
    assert record == EMPTY_SESSION


def test_malformed_tool_calls_json_does_not_raise(tmp_path):
    """A row with unparseable tool_calls must degrade, not crash the reader."""
    db = tmp_path / "state.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE sessions (id TEXT, started_at REAL, model TEXT)")
    con.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, "
                "role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, "
                "tool_name TEXT, timestamp REAL, finish_reason TEXT)")
    con.execute("CREATE TABLE session_model_usage (session_id TEXT)")
    con.execute("INSERT INTO sessions VALUES ('S1', 1.0, 'x')")
    con.execute("INSERT INTO messages VALUES "
               "(1, 'S1', 'assistant', '', NULL, '{not valid json', NULL, 1.0, 'tool_calls')")
    con.commit()
    con.close()
    record = read_session(db)
    # Must not raise; the malformed call simply doesn't parse into a command.
    assert record.session_id == "S1"
    assert record.commands == []


def _db_with_one_assistant_message(tmp_path, *, tool_calls_json=None, timestamp=1.0):
    """A minimal single-message state.db, for exercising _build_transcript/
    _build_commands directly through read_session against a specific
    messages.tool_calls or timestamp shape, without needing the full fixture."""
    db = tmp_path / "state.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE sessions (id TEXT, started_at REAL, model TEXT)")
    con.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, "
                "role TEXT, content TEXT, tool_call_id TEXT, tool_calls TEXT, "
                "tool_name TEXT, timestamp REAL, finish_reason TEXT)")
    con.execute("CREATE TABLE session_model_usage (session_id TEXT)")
    con.execute("INSERT INTO sessions VALUES ('S1', 1.0, 'x')")
    con.execute(
        "INSERT INTO messages VALUES (1, 'S1', 'assistant', '', NULL, ?, NULL, ?, 'tool_calls')",
        (tool_calls_json, timestamp),
    )
    con.commit()
    con.close()
    return db


# --- messages.tool_calls is Hermes's schema, not ours: valid JSON, odd shapes ---

@pytest.mark.parametrize("bad_function", [None, "a string", [1, 2]])
def test_tool_call_with_non_dict_function_does_not_raise(tmp_path, bad_function):
    """Reproduced in review with exactly these three shapes: {"function":
    null}, {"function": "t"}, {"function": [1, 2]}. All are valid JSON —
    _parse_tool_calls's json.loads succeeds — but `fn.get(...)` on a
    non-dict `function` used to raise AttributeError, which escaped
    read_session entirely (AttributeError was not in _MALFORMED_DB_ERRORS
    and this shape sails straight past _parse_tool_calls's own JSON-decode
    guard, since the JSON is well-formed)."""
    calls = json.dumps([{"id": "c1", "function": bad_function}])
    db = _db_with_one_assistant_message(tmp_path, tool_calls_json=calls)
    record = read_session(db)  # must not raise
    assert record.session_id == "S1"
    assert record.commands[0].tool == ""
    assert record.commands[0].argv == [""]
    assert "tool_call: " in record.transcript  # degraded to an empty name, not crashed


def test_out_of_range_timestamp_does_not_raise(tmp_path):
    """_to_rfc3339 feeds datetime.fromtimestamp, which raises OverflowError
    (or OSError, platform-dependent) for a value outside the representable
    range. Guarded directly in _to_rfc3339 (degrades to "" for just that
    field) with OverflowError also added to _MALFORMED_DB_ERRORS as a
    backstop."""
    db = _db_with_one_assistant_message(tmp_path, timestamp=1e20)
    record = read_session(db)  # must not raise
    assert record.session_id == "S1"


def test_read_only_open_never_writes_to_the_fixture(tmp_path):
    """Open read-only: the host must never write to an artifact the agent
    produced. Copy the fixture, hash it before and after, and diff."""
    import hashlib
    import shutil

    db = tmp_path / "state.db"
    shutil.copy(FIXTURE, db)
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    read_session(db, allow_multiple=True)
    after = hashlib.sha256(db.read_bytes()).hexdigest()
    assert before == after
