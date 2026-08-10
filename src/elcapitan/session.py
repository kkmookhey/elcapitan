"""Read the agent runtime's own session record from state.db.

docs/spike-findings.md §3 and §6 are why this module exists at all, and why
it looks the way it does:

- **stdout is not the transcript.** The `-q` preview truncates to one named
  fragment ("mkdir -p /work/run + 3 commands") with no output and no exit
  codes. The real record is `/opt/data/state.db` (SQLite): the assistant
  message's `tool_calls` column carries the command text
  (`function.arguments.command`), and the paired tool message's `content` is
  `{"output": ..., "exit_code": ..., "error": ...}`.
- **exit code 0 is not a success signal.** A run with no API key and a run
  whose model 404'd nine times both exit 0 and both still write a `sessions`
  row. `sessions.end_reason` is EMPTY in every observed case — don't rely on
  it. The signal that actually distinguishes them lives on `messages`:
  `finish_reason == "stop"` only appears on a real completion; a session
  that got no assistant reply at all never sets it.

The database is opened **read-only** (`file:...?mode=ro`) — the host must
never write to an artifact the agent produced.
"""
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class MultipleSessionsError(AssertionError):
    """More than one session row exists in a database read_session expected
    to hold exactly one.

    A fresh HERMES_HOME per trial means a trial's state.db should contain
    exactly one session. More than one means either state bled across
    trials (a correctness bug worth crashing on immediately) or the caller
    pointed read_session at the wrong database. This is a different failure
    class from "the database is malformed/absent/locked": those are
    anticipated runtime conditions the harness must survive and report
    structurally (see EMPTY_SESSION below); a contaminated multi-trial
    database is a broken precondition, not an anticipated one, and silently
    picking "the latest" would hide exactly the bug this exists to catch.

    Tests that need to read a genuinely multi-session database — such as
    tests/fixtures/spike-state.db, which holds three sessions from three
    separate spike runs sharing one home — pass allow_multiple=True
    explicitly, rather than this exception being silently downgraded.
    """


@dataclass(frozen=True)
class CommandRecord:
    """A tool call parsed out of state.db, CommandRecord-shaped.

    This is deliberately not a schema-valid CommandRecord (schemas/command-
    record.schema.json): that schema requires stdout_evidence_id /
    stderr_evidence_id, which only exist once a later stage writes this
    command's output through elcapitan.evidence.write_evidence. session.py
    sits upstream of evidence writing, so it carries the raw output/exit_code
    /error it actually has and leaves evidence-ref promotion to that caller.

    `argv` holds a single element: the full shell command line Hermes's
    `terminal` tool received (e.g. "mkdir -p /work/run && ..."). It is not
    tokenised — the command already contains shell operators (&&, quoting)
    that shlex.split would either mangle or that were never meant to be
    split into argv-style tokens in the first place, since this was a single
    string passed to a shell, not an execve argv.
    """

    command_id: str
    tool: str
    argv: list[str]
    exit_code: int | None
    started_at: str
    completed_at: str
    output: str | None
    error: str | None


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    finish_reason: str
    tool_call_count: int
    transcript: str
    usage: dict = field(default_factory=dict)
    commands: list[CommandRecord] = field(default_factory=list)


# Returned whenever the database cannot be trusted at all — absent, locked,
# not SQLite, or missing the tables this reader expects. finish_reason=""
# and tool_call_count=0 make this indistinguishable, from the caller's
# succeeded-predicate's point of view, from a run that did nothing: exactly
# the structured-failure behaviour the harness needs, since a crash here is
# indistinguishable from a run that never happened.
EMPTY_SESSION = SessionRecord(session_id="", finish_reason="", tool_call_count=0,
                              transcript="")

# Exceptions from a database that is present but broken in some way this
# reader cannot make sense of: not a SQLite file, missing expected tables or
# columns, a lock that can't be acquired, or any other OperationalError/
# DatabaseError. IndexError is here because sqlite3.Row raises THAT (not
# KeyError) for a missing column name — not currently reachable given the
# explicit column lists in every SELECT below, but a schema this reader
# doesn't fully control is worth defending defensively, not just for the
# cases already proven to occur. MultipleSessionsError is handled
# separately (re-raised, never caught here) because it signals a real
# precondition violation, not an unusable database.
_MALFORMED_DB_ERRORS = (sqlite3.Error, OSError, ValueError, TypeError, KeyError, IndexError)


def _to_rfc3339(ts) -> str:
    """state.db stores timestamps as float unix seconds; every other record
    in this project uses RFC3339 strings (see records.py's FormatChecker)."""
    if ts is None:
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_tool_calls(raw: str | None) -> list[dict]:
    if not raw:
        return []
    try:
        calls = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return calls if isinstance(calls, list) else []


def _parse_tool_content(raw: str | None) -> dict:
    """The tool response message's content column: '{"output":…,"exit_code":…,"error":…}'."""
    if not raw:
        return {}
    try:
        content = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return content if isinstance(content, dict) else {}


def _build_transcript(rows: list[sqlite3.Row]) -> str:
    lines = []
    for row in rows:
        ts = _to_rfc3339(row["timestamp"])
        role = row["role"]
        if role == "assistant" and row["tool_calls"]:
            lines.append(f"[{ts}] assistant (finish_reason={row['finish_reason']}):")
            for call in _parse_tool_calls(row["tool_calls"]):
                fn = call.get("function", {}) if isinstance(call, dict) else {}
                name = fn.get("name", "")
                args_raw = fn.get("arguments", "")
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except (json.JSONDecodeError, TypeError):
                    args = {}
                command = args.get("command", "") if isinstance(args, dict) else ""
                lines.append(f"  tool_call: {name}")
                lines.append(f"  command: {command}")
        elif role == "tool":
            content = _parse_tool_content(row["content"])
            lines.append(f"[{ts}] tool ({row['tool_name']}):")
            lines.append(f"  output: {content.get('output')}")
            lines.append(f"  exit_code: {content.get('exit_code')}")
            lines.append(f"  error: {content.get('error')}")
        else:
            lines.append(f"[{ts}] {role}: {row['content'] or ''}")
    return "\n".join(lines)


def _build_commands(rows: list[sqlite3.Row]) -> list[CommandRecord]:
    # Index tool-response rows by tool_call_id so each command call can be
    # paired with its result in a single pass.
    tool_results = {
        row["tool_call_id"]: row for row in rows
        if row["role"] == "tool" and row["tool_call_id"]
    }

    commands: list[CommandRecord] = []
    seq = 0
    for row in rows:
        if row["role"] != "assistant" or not row["tool_calls"]:
            continue
        for call in _parse_tool_calls(row["tool_calls"]):
            if not isinstance(call, dict):
                continue
            call_id = call.get("id") or call.get("call_id")
            fn = call.get("function", {})
            name = fn.get("name", "")
            args_raw = fn.get("arguments", "")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except (json.JSONDecodeError, TypeError):
                args = {}
            command_text = args.get("command", "") if isinstance(args, dict) else ""

            result_row = tool_results.get(call_id)
            content = _parse_tool_content(result_row["content"]) if result_row else {}

            seq += 1
            commands.append(CommandRecord(
                command_id=f"CMD-{seq:03d}",
                tool=name,
                argv=[command_text],
                exit_code=content.get("exit_code"),
                started_at=_to_rfc3339(row["timestamp"]),
                completed_at=_to_rfc3339(result_row["timestamp"]) if result_row else "",
                output=content.get("output"),
                error=content.get("error"),
            ))
    return commands


def _latest_finish_reason(rows: list[sqlite3.Row]) -> str:
    """The last non-null finish_reason seen, in row order.

    A completed reply ends with "stop"; an in-flight tool call carries
    "tool_calls" until the assistant's follow-up message supersedes it. A
    session with no assistant reply at all (both failure fixtures) has no
    row with a finish_reason, so this returns "".
    """
    reason = ""
    for row in rows:
        if row["finish_reason"]:
            reason = row["finish_reason"]
    return reason


def _read(con: sqlite3.Connection, *, allow_multiple: bool) -> SessionRecord:
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT id FROM sessions ORDER BY started_at DESC")
    session_rows = cur.fetchall()
    if not session_rows:
        return EMPTY_SESSION
    if len(session_rows) > 1 and not allow_multiple:
        raise MultipleSessionsError(
            f"expected exactly one session, found {len(session_rows)}: "
            f"{[r['id'] for r in session_rows]}. A fresh HERMES_HOME per trial "
            "should produce exactly one; pass allow_multiple=True if this "
            "database is deliberately shared across sessions (e.g. a test "
            "fixture).")
    session_id = session_rows[0]["id"]

    cur.execute(
        "SELECT id, role, content, tool_call_id, tool_calls, tool_name, "
        "timestamp, finish_reason FROM messages WHERE session_id = ? ORDER BY id",
        (session_id,),
    )
    message_rows = cur.fetchall()

    cur.execute("SELECT * FROM session_model_usage WHERE session_id = ?", (session_id,))
    usage_row = cur.fetchone()
    usage = dict(usage_row) if usage_row is not None else {}

    commands = _build_commands(message_rows)
    return SessionRecord(
        session_id=session_id,
        finish_reason=_latest_finish_reason(message_rows),
        tool_call_count=len(commands),
        transcript=_build_transcript(message_rows),
        usage=usage,
        commands=commands,
    )


def read_session(db_path, *, allow_multiple: bool = False) -> SessionRecord:
    """Read the session record from a Hermes state.db.

    Takes the latest session by `started_at`. Never raises on a malformed,
    absent, locked, or non-SQLite database — returns EMPTY_SESSION instead,
    so the caller reports a structured failure rather than crashing (same
    contract as elcapitan.validate, for the same reason: a crash here is
    indistinguishable from a run that never happened).

    Raises MultipleSessionsError — deliberately, not swallowed — if the
    database holds more than one session and allow_multiple is not set. See
    that exception's docstring for why this is a different failure class
    from "malformed database".
    """
    db_path = Path(db_path)
    con = None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        return _read(con, allow_multiple=allow_multiple)
    except MultipleSessionsError:
        raise
    except _MALFORMED_DB_ERRORS:
        return EMPTY_SESSION
    finally:
        if con is not None:
            con.close()
