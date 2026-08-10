"""The only place an agent runtime is invoked.

The argv built here is taken verbatim from docs/spike-findings.md §2 — an
empirically proven invocation against the real image, not an invented one:

    chat -q "<prompt>" -t terminal --yolo --ignore-user-config -m <model>

There is no `--prompt-file` in Hermes (confirmed in the spike by reading
`hermes chat --help` and the argument-routing script directly). The
supported non-interactive forms are `hermes chat -q "<prompt>"` (retains
tool calls and their output — what the probe needs) and `hermes -z` (final
text only, no tool transcript). `-q` is used here for exactly that reason.

Two measured facts from the spike shape `AgentResult` (§3, §6):

- **stdout is not the transcript.** `chat -q`'s stdout preview truncates to
  one named tool-call fragment with no output and no exit codes. The real
  record is /opt/data/state.db, read via `elcapitan.session.read_session`.
- **exit code 0 is not a success signal.** A run with no API key and a run
  whose model 404'd nine times both exit 0 and both still write a `sessions`
  row with no completed assistant reply. `AgentResult.succeeded` is derived
  from the session record's `finish_reason`/`tool_call_count`, never from
  `exit_code` — which is kept on the result for diagnosis only.
"""
import json
import os
import sqlite3
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .constants import SCANNER_ENV_MAP
from .container import ContainerSpec
from .session import CommandRecord, read_session, session_succeeded

StubFn = Callable[[list[str], str, dict], tuple[int, str]]

# Re-exported, not redefined: elcapitan.cloud uses the same three host
# variable names on the host side to re-query the finding's resource after the
# run. One definition in constants.py, two importers — see its comment.
MODEL_ENV_MAP = {"ELCAP_MODEL_API_KEY": "ANTHROPIC_API_KEY"}


@dataclass(frozen=True)
class AgentResult:
    exit_code: int           # recorded for diagnosis only — see module docstring
    succeeded: bool           # derived from the session record, never from exit_code
    session_id: str
    finish_reason: str        # "stop" on a real completion; "" otherwise
    tool_call_count: int
    transcript: str           # extracted from state.db, NOT scraped from stdout
    usage: dict                # session_model_usage row: tokens, cost, provider
    commands: list[CommandRecord]  # structured tool calls — see run_agent's persistence note
    stdout: str                 # kept for debugging only; not evidence
    state_db_captured: bool = True  # False: no source, or capture itself failed — see
                                    # _capture_state_db's docstring. A caller that knows
                                    # the archive is missing is strictly better off than
                                    # one that has to infer it from run_dir's filesystem.


def resolve_secret_env(host_env: dict, mapping: dict) -> dict:
    """Translate host-side secret variable names into container-side names.

    Raises KeyError naming the missing host variable rather than silently
    proceeding with a partial credential set — a partially-resolved AWS
    credential trio is worse than an obvious, immediate failure.
    """
    resolved = {}
    for host_name, container_name in mapping.items():
        if host_name not in host_env:
            raise KeyError(f"required secret not set on host: {host_name}")
        resolved[container_name] = host_env[host_name]
    return resolved


def _run_dir(spec: ContainerSpec) -> Path:
    return Path(next(m.source for m in spec.mounts if m.target == "/work/run"))


# Wall-clock ceiling on one Connection.backup() call.
#
# This is the ONLY thing that bounds it. `backup()` retries SQLITE_BUSY /
# SQLITE_LOCKED in a C loop with no iteration limit, and that loop is not
# interruptible by a Python signal handler — measured directly against a
# source held under BEGIN EXCLUSIVE: a `signal.alarm(6)` never fired and the
# call was still running when killed at 20 s. Neither `sleep=` nor the
# connection's busy timeout bounds the total; both only affect how long each
# individual retry takes. The progress callback is the one hook that runs
# Python code on every iteration, so raising from it is the only available
# abort.
#
# 5.0 s, chosen to match the ceiling the reader on the same file already
# degrades under: `read_session` opens with `sqlite3.connect`'s default
# `timeout=5.0`, and was measured degrading on a locked database in 5.4 s.
# Giving the capture the same patience as the read — and no more — keeps one
# blocked state.db from stalling a trial for longer than the read of it
# already could. It is four orders of magnitude above what a real capture
# needs: the real state.db measured 212 KB and a 119 KB database backs up in
# 0.002 s.
_BACKUP_BUDGET_SECONDS = 5.0

# Per-retry busy timeout on the source connection. Deliberately far below
# _BACKUP_BUDGET_SECONDS: sqlite3_backup_step blocks inside C for the whole
# busy timeout before returning SQLITE_BUSY, and the deadline can only be
# checked between steps. Measured with the default 5 s timeout, a 2.0 s
# budget was not honoured until 5.4 s — one step, one callback. At 0.25 s the
# callback runs about twice a second, so the budget is honoured to within a
# fraction of a second. This does NOT reduce how long the capture waits
# overall: the retry loop keeps going until the budget expires either way.
_BACKUP_BUSY_TIMEOUT_SECONDS = 0.25

# Pages per backup_step. A bounded step count is what makes the progress
# callback — and therefore the deadline — fire periodically during a long
# copy, instead of once at the end as the default (-1, "all pages in one
# step") would.
_BACKUP_PAGES_PER_STEP = 256


class _BackupDeadlineExceeded(Exception):
    """Raised from backup()'s progress callback to abort its retry loop.

    Private and never allowed to escape `_capture_state_db` — it exists only
    because raising is the sole way to break out of `backup()`'s otherwise
    unbounded C-level retry.
    """


def _capture_state_db(host_hermes_home: Path, run_dir: Path) -> bool:
    """Archive state.db into the run directory — the persistent evidence
    bundle — before anything can delete the ephemeral Hermes home it came
    from.

    Returns True if state.db was actually captured, False otherwise (no
    source to capture, or the capture itself failed). Recorded on
    `AgentResult.state_db_captured` and surfaced in bin/agent-run.sh's
    summary JSON, rather than left for a caller to infer by checking
    run_dir's filesystem directly.

    **This function must never raise.** bin/agent-run.sh runs
    `rm -rf "$HOST_HERMES_HOME"` from `trap cleanup EXIT`, which fires
    however `run_agent` exits — so an exception escaping here does not just
    lose the archive, it destroys the source too, and takes the whole
    `AgentResult` (and therefore session.json) with it. A crash here is
    indistinguishable from a run that never happened. Every failure mode
    below is therefore a `return False`, never a raise.

    ## Why it exists

    bin/agent-run.sh deletes any host_hermes_home it seeded itself, on EXIT,
    on success as much as on failure (nothing else owns that ephemeral
    directory's lifecycle). Before this function existed, that meant
    state.db — this module's own docstring calls it "the real record" — was
    gone the moment a successful run finished. Capturing it here, inside
    run_agent itself, fixes it for every caller, not just agent-run.sh, and
    fixes it before the caller's own cleanup can ever run.

    ## Why sqlite3's backup API, not a file copy

    Hermes's state.db runs in WAL mode and is never checkpointed by anything
    this shim controls, so the main .db file on its own can be a near-empty
    husk (observed: 4096 bytes, zero tables) with every actual row sitting in
    the uncopied state.db-wal sidecar. A plain `shutil.copy2` of just the
    main file was tried first and confirmed, against a real run, to silently
    archive an empty database while session.json right next to it correctly
    reported `succeeded: true`. `Connection.backup()` reads through the
    source connection (WAL included — a read-only connection still consults
    the WAL when present) and writes a single, complete, already-checkpointed
    copy; there is no `-wal` sidecar of the *destination* that would need
    copying alongside it, so the result can't be torn.

    ## Why a private temp name and os.replace, not a direct write to dest

    `run_dir` is `/work/run`: a writable bind mount inside a container the
    agent drives with `--yolo`. The spike transcript has the agent itself
    running `mkdir -p /work/run`. So `run_dir/state.db` is an
    attacker-influenced path, and every earlier version of this function
    both wrote to it directly and, on failure, ran `unlink` on it. Writing
    the backup to `.state.db.partial-<pid>` first and then `os.replace`-ing
    it onto `state.db` means:

    - Cleanup only ever touches a path this function created. An
      agent-planted directory or junk file at `state.db` can no longer be
      handed to `unlink` (measured: `Path.unlink` on a directory raises
      PermissionError on macOS, IsADirectoryError on Linux — that escaped
      `run_agent` and left session.json unwritten) nor poison
      `sqlite3.connect(dest)`.
    - A junk file the agent planted at `state.db` is simply replaced by the
      real evidence (measured: capture succeeds and the archive reads back
      correctly), instead of the capture failing on it and the junk being
      deleted while the real evidence is never archived.
    - A *failed* capture can no longer destroy a previously good archive:
      `state.db` is only ever touched by the final atomic rename, which
      happens only after a complete, successful backup.

    A directory pre-existing at `state.db` still cannot be captured over —
    `os.replace` onto a directory raises IsADirectoryError — but that now
    degrades to `False` with the directory left untouched, rather than
    raising. Deleting it is not this function's business: it is a path the
    agent controls, and the whole point of the restructure is that this
    function's recovery path never mutates one.

    ## Why Path.as_uri()

    An f-string (`f"file:{source}?mode=ro"`) leaves any `?`/`#` in
    `host_hermes_home` unescaped — and both `run_dir` and `host_hermes_home`
    are caller-supplied argv in bin/agent-run.sh. Measured against a path
    containing a literal `?`: the unescaped form connects successfully to the
    WRONG resource (SQLite reads everything before the first bare `?` as the
    path, everything after as query parameters), completes with no exception,
    and writes a 4096-byte destination with an empty `sqlite_master` — a
    second, silent route to the husk symptom. `as_uri()` percent-encodes it
    (`Path("/tmp/weird?dir/x").as_uri()` -> `.../weird%3Fdir/x`).

    ## The degraded cases, all measured

    - **Source absent** (a stub test, or a real run that never got far enough
      to write anything) — not an error; read_session degrades to
      EMPTY_SESSION for the same input and this degrades the same way.
    - **Source is a directory** — same: `is_file()` is False, `return False`.
    - **Source is not a SQLite file, or is a truncated one** —
      `sqlite3.DatabaseError: file is not a database`.
    - **run_dir not writable** — `sqlite3.OperationalError: unable to open
      database file`, whether or not a `state.db` already exists there. (The
      pre-existing-destination variant is why the old code's unguarded
      `dest.unlink()` in the handler raised: with dest absent it was a no-op,
      which is the only case the old test covered.)
    - **Source locked** — bounded by `_BACKUP_BUDGET_SECONDS`; see that
      constant for why nothing else bounds it. Previously this did not fail
      at all, it hung, which for a harness is strictly worse than crashing.

    `read_session` returning successfully moments earlier in the same
    `run_agent` call proves none of these are impossible: its contract is to
    catch exactly this exception class and return EMPTY_SESSION, so a
    successful *return* from it is exactly as consistent with "the database
    is fine" as with "the database is garbage."
    """
    source = host_hermes_home / "state.db"
    if not source.is_file():
        return False

    dest = run_dir / "state.db"
    # A name this function owns, so the failure path never touches an
    # agent-controlled path. See the docstring.
    partial = run_dir / f".state.db.partial-{os.getpid()}"
    try:
        # Read-only source, the same guarantee session.py's own reader
        # established: the host must never write to an artifact the agent
        # produced.
        source_con = sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True,
                                     timeout=_BACKUP_BUSY_TIMEOUT_SECONDS)
        try:
            dest_con = sqlite3.connect(partial)
            try:
                deadline = time.monotonic() + _BACKUP_BUDGET_SECONDS

                def _abort_when_out_of_time(status, remaining, pagecount):
                    if time.monotonic() > deadline:
                        raise _BackupDeadlineExceeded(
                            f"state.db backup exceeded {_BACKUP_BUDGET_SECONDS}s")

                source_con.backup(dest_con, pages=_BACKUP_PAGES_PER_STEP,
                                  progress=_abort_when_out_of_time)
            finally:
                dest_con.close()
        finally:
            source_con.close()
        os.replace(partial, dest)
    except (sqlite3.Error, OSError, ValueError, _BackupDeadlineExceeded):
        # The recovery path of a never-raise function has to be at least as
        # unfailable as its happy path. `partial` is a path this function
        # chose, but run_dir is still agent-writable, so unlink can still
        # fail on it (measured: a directory planted at exactly this name
        # makes Path.unlink raise PermissionError) — and a failure to clean
        # up a temp file is never worth converting a degraded capture into a
        # lost AgentResult.
        try:
            partial.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    return True


def _write_session_json(run_dir: Path, session) -> None:
    """Persist the structured record — usage and CommandRecord-shaped
    commands — as JSON in the run directory.

    transcript.log (unescaped free text a malicious or merely confused
    agent's own tool output could forge lines resembling, e.g. a command
    whose *output* happens to contain the literal line "  exit_code: 0")
    is kept for human readability, but it is not this run's structured
    evidence. session.json is: `commands` came from parsing
    `messages.tool_calls`/tool-response `content` JSON columns directly,
    and `usage` is the `session_model_usage` row verbatim — neither passes
    through any string formatting an agent's own output could imitate.

    `default=str` on the dump: `usage` is `SELECT *` on
    `session_model_usage` (session.py's `_read`) — Hermes's schema, not
    ours, the same reasoning that justified `_MALFORMED_DB_ERRORS` in
    session.py. A BLOB-typed column there comes back as `bytes`, which
    `json.dumps` rejects by default (`TypeError: Object of type bytes is
    not JSON serializable`) — and since this call happens after the
    container has already run, an uncaught TypeError here would discard
    the whole `AgentResult` and leave session.json unwritten, exactly the
    crash-on-a-schema-we-don't-control failure mode this module exists to
    avoid elsewhere. `default=str` coerces any such non-JSON-native scalar
    to its string form instead of raising.
    """
    payload = {
        "session_id": session.session_id,
        "finish_reason": session.finish_reason,
        "tool_call_count": session.tool_call_count,
        "usage": session.usage,
        "commands": [asdict(c) for c in session.commands],
    }
    (run_dir / "session.json").write_text(json.dumps(payload, indent=2, default=str))


def run_agent(spec: ContainerSpec, prompt_path, *, secret_env: dict, model: str,
              stub: StubFn | None = None) -> AgentResult:
    """Invoke the agent runtime once and return its session-derived result.

    `prompt_path` is read eagerly so a missing prompt fails loudly
    (FileNotFoundError) before any container ever starts, rather than
    Hermes silently receiving an empty query.

    `stub`, when given, is called instead of `subprocess.run` — `(argv,
    prompt_text, secret_env) -> (exit_code, stdout)` — so tests can assert
    on the exact argv and prompt without docker or a real image. Production
    callers (bin/agent-run.sh) leave it unset.
    """
    prompt_text = Path(prompt_path).read_text()   # FileNotFoundError by design
    argv = spec.to_argv() + [
        "chat", "-q", prompt_text,
        "-t", "terminal", "--yolo", "--ignore-user-config",
        "-m", model,
    ]

    if stub is not None:
        exit_code, stdout = stub(argv, prompt_text, secret_env)
    else:
        # Secret values reach docker only through this environment, never
        # argv: the subprocess gets PATH (so the docker binary can be
        # found) plus secret_env, and nothing else — no ambient host
        # secret leaks in by accident. A hard-coded "/usr/bin:/bin" was
        # tried first and broke the real verification run in this task's
        # own report: docker lives at /usr/local/bin on this host (and its
        # location varies further across CI images and Linux distros), so
        # the *real* PATH is passed through instead of a guessed one.
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   check=False,
                                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                       **secret_env})
        exit_code = completed.returncode
        stdout = completed.stdout + completed.stderr

    run_dir = _run_dir(spec)
    (run_dir / "stdout.log").write_text(stdout)

    # The transcript comes from the session store, not from stdout — see
    # module docstring. read_session never raises on an absent/malformed
    # database (e.g. the stub-only tests here, which never create one); it
    # returns EMPTY_SESSION, so succeeded correctly comes out False rather
    # than the caller crashing on what looks like a completed run.
    host_hermes_home = Path(spec.host_hermes_home)
    session = read_session(host_hermes_home / "state.db")
    (run_dir / "transcript.log").write_text(session.transcript)

    # Persist the primary evidence into run_dir BEFORE returning: a caller
    # (bin/agent-run.sh) may delete host_hermes_home the moment this
    # function returns, on success as much as on failure. See
    # _capture_state_db's docstring for why this used to be lost entirely,
    # and for why it degrades (never raises) rather than crashing run_agent.
    state_db_captured = _capture_state_db(host_hermes_home, run_dir)
    _write_session_json(run_dir, session)

    return AgentResult(
        exit_code=exit_code,
        # A run that did nothing still exits 0 (spike-findings.md §6).
        # Success is a property of the session, not of the process — see
        # session_succeeded's docstring for why BOTH conjuncts are required.
        succeeded=session_succeeded(session),
        session_id=session.session_id,
        finish_reason=session.finish_reason,
        tool_call_count=session.tool_call_count,
        transcript=session.transcript,
        usage=session.usage,
        commands=session.commands,
        stdout=stdout,
        state_db_captured=state_db_captured,
    )
