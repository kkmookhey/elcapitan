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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .container import ContainerSpec
from .session import CommandRecord, read_session, session_succeeded

StubFn = Callable[[list[str], str, dict], tuple[int, str]]

# Host variable name -> in-container variable name. An explicit map, not a
# prefix-strip, so ELCAP_SCANNER_AWS_ACCESS_KEY_ID on the host becomes
# AWS_ACCESS_KEY_ID inside the container — the name AWS tooling actually
# looks for — and the ELCAP_ prefix is never applied twice or left on by
# accident.
SCANNER_ENV_MAP = {
    "ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
    "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
    "ELCAP_SCANNER_AWS_SESSION_TOKEN": "AWS_SESSION_TOKEN",
}
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


def _capture_state_db(host_hermes_home: Path, run_dir: Path) -> bool:
    """Copy state.db into the run directory — the persistent evidence bundle
    — before anything can delete the ephemeral Hermes home it came from.

    Returns True if state.db was actually captured, False otherwise (no
    source to capture, or the capture itself failed). Recorded on
    `AgentResult.state_db_captured` rather than left for a caller to infer
    by checking run_dir's filesystem directly.

    This exists because bin/agent-run.sh deletes any host_hermes_home it
    seeded itself, on EXIT, on success as much as on failure (nothing else
    owns that ephemeral directory's lifecycle). Before this function
    existed, that meant state.db — this module's own docstring calls it
    "the real record" — was gone the moment a successful run finished: a
    real, reviewed defect in this task, not a hypothetical one. Capturing
    it here, inside run_agent itself, fixes it for every caller, not just
    agent-run.sh, and fixes it before the caller's own cleanup can ever run
    (run_agent returns before bin/agent-run.sh's `trap cleanup EXIT` fires).

    Uses sqlite3's backup API, NOT a byte-level file copy. Hermes's
    state.db runs in WAL mode and is never checkpointed by anything this
    shim controls, so the main .db file on its own can be a near-empty
    husk (observed: 4096 bytes, zero tables) with every actual row sitting
    in the uncopied state.db-wal sidecar — a plain `shutil.copy2` of just
    the main file was tried first and confirmed, against a real run, to
    silently archive an empty database while `session.json` right next to
    it correctly reported `succeeded: true`. `Connection.backup()` reads
    through the source connection (WAL included — a read-only connection
    still consults the WAL when present) and writes a single, complete,
    already-checkpointed copy in one call; there is no intermediate state
    where a second file (a `-wal` sidecar of the destination) would need
    to be copied alongside it, so the result can't be torn.

    The read-only URI is built with `Path.as_uri()`, not an f-string. An
    f-string (`f"file:{source}?mode=ro"`) leaves any `?`/`#` in
    `host_hermes_home` unescaped — both `run_dir` and `host_hermes_home`
    are caller-supplied argv in bin/agent-run.sh. Measured against a path
    containing a literal `?`: the unescaped form connects successfully to
    the WRONG resource (SQLite reads everything before the first bare `?`
    as the path and everything after as query parameters), completes with
    no exception, and writes a 4096-byte destination with an empty
    `sqlite_master` — a *second*, silent route to the exact F1 symptom.
    `as_uri()` percent-encodes `?` (confirmed: `Path("/tmp/weird?dir/x").as_uri()`
    -> `.../weird%3Fdir/x`), so it names the real file regardless of what
    characters are in the path.

    A source that doesn't exist (a stub test, or a real run that never got
    far enough to write anything) is not an error — read_session already
    degrades to EMPTY_SESSION for that case, and this degrades the same way.

    A source that EXISTS but backup() fails — locked, truncated, corrupt,
    not a SQLite file at all, or run_dir not writable — must ALSO degrade
    rather than raise. `read_session` succeeding moments earlier in the
    same `run_agent` call proves nothing about this: `read_session`'s own
    contract is to catch exactly this exception class and return
    EMPTY_SESSION, so a successful *return* from it is exactly as
    consistent with "the database is fine" as with "the database is
    garbage." Letting the exception escape here instead of degrading would
    be a regression past the original F1 bug, not a fix past it: F1 lost
    only the archive; an uncaught exception here crashes `run_agent`,
    discarding the whole `AgentResult` (so `session.json` never gets
    written either) — and self-defeatingly, since an exception out of
    `run_agent` still reaches bin/agent-run.sh's `trap cleanup EXIT`, which
    deletes `host_hermes_home` regardless of how `run_agent` exited,
    destroying the very evidence this function exists to preserve. Any
    partial destination file `sqlite3.connect(dest)` may already have
    created before the failure is removed — a stale 0-byte `state.db`
    would be misreadable as "captured successfully but genuinely empty"
    rather than "capture failed," which `state_db_captured=False` states
    unambiguously instead.
    """
    source = host_hermes_home / "state.db"
    if not source.is_file():
        return False
    dest = run_dir / "state.db"
    try:
        # Read-only source, same guarantee session.py's own reader already
        # established: the host must never write to an artifact the agent
        # produced.
        source_con = sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True)
        try:
            dest_con = sqlite3.connect(dest)
            try:
                source_con.backup(dest_con)
            finally:
                dest_con.close()
        finally:
            source_con.close()
    except (sqlite3.Error, OSError, ValueError):
        dest.unlink(missing_ok=True)
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
