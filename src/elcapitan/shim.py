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
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .container import ContainerSpec
from .session import read_session

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
    stdout: str                 # kept for debugging only; not evidence


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
    session = read_session(Path(spec.host_hermes_home) / "state.db")
    (run_dir / "transcript.log").write_text(session.transcript)

    return AgentResult(
        exit_code=exit_code,
        # A run that did nothing still exits 0 (spike-findings.md §6).
        # Success is a property of the session, not of the process.
        succeeded=(session.finish_reason == "stop" and session.tool_call_count > 0),
        session_id=session.session_id,
        finish_reason=session.finish_reason,
        tool_call_count=session.tool_call_count,
        transcript=session.transcript,
        usage=session.usage,
        stdout=stdout,
    )
