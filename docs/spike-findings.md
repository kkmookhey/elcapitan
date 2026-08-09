# Task 0 Spike — Hermes image and invocation

**Date:** 2026-08-09
**Image:** `nousresearch/hermes-agent:v2026.8.3` (release "Hermes Agent v0.20.0")
**Status:** all six questions answered. Two findings change the plan; see §7.

Every command below was run against the real image. Nothing here is inferred
from documentation.

---

## 1. Base image identity

```
base_image_ref     nousresearch/hermes-agent
base_image_digest  sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e
tag                v2026.8.3
size               957 MB
entrypoint         /opt/hermes/docker/entrypoint-dispatch.sh
config user        root  (drops to `hermes`, uid 10000, via s6-setuidgid)
```

Resolved with:
```bash
gh release list --repo NousResearch/hermes-agent --limit 5
docker pull nousresearch/hermes-agent:v2026.8.3
docker image inspect nousresearch/hermes-agent:v2026.8.3 --format '{{index .RepoDigests 0}}'
```

Tag list came from the Docker Hub v2 API. `latest` and `main` both move; `v2026.8.3`
is the newest immutable tag and matches the v0.20.0 release.

## 2. Working non-interactive invocation

```bash
docker run --rm \
  -v <host-hermes-home>:/opt/data \
  -v <host-run-dir>:/work/run \
  -e ANTHROPIC_API_KEY \
  nousresearch/hermes-agent:v2026.8.3 \
  chat -q "<prompt>" \
  -t terminal --yolo --max-turns 10 -m anthropic/claude-sonnet-5
```

Verified end to end: the agent ran a shell command, wrote `/work/run/out.txt`, and the
file contained the correct answer.

**There is no `--prompt-file`.** The prompt is the `-q` value. Argument routing is in
`/opt/hermes/docker/main-wrapper.sh`: no args → `hermes`; first arg is an executable →
exec it; anything else → `hermes <args>`.

Flags that matter, from `hermes chat --help`:

| Flag | Effect |
|---|---|
| `-q, --query` | single query, non-interactive |
| `-m, --model` | e.g. `anthropic/claude-sonnet-5` (normalised to `claude-sonnet-5`) |
| `-t, --toolsets` | comma-separated; **terminal tools are off unless requested** |
| `--yolo` | bypasses dangerous-command approval — required headless, and a deliberate reduction of a defence layer |
| `--max-turns N` | default 500 |
| `--ignore-user-config` | fall back to built-in defaults; credentials in `.env` still load |
| `-Q, --quiet` | suppresses banner, spinner **and tool previews** — do not use |
| `--reasoning LEVEL` | none…ultra |

## 3. Transcript and usage metadata — **stdout is not the transcript**

The `-q` stdout tool preview is truncated and unusable as evidence:

```
  ┊ 💻 $         mkdir -p /work/run + 3 commands  0.0s
```

It names one fragment, hides the rest, and shows no output and no exit codes. The plan
requires citing commands, exit codes, and raw output.

**The real record is `/opt/data/state.db` (SQLite).** `sessions/` stays empty; everything
goes to the DB. Relevant tables: `messages`, `sessions`, `session_model_usage`,
`system_prompts`.

The assistant message's `tool_calls` column carries the actual command:

```json
[{"id":"toolu_…","type":"function","function":{"name":"terminal",
  "arguments":"{\"command\": \"mkdir -p /work/run && n=$(find /work/run -maxdepth 1 -type f | wc -l) && echo -n \\\"$n\\\" > /work/run/out.txt && cat /work/run/out.txt\"}"}}]
```

and the tool message's `content` carries the result, already structured:

```json
{"output": "3", "exit_code": 0, "error": null}
```

`messages` columns include `role, content, tool_call_id, tool_calls, tool_name,
timestamp, token_count, finish_reason, reasoning`.

**The `--usage-file` conflict is a non-issue.** `--usage-file` is `-z`-only, and `-z`
suppresses tool output — but token accounting does not need it. `session_model_usage`
records per session: `model, billing_provider, api_call_count, input_tokens,
output_tokens, cache_read_tokens, cache_write_tokens, reasoning_tokens,
estimated_cost_usd, cost_status, cost_source`. Observed for the test run:
`claude-sonnet-5 / anthropic / 2 api calls / 4 in / 147 out / 4669 cache-read /
4810 cache-write / $0.0144368 estimated`.

So `chat -q` + `state.db` gives transcript **and** usage together. The plan's stated
tension does not exist.

## 4. Minimum `/opt/data` contents

**None.** An empty directory is sufficient. On first run the image creates the full
tree itself — `config.yaml` (~90 KB of defaults), `state.db`, `logs/`, `memories/`,
`sessions/`, `skills/`, `cron/`, `hooks/`, and ~20 more — and syncs 71 bundled skills.

`hermes setup` is **not** required, so Task 2's baseline home can be generated
non-interactively: run the container once against an empty directory, then sanitise
the result.

One warning appears on a fresh home and is cosmetic:
`[config-migrate] WARNING: This config predates version 12 … run hermes setup to regenerate`.

## 5. `--user` — confirmed unsupported

`docker run --user 1000:1000 …` → **exit 1**, with an explicit error:

```
[hermes] ERROR: container started with --user 1000 (an arbitrary, non-hermes UID) — not supported.
    docker run -e HERMES_UID=$(id -u) -e HERMES_GID=$(id -g) ...
```

The guard lives in both `main-wrapper.sh` and `stage2-hook.sh`. `container.py` already
emits no `--user`; that is correct and must stay.

**Newly discovered, not in the plan:** the image chowns `/opt/data` to uid 10000
(`[stage2] Fixing ownership of /opt/data (targeted) to hermes (10000)`). On macOS the
Docker Desktop filesystem layer masks this. **On Linux the host validator would face
files owned by uid 10000.** The supported fix is `-e HERMES_UID=$(id -u) -e
HERMES_GID=$(id -g)`, which remaps the hermes user at boot. Task 11 should pass these.

## 6. Exit codes — **exit 0 does not mean success**

| Scenario | Exit |
|---|---|
| Successful run with a tool call | 0 |
| **No API key configured — no work done** | **0** |
| **Invalid model, 9 consecutive HTTP 404s** | **0** |
| `--user 1000` (rejected before start) | 1 |

Only the pre-start guard exits non-zero. A total API failure exits 0, prints its errors
to stdout, and still writes a `sessions` row.

## 7. What this changes in the plan

**7.1 — Task 11's shim cannot use the process exit code as the success signal.**
`run_agent` currently returns `exit_code` and the harness treats it as the verdict. As
measured, a run that did nothing at all returns 0. Success must be derived from the
session record: `finish_reason == "stop"`, a non-zero `tool_call_count`, and the
expected artifacts on disk. The host-side validator is unaffected — it already judges
artifacts rather than exit status, which turns out to have been the right call for a
reason nobody anticipated.

**7.2 — Task 11 must extract the transcript from `state.db`, not capture stdout.**
`AgentResult.transcript` should be built from `messages` (with `tool_calls` and the
tool responses' `output`/`exit_code`), and the usage row should be carried into
`TrialResult.trial` alongside the model and version. Capturing stdout as well is
harmless and useful for debugging, but it is not evidence.

This also *improves* the design: the `CommandRecord` schema already requires
`command_id, tool, argv, exit_code, started_at, completed_at, stdout_evidence_id,
stderr_evidence_id`, and `state.db` supplies command text, exit code and timestamps
directly — closer to the schema than a scraped terminal stream would ever be.

**7.3 — Smaller items.** Pass `HERMES_UID`/`HERMES_GID` for Linux portability. Record
`--yolo` as a deliberately disabled defence layer in the risk register. Note the
observed startup warning `tirith security scanner enabled but not available — command
scanning will use pattern matching only`: the image ships with its command scanner
degraded, so approval-policy protections are weaker than the docs imply. Irrelevant
under `--yolo`, but it belongs in the risk register.

## 8. Values for `runtime.lock.json` (Task 1b)

```json
{
  "base_image_ref": "nousresearch/hermes-agent",
  "base_image_digest": "sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e",
  "base_image_tag": "v2026.8.3",
  "hermes_version": "0.20.0"
}
```

`runtime_image_ref`, `runtime_image_id` and `dockerfile_sha256` remain to be filled by
Task 1b once the derived image is built.
