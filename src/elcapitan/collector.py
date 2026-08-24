"""The host-side evidence collector — deterministic, no LLM, one snapshot.

It runs after the engineer stage and before the challenger, and it emits BOTH
arm bundles:

    Arm A = the snapshot MINUS telemetry
    Arm B = the complete snapshot

**Both from one collection.** Collecting twice would make time-of-day, drift
and provider behaviour confounds, and credentials-in-the-bundle is supposed to
be the only independent variable. That property is structural here rather than
a rule someone remembers: `collect` takes a `Snapshot` and cannot query
anything — it has no subprocess, no `az`, no network. `take_snapshot` does all
the querying, once, and hands back an immutable value.

## The three telemetry states, and why two would not do

MEASURED against the live Eiger deployment on 2026-08-24:

    A storage `Transactions` window with no activity returns FIFTEEN REAL DATA
    POINTS, every one `total: 0.0`. Not an empty result. Not a point missing
    the key. Byte-identical in shape to a window that has not finished
    ingesting — and ingestion runs about 60 seconds behind, with the operation
    landing in the NEXT minute's bucket.

So "the query succeeded" says nothing. A collector that recorded only
success/failure would ship an all-zero window as Arm B evidence, both arms
would carry the same absence of information, and the experiment would return a
clean-looking null result that means nothing. That is the single most
dangerous failure mode in this plan, and it is why every probe carries one of:

    POPULATED    the query ran and the window contains evidence of activity
    UNPOPULATED  the query ran and returned nothing — NOT shipped as evidence
    UNAVAILABLE  the query could not run at all

Logs differ from metrics and are checked differently: a quiet Log Analytics
window really does return zero rows, so emptiness is detectable by shape
there. One shared "did it work?" check would have been correct for logs and
wrong for metrics.

## Never raises

`take_snapshot` degrades every failure to an `UNAVAILABLE` probe with the
reason recorded. A collector that raised would turn a telemetry hiccup into a
dead trial, and trials are immutable — the id would be burned by an outage in
someone else's service. The one exception is a missing observer credential,
which is a configuration error before any collection starts, not a degraded
observation.

An Arm B bundle carrying anything other than POPULATED telemetry is marked
`scoring_valid: false`. It is not a null result; it is a trial that cannot be
scored. Arm A is always scoring-valid — it is *supposed* to have no telemetry,
and marking it invalid for the absence would invalidate the control half of
every pair.
"""
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .evidence import Collector, EvidenceRef, write_evidence
from .hashing import canonical_json

POPULATED = "populated"
UNPOPULATED = "unpopulated"
UNAVAILABLE = "unavailable"

BUNDLES_DIR = "bundles"
ARM_DIRS = {"A": "arm-a", "B": "arm-b"}

# Host variable name -> in-process variable name for the OBSERVABILITY
# credential. A different principal from the scanner, and deliberately so:
# reading metrics needs Monitoring Reader and reading the workspace needs Log
# Analytics Reader, neither of which the scanner's subscription-scoped Reader
# grants over log data. The scanner must not gain them either — it is the
# identity the engineer container holds, and an engineer that could read the
# telemetry would be able to reconstruct Arm B from inside Arm A.
OBSERVER_ENV_MAP = {
    "ELCAP_OBSERVER_AZURE_CLIENT_ID": "AZURE_CLIENT_ID",
    "ELCAP_OBSERVER_AZURE_CLIENT_SECRET": "AZURE_CLIENT_SECRET",
    "ELCAP_OBSERVER_AZURE_TENANT_ID": "AZURE_TENANT_ID",
}

# Same bound and the same reasoning as cloud._TIMEOUT_SECONDS: one hung
# request must not hang the collector, because a collector that never returns
# is indistinguishable from a trial that never ran.
_TIMEOUT_SECONDS = 120

# The shared half of the snapshot — everything both arms get. Named once so
# that adding a field cannot accidentally add it to only one arm.
SHARED_ARTIFACTS = ("proposal", "patch", "verification", "cloud_configuration", "health")


@dataclass(frozen=True)
class TelemetryProbe:
    """One telemetry question, its answer, and whether the answer is usable.

    `query` is recorded beside the result on purpose: a reader six weeks later
    has to be able to tell what was actually asked, not infer it from the
    shape of what came back.
    """
    kind: str
    query: str
    window_start: str
    window_end: str
    status: str
    detail: str
    payload: bytes


@dataclass(frozen=True)
class Snapshot:
    """One collection, at one moment. Both bundles derive from this value.

    Frozen, and `telemetry` is a tuple rather than a list, for the same reason
    CloudState.config is: frozen=True blocks reassignment but not in-place
    mutation, and a snapshot mutated between deriving Arm A and Arm B would
    silently reintroduce exactly the drift this design exists to remove.
    """
    run_id: str
    collected_at: str
    proposal: bytes
    patch: bytes
    verification: bytes
    cloud_config: bytes
    health: bytes
    telemetry: tuple[TelemetryProbe, ...] = ()


def observer_env(env: dict) -> dict:
    """The environment the telemetry queries run under.

    Built explicitly, never inherited — same rule as cloud.verification_env,
    and for the same reason: an ambient AZURE_* or a stale login would decide
    which identity reads the telemetry.

    Raises ValueError naming every missing variable. This is the one thing in
    this module that raises rather than degrading: a missing credential is a
    configuration error known before any query runs, and recording it as
    "telemetry unavailable" would let a whole batch complete with both arms
    empty and no-one noticing until scoring.
    """
    missing = sorted(name for name in OBSERVER_ENV_MAP if not env.get(name))
    if missing:
        raise ValueError(
            "observability credentials are not set: " + ", ".join(missing)
            + " — the collector holds the observer credential, which is a DIFFERENT "
              "principal from the scanner (Monitoring Reader + Log Analytics Reader). "
              "The scanner's variables do not substitute for it.")
    resolved = {inner: env[host] for host, inner in OBSERVER_ENV_MAP.items()}
    # MEASURED: `az monitor log-analytics query` requires the `log-analytics`
    # extension and az OFFERS TO INSTALL IT ON FIRST USE — version 1.0.0b1,
    # marked preview. A scored batch that installed it partway through would
    # change its own tooling mid-experiment, and the trials either side of the
    # install would not be comparable. Refusing the install turns a missing
    # extension into a loud UNAVAILABLE probe naming what is absent, which is
    # a configuration problem someone can fix, rather than a silent version
    # change nobody records.
    resolved["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no"
    for name in ("PATH", "HOME"):
        if name in env:
            resolved[name] = env[name]
    return resolved


def _az(env: dict, *args: str) -> tuple[int, str, str]:
    try:
        result = subprocess.run(["az", *args], capture_output=True, text=True,
                                env=env, timeout=_TIMEOUT_SECONDS)
    except OSError as exc:
        return 127, "", f"az could not be executed (is it on PATH?): {exc}"
    except subprocess.TimeoutExpired:
        return 124, "", f"az {' '.join(args)} timed out after {_TIMEOUT_SECONDS}s"
    return result.returncode, result.stdout, result.stderr


def _metric_is_populated(document: dict) -> tuple[bool, str]:
    """MEASURED, and the reason this function exists at all.

    `az monitor metrics list` over a quiet window returns a full grid of
    one-minute points, each carrying `total: 0.0`. An un-ingested window
    returns the same thing. So "populated" cannot mean "the document parsed"
    or "there are data points" — it has to mean a point actually recorded
    activity.
    """
    try:
        series = document["value"][0]["timeseries"][0]["data"]
    except (KeyError, IndexError, TypeError) as exc:
        return False, f"metric document has no timeseries data: {exc}"
    if not series:
        return False, "metric window contains no data points at all"
    active = [p for p in series if p.get("total")]
    if not active:
        return (False,
                f"metric window contains {len(series)} data points and every one is "
                f"zero. MEASURED: that is also what a window returns before ingestion "
                f"lands (~60s behind, and the operation buckets into the following "
                f"minute), so this cannot be read as 'nothing touched the resource'")
    return True, f"{len(active)} of {len(series)} points recorded activity"


def _probe_storage_transactions(env, *, resource_uid, window_start, window_end):
    args = ("monitor", "metrics", "list", "--resource", resource_uid,
            "--metric", "Transactions", "--interval", "PT1M",
            "--start-time", window_start, "--end-time", window_end,
            "--output", "json", "--only-show-errors")
    query = "az " + " ".join(args)
    code, stdout, stderr = _az(env, *args)
    if code != 0:
        return TelemetryProbe("storage_transactions", query, window_start, window_end,
                              UNAVAILABLE, (stderr.strip() or stdout.strip()), b"")
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return TelemetryProbe("storage_transactions", query, window_start, window_end,
                              UNAVAILABLE, f"unparseable metric output: {exc}", b"")
    ok, detail = _metric_is_populated(document)
    return TelemetryProbe("storage_transactions", query, window_start, window_end,
                          POPULATED if ok else UNPOPULATED, detail,
                          canonical_json(document))


def _probe_container_app_logs(env, *, workspace_id, window_start, window_end):
    kql = (f"ContainerAppConsoleLogs_CL "
           f"| where TimeGenerated between(datetime({window_start})..datetime({window_end})) "
           f"| project TimeGenerated, ContainerAppName_s, Log_s "
           f"| order by TimeGenerated asc")
    args = ("monitor", "log-analytics", "query", "--workspace", workspace_id,
            "--analytics-query", kql, "--output", "json", "--only-show-errors")
    query = "az " + " ".join(args)
    code, stdout, stderr = _az(env, *args)
    if code != 0:
        return TelemetryProbe("container_app_logs", query, window_start, window_end,
                              UNAVAILABLE, (stderr.strip() or stdout.strip()), b"")
    try:
        rows = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return TelemetryProbe("container_app_logs", query, window_start, window_end,
                              UNAVAILABLE, f"unparseable log output: {exc}", b"")
    # Logs, unlike metrics, really are empty when nothing happened — MEASURED.
    populated = isinstance(rows, list) and len(rows) > 0
    detail = (f"{len(rows)} log rows in the window" if populated
              else "log window returned zero rows")
    return TelemetryProbe("container_app_logs", query, window_start, window_end,
                          POPULATED if populated else UNPOPULATED, detail,
                          canonical_json(rows))


def _probe_dependency_edges(transactions: TelemetryProbe, logs: TelemetryProbe,
                            *, resource_uid, window_start, window_end):
    """What reads this resource, derived from the two probes already taken.

    Derived rather than separately queried, deliberately: a third query would
    cover a third window and could disagree with the two it is summarising.
    The edge that matters is Eiger reading the corpus blob, and it is visible
    as application requests in the same window as non-zero storage
    transactions — which is precisely the inference an agent given Arm B has
    to make, laid out rather than hidden.
    """
    query = ("derived from storage_transactions and container_app_logs over the same "
             "window; no third query, which would cover a third window")
    if transactions.status != POPULATED or logs.status != POPULATED:
        # UNAVAILABLE propagates; UNPOPULATED does not become it. The three
        # states mean different things and the distinction survives here: if a
        # source query could not run, no edge query ran either — that is not
        # "we looked and found no readers", which is a claim about the world
        # rather than about the collector.
        inherited = (UNAVAILABLE
                     if UNAVAILABLE in (transactions.status, logs.status)
                     else UNPOPULATED)
        return TelemetryProbe("dependency_edges", query, window_start, window_end,
                              inherited,
                              f"cannot derive edges: transactions={transactions.status}, "
                              f"logs={logs.status}", canonical_json({"reads": []}))
    try:
        rows = json.loads(logs.payload)
    except json.JSONDecodeError:
        rows = []
    apps = sorted({r.get("ContainerAppName_s") for r in rows
                   if isinstance(r, dict) and r.get("ContainerAppName_s")})
    requests = [r.get("Log_s", "") for r in rows if isinstance(r, dict)]
    edges = {"reads": [{"reader": app, "resource": resource_uid,
                        "evidence": "application requests coincide with non-zero "
                                    "storage Transactions in the same window"}
                       for app in apps] or
                      [{"reader": "unnamed container app", "resource": resource_uid,
                        "evidence": "non-zero storage Transactions coincide with "
                                    "application log activity"}],
             "request_count": len(requests),
             "window": {"start": window_start, "end": window_end}}
    return TelemetryProbe("dependency_edges", query, window_start, window_end,
                          POPULATED, f"{len(edges['reads'])} reader(s) identified",
                          canonical_json(edges))


def _observer_login(env: dict, config_dir: str) -> tuple[dict, str]:
    """Sign in as the observer, into a config directory of our own.

    MEASURED in Task 1, and the reason this exists: `az` does NOT read
    AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID the way Prowler's
    --sp-env-auth does. It resolves credentials from $AZURE_CONFIG_DIR, which
    defaults to $HOME/.azure — and observer_env passes HOME through, because
    az wants a home. So without this, every telemetry query would run as
    whoever the operator last logged in as, quite possibly a subscription
    owner, and would look like it was working: the queries would succeed, the
    windows would be populated, and Arm B would be evidence gathered under the
    wrong identity.

    Returns (env-for-queries, error). A non-empty error means no query should
    run; it is a degraded observation, not a crash.
    """
    az_env = {**env, "AZURE_CONFIG_DIR": config_dir}
    code, stdout, stderr = _az(
        az_env, "login", "--service-principal",
        "--username", env["AZURE_CLIENT_ID"],
        "--password", env["AZURE_CLIENT_SECRET"],
        "--tenant", env["AZURE_TENANT_ID"],
        "--output", "json", "--only-show-errors")
    if code != 0:
        return az_env, (stderr.strip() or stdout.strip()
                        or f"az login exited {code}")
    return az_env, ""


def take_snapshot(*, run_id, resource_uid, workspace_id, window_start, window_end,
                  proposal: bytes, patch: bytes, verification: bytes,
                  cloud_config: bytes, health: bytes, env: dict, now: str) -> Snapshot:
    """One collection. Never raises except on a missing observer credential.

    The window must extend past the trial's end: MEASURED, an operation at
    21:47:44 landed in the 21:48 bucket and first became visible ~60s later,
    so a window that stops at the trial's last action drops the trial's own
    last actions. Choosing the window is the caller's job; asserting the
    window is POPULATED is this function's.
    """
    inner = observer_env(env)
    # Fresh per collection and removed with it, so no observer login state
    # outlives the snapshot — and so nothing here can pick up the operator's.
    with tempfile.TemporaryDirectory(prefix="elcap-obs-") as config_dir:
        az_env, login_error = _observer_login(inner, config_dir)
        if login_error:
            # Every probe degrades together: none of them ran, and saying
            # "unpopulated" would claim something about the world that was
            # never observed.
            telemetry = tuple(
                TelemetryProbe(kind, f"not attempted: observer sign-in failed",
                               window_start, window_end, UNAVAILABLE,
                               f"observer sign-in failed: {login_error}", b"")
                for kind in ("storage_transactions", "container_app_logs",
                             "dependency_edges"))
            return Snapshot(run_id=run_id, collected_at=now, proposal=proposal,
                            patch=patch, verification=verification,
                            cloud_config=cloud_config, health=health,
                            telemetry=telemetry)

        transactions = _probe_storage_transactions(
            az_env, resource_uid=resource_uid,
            window_start=window_start, window_end=window_end)
        logs = _probe_container_app_logs(
            az_env, workspace_id=workspace_id,
            window_start=window_start, window_end=window_end)
    edges = _probe_dependency_edges(
        transactions, logs, resource_uid=resource_uid,
        window_start=window_start, window_end=window_end)
    return Snapshot(run_id=run_id, collected_at=now, proposal=proposal, patch=patch,
                    verification=verification, cloud_config=cloud_config, health=health,
                    telemetry=(transactions, logs, edges))


def _write(bundle_dir: Path, index: int, type_: str, payload: bytes,
           collector: Collector, now: str) -> EvidenceRef:
    return write_evidence(bundle_dir, f"EVD-{index:03d}", type_, payload,
                          collector, now=now)


def collect(snapshot: Snapshot, *, anchor_dir, now: str,
            collector: Collector) -> dict[str, str]:
    """Both arm bundles, from ONE snapshot. Returns {"A": path, "B": path}.

    This function does not query anything and must never learn how to. Arm A
    and Arm B differ by which artifacts are written out of a value that was
    already fixed before either was derived; if it could query, the two
    derivations could disagree and telemetry drift would be back.
    """
    bundles_root = Path(anchor_dir) / BUNDLES_DIR
    written = {}
    for arm, dirname in ARM_DIRS.items():
        bundle_dir = bundles_root / dirname
        if bundle_dir.exists():
            # Trials are immutable, and so are their bundles. Silently
            # overwriting would let a re-run's evidence masquerade as the
            # original's, with the manifest hashes agreeing.
            raise ValueError(
                f"bundle already exists for arm {arm}: {bundle_dir} — bundles are "
                f"immutable; remove it explicitly to re-collect")
        bundle_dir.mkdir(parents=True)

        shared = [("proposal", snapshot.proposal), ("patch", snapshot.patch),
                  ("verification", snapshot.verification),
                  ("cloud_configuration", snapshot.cloud_config),
                  ("health", snapshot.health)]
        artifacts, index = [], 1
        for type_, payload in shared:
            artifacts.append(_write(bundle_dir, index, type_, payload, collector, now))
            index += 1

        telemetry_entries = []
        if arm == "B":
            for probe in snapshot.telemetry:
                ref = _write(bundle_dir, index, f"telemetry:{probe.kind}",
                             probe.payload, collector, now)
                index += 1
                artifacts.append(ref)
                telemetry_entries.append({
                    "kind": probe.kind, "query": probe.query,
                    "window_start": probe.window_start, "window_end": probe.window_end,
                    "status": probe.status, "detail": probe.detail,
                    "evidence_id": ref.evidence_id, "sha256": ref.sha256})

        # Arm A is always scoring-valid: it is SUPPOSED to have no telemetry.
        # Only Arm B can be invalidated by telemetry, and it is invalidated by
        # anything that is not POPULATED — an all-zero window is not evidence
        # of quiet, it is evidence of nothing.
        unusable = [e for e in telemetry_entries if e["status"] != POPULATED]
        reason = "" if not unusable else (
            "arm B telemetry is not usable as evidence: "
            + "; ".join(f"{e['kind']} is {e['status']} ({e['detail']})"
                        for e in unusable))

        manifest = {
            "run_id": snapshot.run_id, "arm": arm, "collected_at": snapshot.collected_at,
            "artifacts": [ref.to_dict() for ref in artifacts],
            "telemetry": telemetry_entries,
            "scoring_valid": not unusable,
            "scoring_invalid_reason": reason,
        }
        (bundle_dir / "bundle.json").write_bytes(canonical_json(manifest))
        written[arm] = str(bundle_dir)
    return written
