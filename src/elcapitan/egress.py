"""The challenger's egress boundary: the model endpoint, and nothing else.

## Why this exists

`challenger_spec` used to say `network="none"`, the plan restated it, and the
spec never addressed the contradiction: the challenger is a **model-backed
agent**. It has to reach `api.anthropic.com`. MEASURED 2026-08-24 — with no
network the container starts, the prompt arrives, and then:

    ⚠️  API call failed (attempt 3/3): APIConnectionError
    ❌ API failed after 3 retries — Connection error.

Exit code **0**, `tool_call_count: 0`, `usage: {}`, no verdict. The
false-green shape this project keeps finding.

## What `--network=none` was really protecting

Not "no network" for its own sake. The property that matters is that **the
challenger cannot fetch evidence** — it judges the bundle it was handed rather
than going to look for more. Two mechanisms enforce that here, and either
alone would be weaker than it appears:

1. **The network is `--internal`.** Docker gives it no route off the host, so
   a challenger that ignored every proxy variable still has nowhere to go.
2. **One proxy, one allowlisted host.** The model endpoint over CONNECT :443,
   and nothing else.

The first without the second would let the challenger reach anything the
proxy could. The second without the first would be a suggestion — proxy
variables are environment, and environment is advice.

## What this does not claim

The challenger can still reach the model provider, and a model provider is a
general-purpose thing. This bounds what the CONTAINER can fetch; it does not
bound what the model already knows. That is fine and is true of both arms
equally — the independent variable is what is in the bundle, not what is in
the weights.
"""
import json
import subprocess
import time
from contextlib import contextmanager

NETWORK_NAME = "elcapitan-challenger"
PROXY_NAME = "elcapitan-egress"
PROXY_IMAGE = "elcapitan-egress:0.1.0"
PROXY_PORT = 8888

# The only host the challenger may reach. Adding an entry widens the boundary
# this module exists to hold, so it is a tuple in source rather than a
# configurable — a scored batch must not be able to relax it from the outside.
# It is duplicated in docker/egress-proxy/filter, which is what actually
# enforces it; the test suite asserts on this tuple, and the smoke test
# asserts on the enforcement.
ALLOWED_HOSTS = ("api.anthropic.com",)

_DOCKER_TIMEOUT = 120


def proxy_env(proxy_host: str) -> dict:
    """The proxy variables the challenger container gets.

    Both cases are set deliberately. `httpx` — which the anthropic SDK uses —
    reads the lowercase forms, other tooling reads the uppercase, and which
    one wins is exactly the kind of thing that produces a challenger that
    silently has no route and returns no verdict.
    """
    url = f"http://{proxy_host}:{PROXY_PORT}"
    return {"HTTPS_PROXY": url, "HTTP_PROXY": url,
            "https_proxy": url, "http_proxy": url,
            # Without this, a request to the container's own name or to
            # localhost would bypass the proxy. Nothing in a trial needs that,
            # and an unexplained bypass rule is a hole nobody remembers.
            "NO_PROXY": "localhost,127.0.0.1"}


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            timeout=_DOCKER_TIMEOUT)
    if check and result.returncode != 0:
        raise ValueError(f"docker {' '.join(args)} failed ({result.returncode}): "
                         f"{result.stderr.strip() or result.stdout.strip()}")
    return result


def proxy_image_exists() -> bool:
    return _docker("image", "inspect", PROXY_IMAGE, check=False).returncode == 0


def build_proxy_image(context_dir) -> str:
    _docker("build", "-t", PROXY_IMAGE, str(context_dir))
    return PROXY_IMAGE


def _network_exists() -> bool:
    return _docker("network", "inspect", NETWORK_NAME, check=False).returncode == 0


def ensure_network() -> str:
    """An INTERNAL docker network — no route off the host.

    `--internal` is the half that does not depend on the challenger
    cooperating. Proxy variables are environment, and a container is free to
    ignore its environment; a network with no gateway is not negotiable.
    """
    if not _network_exists():
        _docker("network", "create", "--internal", NETWORK_NAME)
    inspected = json.loads(_docker("network", "inspect", NETWORK_NAME).stdout)
    if not inspected[0].get("Internal"):
        # A pre-existing network with the right name and the wrong properties
        # would silently give the challenger a route out.
        raise ValueError(
            f"docker network {NETWORK_NAME} exists but is NOT internal, so the "
            f"challenger would have a route to the internet that bypasses the "
            f"allowlist entirely. Remove it: docker network rm {NETWORK_NAME}")
    return NETWORK_NAME


@contextmanager
def egress_network(*, proxy_image: str = PROXY_IMAGE):
    """Stand up the network and the proxy; tear both down afterwards.

    Yields the proxy's hostname on the internal network, which is what
    `proxy_env` needs.

    The proxy is attached to TWO networks: the internal one, where the
    challenger can reach it, and the default bridge, which is where its own
    egress comes from. That asymmetry is the whole design — the proxy has a
    route out and the challenger does not, so everything the challenger
    reaches has passed the allowlist.
    """
    ensure_network()
    # A leftover from a killed run would make `docker run --name` fail, and a
    # trial should not die because a previous one was interrupted.
    _docker("rm", "-f", PROXY_NAME, check=False)
    _docker("run", "-d", "--name", PROXY_NAME, "--network", "bridge",
            "--restart", "no", proxy_image)
    try:
        _docker("network", "connect", "--alias", PROXY_NAME, NETWORK_NAME, PROXY_NAME)
        _wait_for_proxy()
        yield PROXY_NAME
    finally:
        _docker("rm", "-f", PROXY_NAME, check=False)


def _wait_for_proxy(attempts: int = 30) -> None:
    """Block until the proxy answers, or say so.

    Without this the challenger races the proxy's startup and loses
    intermittently — and it loses by getting a connection error, which is
    indistinguishable from the no-network failure this module was written to
    fix. A flaky version of the original bug is worse than the original bug.
    """
    for _ in range(attempts):
        probe = _docker("exec", PROXY_NAME, "sh", "-c",
                        f"nc -z 127.0.0.1 {PROXY_PORT} || wget -q -T 1 -O /dev/null "
                        f"http://127.0.0.1:{PROXY_PORT} 2>/dev/null; echo $?",
                        check=False)
        if probe.returncode == 0 and probe.stdout.strip().endswith("0"):
            return
        time.sleep(1)
    raise ValueError(
        f"the egress proxy {PROXY_NAME} did not start listening on {PROXY_PORT}. "
        f"A challenger started now would fail with a connection error that looks "
        f"exactly like having no network at all.")
