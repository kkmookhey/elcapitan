"""elcapitan.egress — the challenger reaches the model and nothing else.

`--network=none` was the original design and it cannot work: the challenger is
a model-backed agent, so it must reach `api.anthropic.com`. MEASURED
2026-08-24 — the container starts, the prompt arrives, and then three
`APIConnectionError` retries, exit code **0**, `tool_call_count: 0`, no
verdict. The false-green shape.

What `--network=none` was actually protecting is narrower than "no network":
the challenger must not be able to fetch EVIDENCE. It must judge the bundle it
was handed, not go looking. So the network is replaced by an allowlist — an
internal docker network with no route out, plus one proxy that permits exactly
the model endpoint.

**The load-bearing test here is
test_a_non_allowlisted_host_is_actually_blocked, and it is measured against
real docker.** An allowlist nobody tested against a real denied host is a
configuration file, not a guarantee — and this project's dominant defect class
is exactly the check that passes against a synthetic artifact. The companion
test proves the allowed host still works, because an egress policy that blocks
everything would also produce a green suite and a challenger that never runs.
"""
import json
import os
import subprocess

import pytest

from elcapitan.egress import (
    ALLOWED_HOSTS,
    PROXY_PORT,
    egress_network,
    proxy_env,
)

SMOKE = pytest.mark.skipif(os.environ.get("ELCAP_SMOKE") != "1",
                           reason="set ELCAP_SMOKE=1 to run docker egress tests")


# --- the pure parts ---------------------------------------------------------

def test_the_allowlist_is_exactly_the_model_endpoint():
    # A second entry here widens what the challenger can reach, which is the
    # one thing this module exists to bound. It should be hard to do quietly.
    assert ALLOWED_HOSTS == ("api.anthropic.com",)


def test_proxy_env_points_the_sdk_at_the_proxy():
    env = proxy_env("elcapitan-egress")
    assert env["HTTPS_PROXY"] == f"http://elcapitan-egress:{PROXY_PORT}"
    assert env["HTTP_PROXY"] == env["HTTPS_PROXY"]
    # httpx (which the anthropic SDK uses) reads the lowercase forms too, and
    # which one wins has bitten enough people to be worth setting both.
    assert env["https_proxy"] == env["HTTPS_PROXY"]


def test_proxy_env_carries_no_credential():
    # The proxy is a route, not an identity. A credential here would travel to
    # the challenger, which is the one container that must hold none.
    for value in proxy_env("host").values():
        assert "key" not in value.lower() and "token" not in value.lower()


# --- measured against real docker -------------------------------------------

def _curl_from_challenger_network(network: str, proxy_host: str, url: str,
                                  timeout: int = 20) -> subprocess.CompletedProcess:
    """A throwaway container on the challenger's own network, using the same
    proxy variables the challenger gets. This is the challenger's view."""
    env_flags = []
    for name, value in proxy_env(proxy_host).items():
        env_flags += ["-e", f"{name}={value}"]
    return subprocess.run(
        ["docker", "run", "--rm", f"--network={network}", *env_flags,
         "curlimages/curl:8.10.1", "--max-time", str(timeout), "-s", "-o", "/dev/null",
         "-w", "%{http_code}", url],
        capture_output=True, text=True)


@SMOKE
def test_a_non_allowlisted_host_is_actually_blocked():
    # THE test. Not "the config says deny" — a real request to a real host
    # from the challenger's real network, and it must not get through.
    with egress_network() as proxy_host:
        result = _curl_from_challenger_network(
            "elcapitan-challenger", proxy_host, "https://example.com")
        assert result.stdout.strip() not in ("200", "301", "302"), (
            f"example.com was REACHABLE from the challenger network "
            f"(HTTP {result.stdout.strip()}) — the allowlist is not enforcing")


@SMOKE
def test_the_model_endpoint_is_reachable():
    # The other half. An egress policy that blocks everything is trivially
    # "secure" and produces a challenger that never runs — which is the exact
    # failure that started this.
    with egress_network() as proxy_host:
        result = _curl_from_challenger_network(
            "elcapitan-challenger", proxy_host, "https://api.anthropic.com/v1/messages")
        # 401 is the CORRECT answer: the request reached Anthropic and was
        # rejected for having no credential. Anything that is not an HTTP
        # status means it never arrived.
        assert result.stdout.strip().isdigit() and result.stdout.strip() != "000", (
            f"api.anthropic.com was NOT reachable through the proxy "
            f"(curl wrote {result.stdout.strip()!r}) — the challenger cannot run")


@SMOKE
def test_the_challenger_network_has_no_route_out_without_the_proxy():
    # Belt and braces: the network itself is internal, so even a challenger
    # that ignored the proxy variables has nowhere to go.
    with egress_network():
        result = subprocess.run(
            ["docker", "run", "--rm", "--network=elcapitan-challenger",
             "curlimages/curl:8.10.1", "--max-time", "10", "-s", "-o", "/dev/null",
             "-w", "%{http_code}", "https://api.anthropic.com/v1/messages"],
            capture_output=True, text=True)
        assert result.stdout.strip() in ("", "000"), (
            f"the challenger network routed directly to the internet "
            f"(HTTP {result.stdout.strip()}) — it is not internal")


@SMOKE
def test_the_network_is_declared_internal():
    with egress_network():
        out = subprocess.run(["docker", "network", "inspect", "elcapitan-challenger"],
                             capture_output=True, text=True).stdout
        assert json.loads(out)[0]["Internal"] is True


@SMOKE
def test_the_proxy_is_cleaned_up_afterwards():
    with egress_network() as proxy_host:
        pass
    running = subprocess.run(["docker", "ps", "-a", "--filter", f"name={proxy_host}",
                              "--format", "{{.Names}}"],
                             capture_output=True, text=True).stdout.strip()
    assert running == "", f"the proxy container outlived its trial: {running!r}"
