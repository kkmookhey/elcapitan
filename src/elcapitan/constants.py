"""Constants shared by the isolation boundary and the validator.

GROUND_TRUTH_MARKERS lived as two verbatim copies — one in container.py (which
refuses to *mount* ground truth into an agent container) and one in validate.py
(which fails a run when ground truth is *found* inside the run dir). The two
are the same claim checked at two moments, so a marker added to one copy and
not the other would silently open the other end. One definition, two importers.
"""

GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")

# Host variable name -> in-container variable name for the scoped, read-only
# cloud scanner credential, keyed by cloud provider. An explicit map, not a
# prefix-strip, so ELCAP_SCANNER_AWS_ACCESS_KEY_ID on the host becomes
# AWS_ACCESS_KEY_ID where AWS tooling actually looks for it, and the ELCAP_
# prefix is never applied twice or left on by accident.
#
# It lives here rather than in shim.py because it has two importers with
# opposite jobs: shim.py passes these credentials INTO the agent container,
# and cloud.py uses them on the HOST to re-query the finding's resource after
# the run. Same credential, same read-only role; a rename must not be able to
# fix one side and silently strand the other.
#
# KEYED BY PROVIDER since Eiger. A single flat map meant every entry point
# demanded the AWS trio unconditionally — bin/run-trial.sh would not start an
# Azure trial even in stub mode. The provider a trial runs under is not a
# preference: it is read from the scanner finding itself (finding.cloud_target)
# and cross-checked against the environment adapter's `cloud:` field, so
# nothing here is chosen by whichever variables happen to be exported.
SCANNER_ENV_MAPS = {
    "aws": {
        "ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
        "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
        "ELCAP_SCANNER_AWS_SESSION_TOKEN": "AWS_SESSION_TOKEN",
    },
    # Prowler authenticated against Eiger with --sp-env-auth, which reads
    # exactly these three names; the container-side spelling is therefore not
    # a choice, it is what the scanner already requires. MEASURED: the `az`
    # CLI does NOT read them — it needs `az login --service-principal` — which
    # is why cloud.py logs in explicitly rather than exporting and hoping.
    "azure": {
        "ELCAP_SCANNER_AZURE_CLIENT_ID": "AZURE_CLIENT_ID",
        "ELCAP_SCANNER_AZURE_CLIENT_SECRET": "AZURE_CLIENT_SECRET",
        "ELCAP_SCANNER_AZURE_TENANT_ID": "AZURE_TENANT_ID",
    },
}


def scanner_env_map(provider: str) -> dict:
    """The credential map for one provider, or a named error.

    Never a silent empty dict: an unknown provider returning {} would make
    every "are the credentials set?" check vacuously true, and the run would
    proceed to query nothing and compare it against nothing.
    """
    try:
        return SCANNER_ENV_MAPS[provider]
    except KeyError:
        raise ValueError(
            f"no scanner credential map for provider {provider!r} "
            f"(known: {', '.join(sorted(SCANNER_ENV_MAPS))})") from None


# Every host-side scanner variable, all providers. bin/agent-run.sh uses this
# to detect which provider's credentials the operator actually exported.
ALL_SCANNER_ENV_NAMES = frozenset(
    name for mapping in SCANNER_ENV_MAPS.values() for name in mapping)
