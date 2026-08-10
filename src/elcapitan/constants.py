"""Constants shared by the isolation boundary and the validator.

GROUND_TRUTH_MARKERS lived as two verbatim copies — one in container.py (which
refuses to *mount* ground truth into an agent container) and one in validate.py
(which fails a run when ground truth is *found* inside the run dir). The two
are the same claim checked at two moments, so a marker added to one copy and
not the other would silently open the other end. One definition, two importers.
"""

GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")

# Host variable name -> in-container variable name for the scoped, read-only
# cloud scanner credential. An explicit map, not a prefix-strip, so
# ELCAP_SCANNER_AWS_ACCESS_KEY_ID on the host becomes AWS_ACCESS_KEY_ID where
# AWS tooling actually looks for it, and the ELCAP_ prefix is never applied
# twice or left on by accident.
#
# It lives here rather than in shim.py because it now has two importers with
# opposite jobs: shim.py passes these credentials INTO the agent container,
# and cloud.py uses them on the HOST to re-query the finding's resource after
# the run. Same three names, same read-only role; a rename must not be able to
# fix one side and silently strand the other.
SCANNER_ENV_MAP = {
    "ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
    "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
    "ELCAP_SCANNER_AWS_SESSION_TOKEN": "AWS_SESSION_TOKEN",
}
