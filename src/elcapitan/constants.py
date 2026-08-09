"""Constants shared by the isolation boundary and the validator.

GROUND_TRUTH_MARKERS lived as two verbatim copies — one in container.py (which
refuses to *mount* ground truth into an agent container) and one in validate.py
(which fails a run when ground truth is *found* inside the run dir). The two
are the same claim checked at two moments, so a marker added to one copy and
not the other would silently open the other end. One definition, two importers.
"""

GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")
