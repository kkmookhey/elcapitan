# tests/test_toolsem.py
import pytest
from elcapitan.toolsem import interpret_exit

def test_terraform_plan_detailed_exitcode_2_is_success_with_changes():
    v = interpret_exit("terraform", ["plan", "-detailed-exitcode"], 2)
    assert v.ok is True
    assert "changes" in v.meaning

def test_terraform_plan_detailed_exitcode_0_is_success_no_changes():
    v = interpret_exit("terraform", ["plan", "-detailed-exitcode"], 0)
    assert v.ok is True
    assert "no changes" in v.meaning

def test_terraform_plan_detailed_exitcode_1_is_error():
    assert interpret_exit("terraform", ["plan", "-detailed-exitcode"], 1).ok is False

def test_terraform_plan_without_detailed_exitcode_2_is_error():
    # Without the flag, 2 carries no special meaning and is a failure.
    assert interpret_exit("terraform", ["plan"], 2).ok is False

def test_terraform_validate_zero_is_success():
    assert interpret_exit("terraform", ["validate"], 0).ok is True

def test_terraform_validate_nonzero_is_error():
    assert interpret_exit("terraform", ["validate"], 1).ok is False

def test_cdk_diff_without_fail_flag_zero_is_success():
    assert interpret_exit("cdk", ["diff"], 0).ok is True

def test_cdk_diff_with_fail_flag_one_means_differences_present():
    v = interpret_exit("cdk", ["diff", "--fail"], 1)
    assert v.ok is True
    assert "differences" in v.meaning

def test_trivy_with_exit_code_flag_reports_findings_not_failure():
    v = interpret_exit("trivy", ["config", ".", "--exit-code", "1"], 1)
    assert v.ok is True
    assert "findings" in v.meaning

def test_trivy_without_exit_code_flag_nonzero_is_error():
    assert interpret_exit("trivy", ["config", "."], 1).ok is False

def test_unknown_tool_falls_back_to_zero_is_success():
    assert interpret_exit("jq", ["."], 0).ok is True
    assert interpret_exit("jq", ["."], 1).ok is False

def test_unknown_tool_verdict_states_the_fallback():
    assert "generic" in interpret_exit("jq", ["."], 1).meaning

def test_absent_exit_code_is_never_treated_as_success():
    from elcapitan.toolsem import interpret_exit
    with pytest.raises(TypeError):
        interpret_exit("terraform", ["plan"])   # code is required, never defaulted

def test_cdk_diff_with_fail_flag_one_is_ambiguous():
    # cdk has no separate exit code for "differences present" vs. "cdk error"
    # (synth failure, bad credentials, missing stack) — exit 1 covers both.
    v = interpret_exit("cdk", ["diff", "--fail"], 1)
    assert v.ok is True
    assert v.ambiguous is True

def test_cdk_diff_with_fail_flag_zero_is_not_ambiguous():
    v = interpret_exit("cdk", ["diff", "--fail"], 0)
    assert v.ok is True
    assert v.ambiguous is False

def test_trivy_exit_code_one_is_ambiguous():
    # trivy also uses exit 1 for its own scan-level errors, so --exit-code 1
    # collides with findings-present.
    v = interpret_exit("trivy", ["config", ".", "--exit-code", "1"], 1)
    assert v.ok is True
    assert v.ambiguous is True

def test_trivy_exit_code_two_is_not_ambiguous():
    # A configured code other than 1 doesn't collide with trivy's own error
    # code, so this verdict is unambiguous.
    v = interpret_exit("trivy", ["config", ".", "--exit-code", "2"], 2)
    assert v.ok is True
    assert v.ambiguous is False

def test_terraform_verdict_defaults_to_not_ambiguous():
    assert interpret_exit("terraform", ["validate"], 0).ambiguous is False


# --- argv that repeats the tool name ----------------------------------------
#
# FOUND BY THE FIRST REAL BATCH, and it cost six trials and about $13.
#
# A CommandRecord's argv has two conventions in the wild, and the engineer
# picked between them differently on different runs:
#
#     ["terraform", "plan", "-detailed-exitcode"]     tool included
#     ["plan", "-detailed-exitcode"]                  tool excluded
#
# _terraform read argv[0] as the subcommand, so the first form made `sub`
# "terraform", the -detailed-exitcode branch never matched, and a plan exiting
# 2 — SUCCESS, meaning changes are present, which is the expected outcome of
# every remediation this system generates — was scored as a failure. The error
# read "terraform terraform exit 2", which is the tell.
#
# Identical work scoring differently because of a recording convention is an
# experimental confound, not a formatting nit.

@pytest.mark.parametrize("argv", [
    ["terraform", "plan", "-detailed-exitcode"],
    ["plan", "-detailed-exitcode"],
])
def test_a_plan_with_changes_is_success_under_either_argv_convention(argv):
    verdict = interpret_exit("terraform", argv, 2)
    assert verdict.ok, f"exit 2 with -detailed-exitcode means CHANGES PRESENT: {argv}"
    assert "changes present" in verdict.meaning


@pytest.mark.parametrize("argv", [
    ["terraform", "plan", "-detailed-exitcode"],
    ["plan", "-detailed-exitcode"],
])
def test_a_plan_with_no_changes_is_also_success(argv):
    assert interpret_exit("terraform", argv, 0).ok


@pytest.mark.parametrize("argv", [
    ["terraform", "plan", "-detailed-exitcode"],
    ["plan", "-detailed-exitcode"],
])
def test_a_real_plan_error_is_still_a_failure(argv):
    # The fix must not turn every non-zero exit into a pass. Exit 1 from
    # terraform plan is a genuine error under both conventions.
    assert not interpret_exit("terraform", argv, 1).ok


def test_the_duplicated_tool_name_does_not_leak_into_the_message():
    # "terraform terraform exit 2" is what a reader saw. It should never
    # appear again.
    verdict = interpret_exit("terraform", ["terraform", "validate", "-json"], 0)
    assert "terraform terraform" not in verdict.meaning


def test_a_bare_tool_name_argv_does_not_crash():
    assert interpret_exit("terraform", ["terraform"], 0) is not None
