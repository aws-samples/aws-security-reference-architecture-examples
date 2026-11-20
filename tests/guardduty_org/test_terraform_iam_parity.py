"""Static check: the Terraform IAM policies grant the same actions as the CloudFormation roles they mirror."""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tf_hcl  # noqa: E402

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
CFN_DIR = ROOT / "solutions/guardduty/guardduty_org/templates"
TF_DIR = ROOT / "terraform/solutions/guard_duty"

ACTION = r"[a-z0-9-]+:[A-Za-z0-9*]+"
# The trust policies are declared separately in Terraform (assume_role data sources), so they are not compared.
ASSUME_ROLE = {"sts:AssumeRole"}


def cfn_role_actions(template: str, resource: str) -> set:
    """Return the IAM actions listed under Action: in one role resource of a CloudFormation template."""
    text = (CFN_DIR / template).read_text()
    match = re.search(rf"^  {resource}:\n(.*?)(?=^  \w+:\n|^\w+:\n|\Z)", text, re.M | re.S)
    assert match, f"{resource} not found in {template}"
    actions: set = set()
    for found in re.finditer(r"^(\s+)Action:(.*?)(?=^\s+\w+:|\Z)", match.group(1), re.M | re.S):
        actions |= set(re.findall(ACTION, found.group(2)))
    return actions


def terraform_policy_actions(module: str, document_prefix: str = "") -> set:
    """Return the IAM actions in the aws_iam_policy_document data sources of a Terraform module (actions = [...])."""
    actions: set = set()
    for document in tf_hcl.policy_documents(TF_DIR / module / "main.tf", rf"{document_prefix}\w*"):
        for statement in tf_hcl.statements(document):
            actions |= {a for a in tf_hcl.list_values(statement, "actions") if re.fullmatch(ACTION, a)}
    return actions


def assert_same(cfn: set, tf: set, what: str) -> None:
    assert cfn, f"no CloudFormation actions found for {what}"
    assert tf, f"no Terraform actions found for {what}"
    assert cfn - tf == set(), f"{what}: in CloudFormation but not in Terraform: {sorted(cfn - tf)}"
    assert tf - cfn == set(), f"{what}: in Terraform but not in CloudFormation: {sorted(tf - cfn)}"


def test_lambda_role_actions_match() -> None:
    cfn = cfn_role_actions("sra-guardduty-org-configuration.yaml", "rGuardDutyOrgLambdaRole")
    tf = terraform_policy_actions("gd_configuration", "sra_guardduty_org_policy_")
    assert_same(cfn - ASSUME_ROLE, tf - ASSUME_ROLE, "GuardDuty configuration Lambda role")


def test_configuration_role_actions_match() -> None:
    cfn = cfn_role_actions("sra-guardduty-org-configuration-role.yaml", "rConfigurationRole")
    tf = terraform_policy_actions("configuration_role")
    assert_same(cfn - ASSUME_ROLE, tf - ASSUME_ROLE, "GuardDuty configuration role")
