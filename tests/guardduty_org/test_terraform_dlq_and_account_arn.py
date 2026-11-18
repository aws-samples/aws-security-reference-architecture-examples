"""Static check: the GuardDuty DLQ uses alias/aws/sqs and account:ListRegions is scoped to the account, in Terraform and CloudFormation."""

from __future__ import annotations

import re
from pathlib import Path

CFN = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/guardduty/guardduty_org/templates/sra-guardduty-org-configuration.yaml"
MAIN = Path(__file__).resolve().parents[2] / "aws_sra_examples/terraform/solutions/guard_duty/gd_configuration/main.tf"


def block(pattern: str) -> str:
    match = re.search(pattern + r" \{\n(.*?)\n\}\n", MAIN.read_text(), re.S)
    assert match, f"{pattern} not found in {MAIN.name}"
    return match.group(1)


def test_dlq_is_encrypted() -> None:
    dlq = block(r'resource "aws_sqs_queue" "guardduty_dlq"')
    assert re.search(r'^\s*kms_master_key_id\s*=\s*"alias/aws/sqs"', dlq, re.M), "the DLQ must use alias/aws/sqs, as the CloudFormation queue does"


def test_list_regions_is_scoped_to_the_account() -> None:
    policy = block(r'data "aws_iam_policy_document" "sra_guardduty_org_policy_acct"')
    assert "account:ListRegions" in policy
    resources = re.search(r"resources\s*=\s*\[(.*?)\]", policy, re.S)
    assert resources, "AcctListRegions has no resources"
    assert '"*"' not in resources.group(1), "account:ListRegions must not use Resource *"
    assert ":account::${data.aws_caller_identity.current.account_id}:account" in resources.group(1)


def test_cloudformation_list_regions_is_scoped_to_the_account() -> None:
    text = CFN.read_text()
    match = re.search(r"Sid: AcctListRegions\n(.*?)(?=^\s+Tags:|^\s+- (?:PolicyName|Sid):)", text, re.M | re.S)
    assert match, "AcctListRegions not found in the CloudFormation template"
    resource = re.search(r"Resource: (.*)", match.group(1))
    assert resource, "AcctListRegions has no Resource"
    assert resource.group(1).strip() != "'*'", "account:ListRegions must not use Resource '*'"
    assert "account::${AWS::AccountId}:account" in resource.group(1)


def test_cloudformation_dlq_uses_the_same_key_as_terraform() -> None:
    assert re.search(r"rGuardDutyOrgDLQ:\n(?:.*\n)*?\s+KmsMasterKeyId: alias/aws/sqs", CFN.read_text())
