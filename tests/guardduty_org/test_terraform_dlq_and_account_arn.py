"""Static check: the GuardDuty Terraform DLQ is encrypted and account:ListRegions is scoped to the account."""

from __future__ import annotations

import re
from pathlib import Path

MAIN = Path(__file__).resolve().parents[2] / "aws_sra_examples/terraform/solutions/guard_duty/gd_configuration/main.tf"


def block(pattern: str) -> str:
    match = re.search(pattern + r" \{\n(.*?)\n\}\n", MAIN.read_text(), re.S)
    assert match, f"{pattern} not found in {MAIN.name}"
    return match.group(1)


def test_dlq_is_encrypted() -> None:
    dlq = block(r'resource "aws_sqs_queue" "guardduty_dlq"')
    assert re.search(r'^\s*kms_master_key_id\s*=\s*"alias/aws/sqs"', dlq, re.M) or re.search(r"^\s*sqs_managed_sse_enabled\s*=\s*true", dlq, re.M)


def test_list_regions_is_scoped_to_the_account() -> None:
    policy = block(r'data "aws_iam_policy_document" "sra_guardduty_org_policy_acct"')
    assert "account:ListRegions" in policy
    resources = re.search(r"resources\s*=\s*\[(.*?)\]", policy, re.S)
    assert resources, "AcctListRegions has no resources"
    assert '"*"' not in resources.group(1), "account:ListRegions must not use Resource *"
    assert ":account::${data.aws_caller_identity.current.account_id}:account" in resources.group(1)
