"""Static check: the management-account parameters Lambda may read exactly the Control Tower stack sets its code reads.

The same Lambda code is deployed by CloudFormation (common_prerequisites) and Terraform (terraform/common/ssm_parameters),
so every CloudFormation statement in both role policies is checked against the StackSetName values in lambda/src/app.py.
No AWS calls are made.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import child_block, statements, values  # noqa: E402

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
APP = ROOT / "solutions/common/common_prerequisites/lambda/src/app.py"
CFN = ROOT / "solutions/common/common_prerequisites/templates/sra-common-prerequisites-management-account-parameters.yaml"
TF = ROOT / "terraform/common/ssm_parameters/main.tf"
EXPECTED = {
    "AWSControlTowerBP-BASELINE-CLOUDWATCH",
    "AWSControlTowerBP-BASELINE-CONFIG",
    "AWSControlTowerBP-CONFIG-CENTRAL-S3-BUCKET",
    "AWSControlTowerLoggingResources",
}


def stack_sets_in_code() -> set:
    return set(re.findall(r"""StackSetName\s*=\s*["']([^"']+)["']""", APP.read_text()))


def test_code_reads_exactly_these_stack_sets() -> None:
    assert stack_sets_in_code() == EXPECTED


def cfn_statements() -> list:
    lines = CFN.read_text().splitlines()
    start = lines.index("  rManagementAccountParametersLambdaRole:")
    return statements([lines[start], *child_block(lines, start)])


def test_cloudformation_stack_set_reads_are_limited_to_the_expected_arns() -> None:
    expected = {f"!Sub arn:${{AWS::Partition}}:cloudformation:${{AWS::Region}}:${{AWS::AccountId}}:stackset/{name}:*" for name in EXPECTED}
    cfn = [s for s in cfn_statements() if any(a.lower().startswith("cloudformation:") for a in values(s, "Action"))]
    assert cfn, "no CloudFormation statement found"
    for statement in cfn:
        assert set(values(statement, "Resource")) == expected, "\n".join(statement)


def tf_statements() -> list:
    """Each `statement { ... }` block of the Lambda's SSM policy document, as text."""
    text = TF.read_text()
    start = text.index('data "aws_iam_policy_document" "management_account_parameters_lambda_ssm_policy"')
    end = text.index('\nresource "', start)
    return re.findall(r"statement \{(.*?)\n  \}", text[start:end], re.S)


def tf_list(block: str, key: str) -> list:
    match = re.search(rf"\b{key}\s*=\s*\[(.*?)\]", block, re.S)
    return re.findall(r'"([^"]*)"', re.sub(r"#.*", "", match.group(1))) if match else []


def test_terraform_stack_set_reads_are_limited_to_the_expected_arns() -> None:
    expected = {f"arn:${{local.partition}}:cloudformation:${{local.region}}:${{local.account_id}}:stackset/{name}:*" for name in EXPECTED}
    cfn = [b for b in tf_statements() if any(a.lower().startswith("cloudformation:") for a in tf_list(b, "actions"))]
    assert cfn, "no CloudFormation statement found"
    for block in cfn:
        assert set(tf_list(block, "resources")) == expected, block


def test_terraform_policy_has_no_ckv_aws_356_suppression() -> None:
    text = TF.read_text()
    start = text.index('data "aws_iam_policy_document" "management_account_parameters_lambda_ssm_policy"')
    assert "CKV_AWS_356" not in text[start : text.index('\nresource "', start)]
