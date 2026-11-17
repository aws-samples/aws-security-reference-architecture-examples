"""Static check: every required env var read by the Macie org Lambda is set by CloudFormation and Terraform."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
APP = ROOT / "solutions/macie/macie_org/lambda/src/app.py"
CFN = ROOT / "solutions/macie/macie_org/templates/sra-macie-org-configuration.yaml"
TF = ROOT / "terraform/solutions/macie/configuration/main.tf"


def required_env_vars() -> set:
    return set(re.findall(r'os\.environ\[\s*"([A-Z_]+)"\s*\]', APP.read_text()))


def test_required_env_vars_found() -> None:
    assert {"SNS_TOPIC_ARN", "DISABLE_MACIE_ROLE_NAME"} <= required_env_vars()


def lambda_resource_block() -> str:
    """Return the text of the rMacieOrgLambdaFunction resource only (not the custom resource properties)."""
    match = re.search(r"^  rMacieOrgLambdaFunction:\n(.*?)(?=^  \w+:\n)", CFN.read_text(), re.M | re.S)
    assert match, "rMacieOrgLambdaFunction not found in CloudFormation template"
    return match.group(1)


def test_cloudformation_sets_env_vars() -> None:
    block = lambda_resource_block()
    assert re.search(r"^\s+Environment:\n\s+Variables:", block, re.M), "Lambda has no Environment.Variables"
    for name in required_env_vars():
        assert re.search(rf"^\s+{name}:", block, re.M), f"{name} missing from the Lambda's environment in the CloudFormation template"


def test_terraform_sets_env_vars() -> None:
    text = TF.read_text()
    for name in required_env_vars():
        assert re.search(rf"^\s+{name}\s*=", text, re.M), f"{name} missing from Terraform module"


def test_terraform_has_topic_policy() -> None:
    assert 'resource "aws_sns_topic_policy"' in TF.read_text()
