"""Static check: every required env var read by the GuardDuty org Lambda is set by CloudFormation and Terraform."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
APP = ROOT / "solutions/guardduty/guardduty_org/lambda/src/app.py"
CFN = ROOT / "solutions/guardduty/guardduty_org/templates/sra-guardduty-org-configuration.yaml"
TF = ROOT / "terraform/solutions/guard_duty/gd_configuration/main.tf"


def required_env_vars() -> set:
    return set(re.findall(r'os\.environ\[\s*"([A-Z_]+)"\s*\]', APP.read_text()))


def test_required_env_vars_found() -> None:
    assert {"SNS_TOPIC_ARN", "DELETE_DETECTOR_ROLE_NAME"} <= required_env_vars()


def test_cloudformation_sets_env_vars() -> None:
    text = CFN.read_text()
    for name in required_env_vars():
        assert re.search(rf"^\s+{name}:", text, re.M), f"{name} missing from CloudFormation template"


def test_terraform_sets_env_vars() -> None:
    text = TF.read_text()
    for name in required_env_vars():
        assert re.search(rf"^\s+{name}\s*=", text, re.M), f"{name} missing from Terraform module"


def test_terraform_has_topic_policy() -> None:
    assert 'resource "aws_sns_topic_policy"' in TF.read_text()
