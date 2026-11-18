"""Static check: the config_org fan-out topic is restricted to the configuration Lambda and wired to it."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
CFN = ROOT / "solutions/config/config_org/templates/sra-config-org-configuration.yaml"
APP = ROOT / "solutions/config/config_org/lambda/src/app.py"


def test_fanout_topic_has_topic_policy() -> None:
    text = CFN.read_text()
    assert "AWS::SNS::TopicPolicy" in text
    assert "AllowOnlyConfigOrgLambdaRoleToPublish" in text and "DenyPublishFromAnyOtherPrincipal" in text


def test_fanout_topic_env_var_set() -> None:
    assert "SNS_TOPIC_ARN_FANOUT" in APP.read_text()
    assert re.search(r"^\s+SNS_TOPIC_ARN_FANOUT:", CFN.read_text(), re.M)
