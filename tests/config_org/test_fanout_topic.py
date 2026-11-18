"""Static check: the config_org fan-out topic is restricted to the configuration Lambda and wired to it."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
CFN = ROOT / "solutions/config/config_org/templates/sra-config-org-configuration.yaml"


def resource_block(name: str) -> str:
    """Return the text of one top-level resource of the CloudFormation template."""
    match = re.search(rf"^  {name}:\n(.*?)(?=^  \w+:\n|^\w+:\n|\Z)", CFN.read_text(), re.M | re.S)
    assert match, f"{name} not found in CloudFormation template"
    return match.group(1)


def test_fanout_topic_has_topic_policy_for_the_topic() -> None:
    block = resource_block("rConfigOrgTopicPolicy")
    assert "Type: AWS::SNS::TopicPolicy" in block
    assert re.search(r"Topics:\n\s+- !Ref rConfigOrgTopic\b", block), "topic policy is not attached to rConfigOrgTopic"
    allow = re.search(r"Sid: AllowOnlyConfigOrgLambdaRoleToPublish\n(.*?)(?=^\s+- Sid:|\Z)", block, re.M | re.S)
    deny = re.search(r"Sid: DenyPublishFromAnyOtherPrincipal\n(.*?)(?=^\s+- Sid:|\Z)", block, re.M | re.S)
    assert allow and "Effect: Allow" in allow.group(1) and "AWS: !GetAtt rConfigOrgLambdaRole.Arn" in allow.group(1)
    assert deny and "Effect: Deny" in deny.group(1)
    assert re.search(r"ArnNotEquals:\n\s+aws:PrincipalArn: !GetAtt rConfigOrgLambdaRole.Arn", deny.group(1)), "deny is not keyed on the Lambda role"


def test_fanout_topic_env_var_set_on_the_lambda() -> None:
    block = resource_block("rConfigOrgLambdaFunction")
    assert re.search(r"^\s+Environment:\n\s+Variables:", block, re.M), "Lambda has no Environment.Variables"
    assert re.search(r"^\s+SNS_TOPIC_ARN_FANOUT: !Ref rConfigOrgTopic\b", block, re.M), "SNS_TOPIC_ARN_FANOUT missing from the Lambda environment"
