"""Static checks: the Bedrock org Lambda role and the alarm key policy grant only what the Lambda uses.

In member accounts the Lambda works through sra-execution sessions. In the management account it uses its own
role (sra_sts.assume_role returns the Lambda's own client there), so the role keeps permissions for the resources
it creates in that account, scoped to that account.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import child_block, statements  # noqa: E402

SOLUTION = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/genai/bedrock_org"
TEMPLATE = SOLUTION / "templates/sra-bedrock-org-main.yaml"
KEY_POLICIES = SOLUTION / "lambda/src/sra_kms_keys.json"
APP = SOLUTION / "lambda/src/app.py"

# Actions without resource-level permissions, so they need Resource: '*'.
WILDCARD_ACTIONS = {
    "cloudwatch:DescribeAlarms",
    "cloudwatch:Link",
    "config:DescribeConfigRules",
    "kms:CreateKey",
    "kms:ListAliases",
    "kms:ListKeys",
    "organizations:DescribeOrganization",
    "sts:GetCallerIdentity",
    "xray:Link",
}
EXECUTION_ROLE_ARN = "!Sub 'arn:${AWS::Partition}:iam::*:role/${pSRAExecutionRoleName}'"
# What the Lambda does on its own alarm key in the management account. kms:PutKeyPolicy is there because
# CreateKey's policy lockout check requires the creating principal to keep it.
KEY_ADMIN_ACTIONS = ["kms:CreateAlias", "kms:DeleteAlias", "kms:DescribeKey", "kms:EnableKeyRotation", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"]


def values(statement: list, key: str) -> list:
    """Return the scalar or list values of `key` in a statement, without quotes or trailing comments."""
    for index, line in enumerate(statement):
        match = re.match(rf"^\s*(?:- )?{key}:\s*(.*?)\s*$", line)
        if not match:
            continue
        inline = re.sub(r"\s+#.*$", "", match.group(1))
        found = [inline] if inline else [item.strip().removeprefix("- ") for item in child_block(statement, index) if item.strip()]
        found = [re.sub(r"\s+#.*$", "", value) for value in found]
        return [value if value.startswith("!") else value.strip("'\"") for value in found]
    return []


def policy_statements() -> list:
    """Statements in the role's inline policies (not its trust policy)."""
    lines = TEMPLATE.read_text().splitlines()
    role = child_block(lines, lines.index("  rBedrockOrgLambdaRole:"))
    return statements(child_block(role, role.index("      Policies:")))


def resources_for(action: str) -> list:
    return [values(statement, "Resource") for statement in policy_statements() if action in values(statement, "Action")]


def test_only_actions_without_resource_level_permissions_use_a_wildcard_resource() -> None:
    found = set()
    for statement in policy_statements():
        if "*" in values(statement, "Resource"):
            actions = set(values(statement, "Action"))
            found |= actions
            assert actions <= WILDCARD_ACTIONS, f"Resource '*' for {sorted(actions - WILDCARD_ACTIONS)}"
    assert found == WILDCARD_ACTIONS, f"expected {sorted(WILDCARD_ACTIONS)} on '*', found {sorted(found)}"


def test_assume_role_is_limited_to_the_execution_role() -> None:
    assert resources_for("sts:AssumeRole") == [[EXECUTION_ROLE_ARN]]


def test_write_actions_are_limited_to_the_management_account_resources_the_lambda_creates() -> None:
    expected = {
        "config:PutConfigRule": "!Sub 'arn:${AWS::Partition}:config:*:${AWS::AccountId}:config-rule/*'",
        "cloudwatch:PutMetricAlarm": "!Sub 'arn:${AWS::Partition}:cloudwatch:*:${AWS::AccountId}:alarm:sra-bedrock-*'",
        "kms:CreateAlias": "!Sub 'arn:${AWS::Partition}:kms:*:${AWS::AccountId}:alias/sra-alarm-sns-key'",
        "kms:DescribeKey": "!Sub 'arn:${AWS::Partition}:kms:*:${AWS::AccountId}:key/*'",
    }
    for action, resource in expected.items():
        assert resources_for(action) == [[resource]], action
    for action in ["kms:Decrypt", "kms:GenerateDataKey", "kms:ScheduleKeyDeletion", "kms:TagResource", "kms:EnableKeyRotation", "kms:PutKeyPolicy"]:
        assert resources_for(action) == [], f"{action} belongs in the key policy, which covers only the Lambda's own key"


def test_the_execution_role_parameter_names_the_role_app_py_assumes() -> None:
    lines = TEMPLATE.read_text().splitlines()
    parameter = child_block(lines, lines.index("  pSRAExecutionRoleName:"))
    assert values(parameter, "AllowedPattern") == ["^sra-execution$"]
    source = APP.read_text()
    assert re.findall(r'^\s*sts\.CONFIGURATION_ROLE = "([^"]+)"', source, re.M) == ["sra-execution"]
    for call in ast.walk(ast.parse(source)):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr in {"assume_role", "assume_role_resource"}:
            role = call.args[1] if len(call.args) > 1 else next(keyword.value for keyword in call.keywords if keyword.arg == "role_name")
            assert ast.unparse(role) == "sts.CONFIGURATION_ROLE", f"app.py:{call.lineno} assumes {ast.unparse(role)}"


def test_the_role_does_not_suppress_checkov() -> None:
    lines = TEMPLATE.read_text().splitlines()
    role = "\n".join(child_block(lines, lines.index("  rBedrockOrgLambdaRole:")))
    assert "CKV_AWS_107" not in role
    assert "CKV_AWS_111" not in role


def alarm_key_policy() -> dict:
    return json.loads(KEY_POLICIES.read_text())["sra-alarm-sns-key"]


def test_alarm_key_policy_gives_the_lambda_role_only_key_administration_actions() -> None:
    root, cloudwatch, role = alarm_key_policy()["Statement"]
    assert root["Principal"] == {"AWS": "arn:aws:iam::ACCOUNT_ID:root"}
    assert cloudwatch["Principal"] == {"Service": "cloudwatch.amazonaws.com"}
    assert role["Principal"] == {"AWS": "arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"}
    assert sorted(role["Action"]) == KEY_ADMIN_ACTIONS


@pytest.fixture(scope="module")
def app() -> ModuleType:
    """Import the Lambda's app.py with boto3 mocked, because it calls AWS at import time."""
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    sys.path.insert(0, str(APP.parent))
    spec = importlib.util.spec_from_file_location("sra_bedrock_org_app", APP)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.client") as client, mock.patch("boto3.Session"), mock.patch("boto3.session.Session"):
        client.return_value.meta.endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"
        spec.loader.exec_module(module)
    return module


def test_management_account_key_trusts_the_lambda_role(app: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app.sts, "MANAGEMENT_ACCOUNT", "111111111111")
    role_arn = "arn:aws:iam::111111111111:role/sra-bedrock-org-lambda"
    policy = app.build_alarm_key_policy("111111111111", role_arn)
    assert [statement["Principal"] for statement in policy["Statement"]] == [
        {"AWS": "arn:aws:iam::111111111111:root"},
        {"Service": "cloudwatch.amazonaws.com"},
        {"AWS": role_arn},
    ]
    assert app.KMS_KEY_POLICIES == json.loads(KEY_POLICIES.read_text()), "build_alarm_key_policy changed the loaded template"


def test_member_account_key_does_not_trust_the_lambda_role(app: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app.sts, "MANAGEMENT_ACCOUNT", "111111111111")
    policy = app.build_alarm_key_policy("222222222222", "arn:aws:iam::111111111111:role/sra-bedrock-org-lambda")
    assert [statement["Principal"] for statement in policy["Statement"]] == [
        {"AWS": "arn:aws:iam::222222222222:root"},
        {"Service": "cloudwatch.amazonaws.com"},
    ]
    assert app.KMS_KEY_POLICIES == json.loads(KEY_POLICIES.read_text()), "build_alarm_key_policy changed the loaded template"


def test_app_py_only_indexes_key_policy_statements_that_exist() -> None:
    indexes = {int(index) for index in re.findall(r'\["Statement"\]\[(\d+)\]', APP.read_text())}
    assert indexes, "app.py no longer customizes the key policy by index; update this test"
    assert max(indexes) < len(alarm_key_policy()["Statement"]), f"app.py indexes statements {sorted(indexes)}"


POLICY = """\
      Policies:
        - PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - 'sts:GetCallerIdentity'
                Resource: '*' # required for stsGetCallerIdentity action
              - Effect: Allow
                Action: config:PutConfigRule
                Resource:
                  - '*'
              - Effect: Allow
                Action:
                  - 'sts:AssumeRole'
                Resource: !Sub 'arn:${AWS::Partition}:iam::*:role/${pSRAExecutionRoleName}'
"""


def test_values_reads_inline_list_and_commented_forms() -> None:
    first, second, third = statements(POLICY.splitlines())
    assert values(first, "Action") == ["sts:GetCallerIdentity"]
    assert values(first, "Resource") == ["*"]
    assert values(second, "Action") == ["config:PutConfigRule"]
    assert values(second, "Resource") == ["*"]
    assert values(third, "Resource") == [EXECUTION_ROLE_ARN]
