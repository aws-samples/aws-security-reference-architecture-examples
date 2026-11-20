"""Static checks: the Bedrock guardrails Lambda role and the guardrails key policy grant only what the Lambda uses.

In other accounts the Lambda works through sra-execution sessions. In the management account it uses its own
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
from cfn_yaml import child_block, condition, statements, values  # noqa: E402

SOLUTION = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/genai/bedrock_guardrails"
TEMPLATE = SOLUTION / "templates/sra-bedrock-guardrails-main.yaml"
KEY_POLICIES = SOLUTION / "lambda/src/sra_kms_keys.json"
APP = SOLUTION / "lambda/src/app.py"
KEY_ALIAS = "sra-bedrock-guardrails-key"

# Actions without resource-level permissions for what the Lambda requests, so they need Resource: '*'. CreateGuardrail's
# resource types are automated reasoning policies and guardrail profiles, which the Lambda does not use, and ListGuardrails
# without a guardrailIdentifier is authorized against '*'.
WILDCARD_ACTIONS = {
    "bedrock:CreateGuardrail",
    "bedrock:ListGuardrails",
    "kms:CreateKey",
    "kms:ListAliases",
    "kms:ListKeys",
    "organizations:DescribeOrganization",
    "sts:GetCallerIdentity",
}
EXECUTION_ROLE_ARN = "!Sub 'arn:${AWS::Partition}:iam::*:role/${pSRAExecutionRoleName}'"
KEY_ARN = "!Sub 'arn:${AWS::Partition}:kms:*:${AWS::AccountId}:key/*'"
GUARDRAIL_ARN = "!Sub 'arn:${AWS::Partition}:bedrock:*:${AWS::AccountId}:guardrail/*'"
# What the Lambda does on its own guardrails key in the management account. kms:PutKeyPolicy is there because
# CreateKey's policy lockout check requires the creating principal to keep it.
KEY_ADMIN_ACTIONS = ["kms:CreateAlias", "kms:DeleteAlias", "kms:DescribeKey", "kms:EnableKeyRotation", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"]


def policy_statements() -> list:
    """Statements in the role's inline policies (not its trust policy)."""
    lines = TEMPLATE.read_text().splitlines()
    role = child_block(lines, lines.index("  rBedrockGuardrailsLambdaRole:"))
    return statements(child_block(role, role.index("      Policies:")))


def granting(action: str) -> list:
    """Allow statements whose Action list names the action exactly or by a wildcard that matches it."""
    found = []
    for statement in policy_statements():
        if values(statement, "Effect") != ["Allow"]:
            continue
        assert not values(statement, "NotAction"), "Allow with NotAction"
        patterns = [pattern.lower() for pattern in values(statement, "Action")]
        if any(re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), action.lower()) for pattern in patterns):
            found.append(statement)
    return found


def resources_for(action: str) -> list:
    return [values(statement, "Resource") for statement in granting(action)]


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


def test_actions_are_limited_to_management_account_resources() -> None:
    expected = {
        "kms:TagResource": KEY_ARN,
        "kms:DescribeKey": KEY_ARN,
        "kms:GetKeyPolicy": KEY_ARN,
        "kms:ListKeyPolicies": KEY_ARN,
        "kms:CreateAlias": f"!Sub 'arn:${{AWS::Partition}}:kms:*:${{AWS::AccountId}}:alias/{KEY_ALIAS}'",
        "kms:DeleteAlias": f"!Sub 'arn:${{AWS::Partition}}:kms:*:${{AWS::AccountId}}:alias/{KEY_ALIAS}'",
        "bedrock:TagResource": GUARDRAIL_ARN,
        "bedrock:DeleteGuardrail": GUARDRAIL_ARN,
    }
    for action, resource in expected.items():
        assert resources_for(action) == [[resource]], action
    for action in ["kms:Decrypt", "kms:GenerateDataKey", "kms:ScheduleKeyDeletion", "kms:EnableKeyRotation", "kms:PutKeyPolicy"]:
        assert resources_for(action) == [], f"{action} belongs in the key policy, which covers only the Lambda's own key"


@pytest.mark.parametrize("action", ["kms:CreateKey", "kms:TagResource", "bedrock:CreateGuardrail", "bedrock:TagResource"])
def test_create_and_tag_actions_require_the_solution_tag(action: str) -> None:
    assert granting(action), action
    for statement in granting(action):
        assert condition(statement) == ["StringEquals:", "aws:RequestTag/sra-solution: !Ref pSRASolutionName"], action


def test_bedrock_tag_resource_is_denied_on_existing_guardrails() -> None:
    """Tag-on-create is authorized against the literal guardrail/*, and real guardrail IDs are longer than one character.

    Without this Deny the role could add the solution tag to any guardrail in the account and then delete it.
    """
    denies = [
        statement
        for statement in policy_statements()
        if values(statement, "Effect") == ["Deny"] and "bedrock:tagresource" in [action.lower() for action in values(statement, "Action")]
    ]
    assert len(denies) == 1
    assert values(denies[0], "Resource") == ["!Sub 'arn:${AWS::Partition}:bedrock:*:${AWS::AccountId}:guardrail/??*'"]
    assert condition(denies[0]) == []


def test_delete_guardrail_requires_the_solution_tag() -> None:
    assert granting("bedrock:DeleteGuardrail")
    for statement in granting("bedrock:DeleteGuardrail"):
        assert condition(statement) == ["StringEquals:", "aws:ResourceTag/sra-solution: !Ref pSRASolutionName"]


def test_the_lambda_tags_what_it_creates_with_the_solution_tag() -> None:
    kms_source = (SOLUTION / "lambda/src/sra_kms.py").read_text()
    assert 'Tags=[{"TagKey": "sra-solution", "TagValue": solution_name}]' in kms_source
    assert re.search(r'"tags": \[\s*\{"key": "sra-solution", "value": params\["SOLUTION_NAME"\]\}', APP.read_text())


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
    role = "\n".join(child_block(lines, lines.index("  rBedrockGuardrailsLambdaRole:")))
    assert "CKV_AWS_107" not in role
    assert "CKV_AWS_111" not in role


def guardrails_key_policy() -> dict:
    return json.loads(KEY_POLICIES.read_text())[KEY_ALIAS]


def test_key_policy_gives_the_lambda_role_only_key_administration_and_bedrock_grants() -> None:
    root, admin, grant = guardrails_key_policy()["Statement"]
    assert root["Principal"] == {"AWS": "arn:aws:iam::ACCOUNT_ID:root"}
    assert admin["Principal"] == grant["Principal"] == {"AWS": "arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"}
    assert sorted(admin["Action"]) == KEY_ADMIN_ACTIONS
    assert "Condition" not in admin
    assert grant["Action"] == "kms:CreateGrant"
    assert grant["Condition"] == {"StringEquals": {"kms:ViaService": "bedrock.REGION.amazonaws.com"}}


@pytest.fixture(scope="module")
def app() -> ModuleType:
    """Import the Lambda's app.py with boto3 mocked, because it calls AWS at import time."""
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    # Other solutions' tests import helper modules with the same names (sra_sts, sra_kms, ...) from their own folders,
    # so import this solution's helpers fresh and restore sys.modules and sys.path afterwards
    saved_modules, saved_path = dict(sys.modules), list(sys.path)
    for name in [name for name in sys.modules if name.startswith("sra_") or name == "cfnresponse"]:
        del sys.modules[name]
    sys.path.insert(0, str(APP.parent))
    spec = importlib.util.spec_from_file_location("sra_bedrock_guardrails_app", APP)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.client") as client, mock.patch("boto3.Session"), mock.patch("boto3.session.Session"):
        client.return_value.meta.endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"
        try:
            spec.loader.exec_module(module)
        finally:
            for name in [name for name in sys.modules if name not in saved_modules]:
                del sys.modules[name]
            sys.modules.update(saved_modules)
            sys.path[:] = saved_path
    return module


ROLE_ARN = "arn:aws:iam::111111111111:role/sra-bedrock-guardrails-lambda"
CONFIG_RULE_ROLES = ["arn:aws:iam::111111111111:role/sra-bedrock-check-guardrails"]


@pytest.mark.parametrize("config_rule_roles", [[], CONFIG_RULE_ROLES])
def test_management_account_key_trusts_the_lambda_role(app: ModuleType, monkeypatch: pytest.MonkeyPatch, config_rule_roles: list) -> None:
    monkeypatch.setattr(app.sts, "MANAGEMENT_ACCOUNT", "111111111111")
    monkeypatch.setattr(app, "build_role_arns", lambda acct, region: config_rule_roles)
    policy = app.update_kms_key_policy("111111111111", "eu-west-2", ROLE_ARN)
    principals = [{"AWS": "arn:aws:iam::111111111111:root"}, {"AWS": ROLE_ARN}, {"AWS": ROLE_ARN}]
    if config_rule_roles:
        principals.append({"AWS": config_rule_roles})
    assert [statement["Principal"] for statement in policy["Statement"]] == principals
    admin, grant = policy["Statement"][1:3]
    assert sorted(admin["Action"]) == KEY_ADMIN_ACTIONS
    assert (grant["Action"], grant["Condition"]) == ("kms:CreateGrant", {"StringEquals": {"kms:ViaService": "bedrock.eu-west-2.amazonaws.com"}})
    assert app.KMS_KEY_POLICIES == json.loads(KEY_POLICIES.read_text()), "update_kms_key_policy changed the loaded template"


@pytest.mark.parametrize("config_rule_roles", [[], ["arn:aws:iam::222222222222:role/sra-bedrock-check-guardrails"]])
def test_other_account_key_does_not_trust_the_lambda_role(app: ModuleType, monkeypatch: pytest.MonkeyPatch, config_rule_roles: list) -> None:
    monkeypatch.setattr(app.sts, "MANAGEMENT_ACCOUNT", "111111111111")
    monkeypatch.setattr(app, "build_role_arns", lambda acct, region: config_rule_roles)
    policy = app.update_kms_key_policy("222222222222", "us-east-1", ROLE_ARN)
    expected = [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    ]
    if config_rule_roles:
        expected.append(
            {"Principal": {"AWS": config_rule_roles}, "Sid": "Allow IAM Role Access", "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}
        )
    # The same policy as before this change, so search_key_policies still finds keys created by earlier versions
    assert policy["Statement"] == expected
    assert app.KMS_KEY_POLICIES == json.loads(KEY_POLICIES.read_text()), "update_kms_key_policy changed the loaded template"
