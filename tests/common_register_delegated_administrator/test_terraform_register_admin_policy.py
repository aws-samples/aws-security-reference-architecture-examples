"""Static checks: the Terraform register-delegated-admin Lambda role matches the CloudFormation role from #359.

Both deploy the same Lambda code (common_register_delegated_administrator/lambda/src/app.py), which accepts only the service
principals in VALID_SERVICE_PRINCIPAL_LIST. No AWS calls are made.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tf_hcl  # noqa: E402
from cfn_yaml import allows, child_block, condition, statements, values  # noqa: E402

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
APP = ROOT / "solutions/common/common_register_delegated_administrator/lambda/src/app.py"
CFN = ROOT / "solutions/common/common_register_delegated_administrator/templates/sra-common-register-delegated-administrator-ssm.yaml"
TF = ROOT / "terraform/solutions/register_delegated_administrator/register_admin/main.tf"
DOCUMENT = "register_delegated_admin_policy_organizations"
WRITES = [
    "organizations:DeregisterDelegatedAdministrator",
    "organizations:DisableAWSServiceAccess",
    "organizations:EnableAWSServiceAccess",
    "organizations:RegisterDelegatedAdministrator",
]
ACCOUNT_ARN = "arn:${data.aws_partition.current.partition}:organizations::*:account/o-*/*"
CFN_ACCOUNT_ARN = "!Sub arn:${AWS::Partition}:organizations::*:account/o-*/*"
LOG_ACTIONS = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
READ = r"organizations:(Describe|List)\w+"


def valid_service_principals() -> list:
    for node in ast.walk(ast.parse(APP.read_text())):
        if isinstance(node, ast.Assign) and any(getattr(target, "id", "") == "VALID_SERVICE_PRINCIPAL_LIST" for target in node.targets):
            return sorted(ast.literal_eval(node.value))
    raise AssertionError("VALID_SERVICE_PRINCIPAL_LIST not found in app.py")


def tf_statements() -> list:
    return tf_hcl.statements(tf_hcl.policy_documents(TF, DOCUMENT)[0])


def grants(statement: str, action: str) -> bool:
    assert "not_actions" not in statement, "statement uses not_actions"
    if re.search(r'effect\s*=\s*"Deny"', statement):
        return False
    return allows(tf_hcl.list_values(statement, "actions"), action)


def test_terraform_local_lists_the_service_principals_app_py_accepts() -> None:
    assert sorted(tf_hcl.list_values(TF.read_text(), "valid_service_principals")) == valid_service_principals()


def cfn_statements() -> list:
    lines = CFN.read_text().splitlines()
    start = lines.index("  rRegisterDelegatedAdminLambdaRole:")
    return statements([lines[start], *child_block(lines, start)])


def cfn_permission_statements() -> list:
    """Return the role's Allow statements in its policies, without the trust policy (the statement with a Principal)."""
    return [s for s in cfn_statements() if values(s, "Effect") == ["Allow"] and not values(s, "Principal")]


def test_cloudformation_organizations_writes_require_the_same_service_principals() -> None:
    expected = ["StringEquals:", "organizations:ServicePrincipal:", *(f"- {principal}" for principal in valid_service_principals())]
    for action in WRITES:
        granting = [
            statement
            for statement in cfn_statements()
            if values(statement, "Effect") == ["Allow"] and allows(values(statement, "Action"), action)
        ]
        assert granting, action
        for statement in granting:
            assert not values(statement, "NotAction"), action
            assert condition(statement)[:2] + sorted(condition(statement)[2:]) == expected, action


def test_every_terraform_organizations_write_requires_an_accepted_service_principal() -> None:
    for action in WRITES:
        granting = [statement for statement in tf_statements() if grants(statement, action)]
        assert granting, action
        for statement in granting:
            assert tf_hcl.conditions(statement) == [
                {"test": "StringEquals", "variable": "organizations:ServicePrincipal", "values": "local.valid_service_principals"}
            ], f"{action}:{statement}"


def test_terraform_register_and_deregister_are_limited_to_member_accounts() -> None:
    for action in ("organizations:RegisterDelegatedAdministrator", "organizations:DeregisterDelegatedAdministrator"):
        for statement in tf_statements():
            if grants(statement, action):
                assert tf_hcl.list_values(statement, "resources") == [ACCOUNT_ARN], action


def test_cloudformation_register_and_deregister_are_limited_to_member_accounts() -> None:
    for action in ("organizations:RegisterDelegatedAdministrator", "organizations:DeregisterDelegatedAdministrator"):
        granting = [s for s in cfn_permission_statements() if allows(values(s, "Action"), action)]
        assert granting, action
        for statement in granting:
            assert values(statement, "Resource") == [CFN_ACCOUNT_ARN], action


def test_cloudformation_role_grants_only_reads_the_four_writes_and_logging() -> None:
    for statement in cfn_permission_statements():
        assert not values(statement, "NotAction"), statement
        for action in values(statement, "Action"):
            assert action in WRITES or action in LOG_ACTIONS or re.fullmatch(READ, action), action


def test_unconditioned_cloudformation_statements_grant_only_reads_or_logging() -> None:
    for statement in cfn_permission_statements():
        if not condition(statement):
            actions = values(statement, "Action")
            assert actions and all(action in LOG_ACTIONS or re.fullmatch(READ, action) for action in actions), statement


def test_the_terraform_policy_grants_only_reads_and_the_four_writes() -> None:
    for statement in tf_statements():
        if not re.search(r'effect\s*=\s*"Deny"', statement):
            assert "not_actions" not in statement, statement
            for action in tf_hcl.list_values(statement, "actions"):
                assert action in WRITES or re.fullmatch(READ, action), action


def test_unconditioned_terraform_statements_grant_only_reads() -> None:
    for statement in tf_statements():
        if not tf_hcl.conditions(statement):
            actions = tf_hcl.list_values(statement, "actions")
            assert actions and all(re.fullmatch(READ, action) for action in actions), statement


def test_terraform_policy_has_no_checkov_skip() -> None:
    document = re.search(rf'data "aws_iam_policy_document" "{DOCUMENT}" \{{\n(.*?)\n\}}\n', TF.read_text(), re.S)
    assert document and "checkov:skip" not in document.group(1)
