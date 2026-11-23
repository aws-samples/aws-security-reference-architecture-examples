"""Static checks: the Security Hub configuration Lambda role, in CloudFormation and Terraform.

- securityhub:EnableOrganizationAdminAccount, DisableOrganizationAdminAccount and ListOrganizationAdminAccounts are allowed
  only on this account's hub/default (the CloudFormation scope from #360, extended to the list action and to Terraform).
- The Organizations write actions require organizations:ServicePrincipal to equal SERVICE_NAME in app.py, with StringEquals,
  so a request without the key is denied.

No AWS calls are made.
"""

from __future__ import annotations

import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cfn_yaml  # noqa: E402
import tf_hcl  # noqa: E402

ROOT = Path(__file__).resolve().parents[2] / "aws_sra_examples"
TF = ROOT / "terraform/solutions/security_hub/configuration/main.tf"
CFN = ROOT / "solutions/securityhub/securityhub_org/templates/sra-securityhub-org-configuration.yaml"
APP = ROOT / "solutions/securityhub/securityhub_org/lambda/src/app.py"
DOCUMENT = "security_hub_org_policy_securityhub"
TF_HUB = "arn:${data.aws_partition.current.partition}:securityhub:*:${data.aws_caller_identity.current.account_id}:hub/default"
CFN_HUB = "!Sub arn:${AWS::Partition}:securityhub:*:${AWS::AccountId}:hub/default"
# The only Security Hub resources the role may name: this account's hub, and its /accounts resource (EnableSecurityHub)
TF_SECURITYHUB_RESOURCE = re.compile(
    r"arn:\$\{data\.aws_partition\.current\.partition\}:securityhub:\*:\$\{data\.aws_caller_identity\.current\.account_id\}:(hub/default|/accounts)"
)
ADMIN_ACTIONS = [
    "securityhub:DisableOrganizationAdminAccount",
    "securityhub:EnableOrganizationAdminAccount",
    "securityhub:ListOrganizationAdminAccounts",
]
ORGANIZATIONS_WRITES = [
    "organizations:DeregisterDelegatedAdministrator",
    "organizations:DisableAWSServiceAccess",
    "organizations:EnableAWSServiceAccess",
    "organizations:RegisterDelegatedAdministrator",
]
READ = re.compile(r"organizations:(Describe|List)\w+")
ADMIN_AND_ENABLE = [*ADMIN_ACTIONS, "securityhub:EnableSecurityHub"]


def matches(action: str, patterns: list) -> bool:
    return any(fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns)


def tf_statements() -> list:
    found = []
    for document in tf_hcl.policy_documents(TF):
        for statement in tf_hcl.statements(document):
            assert "not_actions" not in statement, "statement uses not_actions"
            if not re.search(r'effect\s*=\s*"Deny"', statement):
                found.append(statement)
    return found


def tf_granting(action: str) -> list:
    return [statement for statement in tf_statements() if matches(action, tf_hcl.list_values(statement, "actions"))]


def cfn_statements() -> list:
    """Return the role's Allow statements in its policies, without the trust policy (the statement with a Principal)."""
    lines = CFN.read_text().splitlines()
    start = lines.index("  rSecurityHubOrgLambdaRole:")
    found = []
    for statement in cfn_yaml.statements([lines[start], *cfn_yaml.child_block(lines, start)]):
        assert not cfn_yaml.values(statement, "NotAction"), "statement uses NotAction"
        if cfn_yaml.values(statement, "Effect") == ["Allow"] and not cfn_yaml.values(statement, "Principal"):
            found.append(statement)
    return found


def cfn_granting(action: str) -> list:
    return [statement for statement in cfn_statements() if matches(action, cfn_yaml.values(statement, "Action"))]


def is_allowed_action(action: str) -> bool:
    """Organizations: only reads and the four writes; Security Hub: only the admin actions and EnableSecurityHub; no `*` or `service:*`."""
    namespace = action.split(":")[0].lower()
    if namespace == "organizations":
        return action in ORGANIZATIONS_WRITES or bool(READ.fullmatch(action))
    if namespace == "securityhub":
        return action in ADMIN_AND_ENABLE
    return namespace != "*" and not action.endswith(":*")


def service_name() -> str:
    match = re.search(r'^SERVICE_NAME\s*=\s*"([^"]+)"', APP.read_text(), re.M)
    assert match, "SERVICE_NAME not found in app.py"
    return match.group(1)


def test_terraform_organization_admin_actions_are_limited_to_this_accounts_hub() -> None:
    for action in ADMIN_ACTIONS:
        statements = tf_granting(action)
        assert statements, action
        for statement in statements:
            assert tf_hcl.list_values(statement, "resources") == [TF_HUB], f"{action}:{statement}"


def test_cloudformation_organization_admin_actions_are_limited_to_this_accounts_hub() -> None:
    for action in ADMIN_ACTIONS:
        statements = cfn_granting(action)
        assert statements, action
        for statement in statements:
            assert cfn_yaml.values(statement, "Resource") == [CFN_HUB], action


def test_terraform_securityhub_actions_name_only_this_accounts_hub_resources() -> None:
    for statement in tf_statements():
        actions = tf_hcl.list_values(statement, "actions")
        if any(action.lower().startswith("securityhub:") or action == "*" for action in actions):
            for resource in tf_hcl.list_values(statement, "resources"):
                assert TF_SECURITYHUB_RESOURCE.fullmatch(resource), f"{resource}:{statement}"


def test_terraform_securityhub_policy_has_no_checkov_skip() -> None:
    document = re.search(rf'data "aws_iam_policy_document" "{DOCUMENT}" \{{\n(.*?)\n\}}\n', TF.read_text(), re.S)
    assert document and "checkov:skip" not in document.group(1)


def test_terraform_organizations_writes_require_exactly_the_security_hub_principal() -> None:
    for action in ORGANIZATIONS_WRITES:
        statements = tf_granting(action)
        assert statements, action
        for statement in statements:
            assert tf_hcl.conditions(statement) == [
                {"test": "StringEquals", "variable": "organizations:ServicePrincipal", "values": f'["{service_name()}"]'}
            ], f"{action}:{statement}"


def test_cloudformation_organizations_writes_require_exactly_the_security_hub_principal() -> None:
    for action in ORGANIZATIONS_WRITES:
        statements = cfn_granting(action)
        assert statements, action
        for statement in statements:
            assert cfn_yaml.condition(statement) == ["StringEquals:", f"organizations:ServicePrincipal: {service_name()}"], action


def test_terraform_role_grants_organizations_and_security_hub_only_what_it_uses() -> None:
    for statement in tf_statements():
        for action in tf_hcl.list_values(statement, "actions"):
            assert is_allowed_action(action), f"{action}:{statement}"


def test_cloudformation_role_grants_organizations_and_security_hub_only_what_it_uses() -> None:
    for statement in cfn_statements():
        for action in cfn_yaml.values(statement, "Action"):
            assert is_allowed_action(action), f"{action}:{statement}"
