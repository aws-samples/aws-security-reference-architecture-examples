"""Static check: the Firewall Manager delegate admin Lambda role may call Organizations write actions only for Firewall Manager."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import child_block, statements, string_equals, values  # noqa: E402

TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "aws_sra_examples/solutions/firewall_manager/firewall_manager_org/templates/sra-firewall-manager-org-delegate-admin.yaml"
)
SERVICE_PRINCIPAL = "fms.amazonaws.com"
# Called by Firewall Manager on the role's behalf when it associates the administrator account.
EXPECTED_WRITE_ACTIONS = {"organizations:EnableAWSServiceAccess", "organizations:RegisterDelegatedAdministrator"}


def lambda_role() -> list:
    lines = TEMPLATE.read_text().splitlines()
    return child_block(lines, lines.index("  rFirewallManagerDelegateAdminLambdaRole:"))


def organizations_actions(statement: list) -> set:
    """Organizations actions in the statement's Action key (not its condition keys)."""
    return {action for action in values(statement, "Action") if action.startswith("organizations:")}


def test_every_organizations_write_action_is_limited_to_firewall_manager() -> None:
    found: set = set()
    for statement in statements(lambda_role()):
        writes = {action for action in organizations_actions(statement) if not action.split(":")[1].startswith(("Describe", "List"))}
        if writes:
            found |= writes
            assert string_equals(statement, "organizations:ServicePrincipal") == [
                SERVICE_PRINCIPAL
            ], f"{statement[0].strip()} allows {sorted(writes)} without organizations:ServicePrincipal = {SERVICE_PRINCIPAL}"
    assert found == EXPECTED_WRITE_ACTIONS, f"expected Organizations write actions {sorted(EXPECTED_WRITE_ACTIONS)}, found {sorted(found)}"


def test_the_role_does_not_suppress_checkov() -> None:
    role = "\n".join(lambda_role())
    assert "CKV_AWS_109" not in role
    assert "CKV_AWS_111" not in role


POLICY = """\
            Statement:
              - Sid: First
                Effect: Allow
                Action: organizations:EnableAWSServiceAccess
                Condition:
                  StringEquals:
{condition}
                Resource: '*'
"""


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("                    organizations:ServicePrincipal: fms.amazonaws.com", ["fms.amazonaws.com"]),
        ("                    organizations:ServicePrincipal: 'fms.amazonaws.com'", ["fms.amazonaws.com"]),
        ("                    organizations:ServicePrincipal:\n                      - fms.amazonaws.com", ["fms.amazonaws.com"]),
        (
            "                    organizations:ServicePrincipal:\n                      - fms.amazonaws.com\n                      - guardduty.amazonaws.com",
            ["fms.amazonaws.com", "guardduty.amazonaws.com"],
        ),
        ("                    aws:PrincipalOrgID: o-example", None),
    ],
)
def test_string_equals_reads_scalar_and_list_values(condition: str, expected: list | None) -> None:
    (statement,) = statements(POLICY.format(condition=condition).splitlines())
    assert string_equals(statement, "organizations:ServicePrincipal") == expected
