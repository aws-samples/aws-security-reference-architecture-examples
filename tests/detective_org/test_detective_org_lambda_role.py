"""Static check: the Detective configuration Lambda role may call Organizations write actions only for Detective."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import child_block, statements, string_equals  # noqa: E402

SOLUTION = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/detective/detective_org"
TEMPLATE = SOLUTION / "templates/sra-detective-org-configuration.yaml"
APP = SOLUTION / "lambda/src/app.py"
WRITE_ACTIONS = {
    "organizations:DeregisterDelegatedAdministrator",
    "organizations:DisableAWSServiceAccess",
    "organizations:EnableAWSServiceAccess",
    "organizations:RegisterDelegatedAdministrator",
}


def is_limited_to(statement: list, principal: str) -> bool:
    """True when the statement has StringEquals organizations:ServicePrincipal set to exactly `principal`."""
    return string_equals(statement, "organizations:ServicePrincipal") == [principal]


def lambda_role() -> list:
    lines = TEMPLATE.read_text().splitlines()
    return child_block(lines, lines.index("  rDetectiveOrgLambdaRole:"))


def service_principal() -> str:
    match = re.search(r'^SERVICE_NAME = "([^"]+)"', APP.read_text(), re.M)
    assert match, "SERVICE_NAME not found in app.py"
    return match.group(1)


def test_every_organizations_write_action_is_limited_to_the_detective_service_principal() -> None:
    principal = service_principal()
    found: set = set()
    for statement in statements(lambda_role()):
        actions = WRITE_ACTIONS & set(re.findall(r"organizations:\w+", "\n".join(statement)))
        if actions:
            found |= actions
            assert is_limited_to(
                statement, principal
            ), f"{statement[0].strip()} allows {sorted(actions)} without organizations:ServicePrincipal = {principal}"
    assert found == WRITE_ACTIONS, f"expected all Organizations write actions in the role, found {sorted(found)}"


def test_the_role_no_longer_suppresses_checkov_ckv_aws_111() -> None:
    assert "CKV_AWS_111" not in "\n".join(lambda_role())


POLICY = """\
      PolicyDocument:
        Statement:
          - Sid: First
            Effect: Allow
            Action: organizations:EnableAWSServiceAccess
            Condition:
              StringEquals:
{condition}
            Resource: '*'
          - Effect: Allow
            Action:
              - organizations:RegisterDelegatedAdministrator
            Resource: '*'
"""


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("                organizations:ServicePrincipal: detective.amazonaws.com", True),
        ("                organizations:ServicePrincipal: 'detective.amazonaws.com'", True),
        ("                aws:PrincipalOrgID: o-example\n                organizations:ServicePrincipal: detective.amazonaws.com", True),
        ("                organizations:ServicePrincipal:\n                  - detective.amazonaws.com", True),
        ("                organizations:ServicePrincipal: guardduty.amazonaws.com", False),
        (
            "                organizations:ServicePrincipal:\n                  - detective.amazonaws.com\n                  - guardduty.amazonaws.com",
            False,
        ),
        ("                aws:PrincipalOrgID: o-example", False),
    ],
)
def test_condition_check_reads_the_whole_string_equals_block(condition: str, expected: bool) -> None:
    first, second = statements(POLICY.format(condition=condition).splitlines())

    assert is_limited_to(first, "detective.amazonaws.com") is expected
    assert not is_limited_to(second, "detective.amazonaws.com")


def test_a_statement_without_a_sid_is_its_own_statement() -> None:
    items = statements(POLICY.format(condition="                organizations:ServicePrincipal: detective.amazonaws.com").splitlines())

    assert [item[0].strip() for item in items] == ["- Sid: First", "- Effect: Allow"]
    assert "organizations:RegisterDelegatedAdministrator" in "\n".join(items[1])
