"""Static check: the Detective configuration Lambda role may call Organizations write actions only for Detective."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SOLUTION = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/detective/detective_org"
TEMPLATE = SOLUTION / "templates/sra-detective-org-configuration.yaml"
APP = SOLUTION / "lambda/src/app.py"
WRITE_ACTIONS = {
    "organizations:DeregisterDelegatedAdministrator",
    "organizations:DisableAWSServiceAccess",
    "organizations:EnableAWSServiceAccess",
    "organizations:RegisterDelegatedAdministrator",
}
SERVICE_PRINCIPAL_KEY = re.compile(r"^\s*organizations:ServicePrincipal:\s*(.*?)\s*$")


# Minimal block-style YAML helpers (no YAML parser is in the locked dependencies).
def indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def child_block(lines: list, index: int) -> list:
    """Return the lines nested under lines[index], that is, the following lines indented further than it."""
    parent = indent(lines[index])
    block = []
    for line in lines[index + 1 :]:
        if line.strip() and indent(line) <= parent:
            break
        block.append(line)
    return block


def statements(lines: list) -> list:
    """Split every `Statement:` list into its items, whether or not an item has a Sid."""
    items: list = []
    for index, line in enumerate(lines):
        if line.strip() != "Statement:":
            continue
        block = child_block(lines, index)
        item_indent = min(indent(item) for item in block if item.lstrip().startswith("- "))
        for item in block:
            if item.strip() and indent(item) == item_indent and item.lstrip().startswith("- "):
                items.append([item])
            elif items and item.strip():
                items[-1].append(item)
    return items


def is_limited_to(statement: list, principal: str) -> bool:
    """True when the statement has StringEquals organizations:ServicePrincipal set to exactly `principal`."""
    for index, line in enumerate(statement):
        if line.strip() != "Condition:":
            continue
        condition = child_block(statement, index)
        for operator_index, operator in enumerate(condition):
            if operator.strip() != "StringEquals:":
                continue
            keys = child_block(condition, operator_index)
            for key_index, key in enumerate(keys):
                match = SERVICE_PRINCIPAL_KEY.match(key)
                if not match:
                    continue
                values = [match.group(1)] if match.group(1) else [value.strip().removeprefix("- ") for value in child_block(keys, key_index)]
                return bool(values) and all(value.strip("'\"") == principal for value in values)
    return False


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
