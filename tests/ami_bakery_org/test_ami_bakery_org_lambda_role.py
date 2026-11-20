"""Static checks: the AMI Bakery configuration Lambda role grants no Organizations write actions (no AWS calls are made)."""

from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import child_block, statements, values  # noqa: E402

SOLUTION = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/ami_bakery/ami_bakery_org"
TEMPLATE = SOLUTION / "templates/sra-ami-bakery-org-configuration.yaml"
LAMBDA_SRC = SOLUTION / "lambda/src"
# Organizations write actions to probe wildcards and NotAction against; any other non-Describe/List action also counts.
KNOWN_WRITES = (
    "organizations:registerdelegatedadministrator",
    "organizations:deregisterdelegatedadministrator",
    "organizations:enableawsserviceaccess",
    "organizations:disableawsserviceaccess",
    "organizations:attachpolicy",
    "organizations:createaccount",
)


def lambda_role() -> list:
    lines = TEMPLATE.read_text().splitlines()
    start = lines.index("  rAMIBakeryOrgLambdaRole:")
    return [lines[start], *child_block(lines, start)]


def is_read(action: str) -> bool:
    return action.split(":", 1)[1].startswith(("describe", "list"))


def organizations_writes(statement: list) -> set:
    """Organizations write actions an Allow statement grants (case-insensitive; wildcards and NotAction count)."""
    if [value.lower() for value in values(statement, "Effect")] != ["allow"]:
        return set()
    actions = [action.lower() for action in values(statement, "Action")]
    granted = {
        action for action in actions if action.startswith("organizations:") and "*" not in action and "?" not in action and not is_read(action)
    }
    granted |= {known for known in KNOWN_WRITES for pattern in actions if ("*" in pattern or "?" in pattern) and fnmatch.fnmatchcase(known, pattern)}
    not_actions = [action.lower() for action in values(statement, "NotAction")]
    if not_actions:
        granted |= {known for known in KNOWN_WRITES if not any(fnmatch.fnmatchcase(known, pattern) for pattern in not_actions)}
    return granted


def test_lambda_role_grants_no_organizations_write_actions() -> None:
    granted = set().union(*(organizations_writes(statement) for statement in statements(lambda_role())))
    assert not granted, f"unexpected Organizations write actions: {sorted(granted)}"


def test_lambda_role_has_no_ckv_aws_111_suppression() -> None:
    assert "CKV_AWS_111" not in "\n".join(lambda_role())


def test_lambda_code_calls_no_organizations_write_api() -> None:
    """Heuristic cross-check on the Lambda source; the template test above is the real guard."""
    source = "\n".join(path.read_text() for path in LAMBDA_SRC.rglob("*.py"))
    for snake, pascal in (
        ("register_delegated_administrator", "RegisterDelegatedAdministrator"),
        ("deregister_delegated_administrator", "DeregisterDelegatedAdministrator"),
        ("enable_aws_service_access", "EnableAWSServiceAccess"),
        ("disable_aws_service_access", "DisableAWSServiceAccess"),
    ):
        assert not re.search(rf"\b({snake}|{pascal})\b", source), snake
