"""Static checks: security_lake_org key policy and configuration Lambda role conditions (no AWS calls are made)."""

from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import child_block, statements  # noqa: E402

SOLUTION = Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/security_lake/security_lake_org"
CONFIGURATION = SOLUTION / "templates/sra-security-lake-org-configuration.yaml"
KMS_KEY = SOLUTION / "templates/sra-security-lake-org-kms-key.yaml"
APP = SOLUTION / "lambda/src/app.py"
# A mapping key ends at the first ": " (or ":" at end of line); keys such as aws:SourceAccount contain ":".
MAPPING_KEY = re.compile(r"^\s*(\S+?):(?:\s+(.*))?$")
WRITE_ACTIONS = {
    "organizations:deregisterdelegatedadministrator",
    "organizations:disableawsserviceaccess",
    "organizations:enableawsserviceaccess",
    "organizations:registerdelegatedadministrator",
}


def service_principal() -> str:
    match = re.search(r'^SERVICE_NAME = "([^"]+)"', APP.read_text(), re.M)
    assert match, "SERVICE_NAME not found in app.py"
    return match.group(1)


def resource(template: Path, logical_id: str) -> list:
    lines = template.read_text().splitlines()
    start = lines.index(f"  {logical_id}:")
    return [lines[start], *child_block(lines, start)]


def values(statement: list, key: str) -> list:
    """Values of a scalar or list key (for example Action or NotAction) in one statement, unquoted and lower-cased."""
    for index, line in enumerate(statement):
        stripped = line.strip().removeprefix("- ")
        if stripped.startswith(f"{key}:"):
            inline = stripped.split(":", 1)[1].strip()
            items = (
                [inline] if inline else [item.strip().removeprefix("- ") for item in child_block(statement, index) if item.strip().startswith("- ")]
            )
            return [item.strip("'\"").lower() for item in items]
    return []


def grants_write(statement: list) -> set:
    if values(statement, "Effect") != ["allow"]:
        return set()
    granted = {action for action in WRITE_ACTIONS for pattern in values(statement, "Action") if fnmatch.fnmatchcase(action, pattern)}
    not_actions = values(statement, "NotAction")
    if not_actions:
        granted |= {action for action in WRITE_ACTIONS if not any(fnmatch.fnmatchcase(action, pattern) for pattern in not_actions)}
    return granted


def condition_values(statement: list, operator: str, key: str) -> list:
    """Values of `key` under `Condition: <operator>:` in one statement (scalar or list), unquoted."""
    for index, line in enumerate(statement):
        if line.strip() != "Condition:":
            continue
        condition = child_block(statement, index)
        for operator_index, operator_line in enumerate(condition):
            if operator_line.strip() != f"{operator}:":
                continue
            keys = child_block(condition, operator_index)
            for key_index, key_line in enumerate(keys):
                match = MAPPING_KEY.match(key_line)
                if not match or match.group(1).strip("'\"") != key:
                    continue
                inline = (match.group(2) or "").strip()
                items = [inline] if inline else [item.strip().removeprefix("- ") for item in child_block(keys, key_index)]
                return [item.strip("'\"") for item in items if item]
    return []


def test_every_organizations_write_grant_is_limited_to_security_lake() -> None:
    principal = service_principal()
    writers = [s for s in statements(resource(CONFIGURATION, "rSecurityLakeOrgLambdaRole")) if grants_write(s)]
    assert writers, "expected the role to grant Organizations write actions"
    for statement in writers:
        assert condition_values(statement, "StringEquals", "organizations:ServicePrincipal") == [principal], "\n".join(statement)


def test_lambda_role_has_no_ckv_aws_111_suppression() -> None:
    assert "CKV_AWS_111" not in "\n".join(resource(CONFIGURATION, "rSecurityLakeOrgLambdaRole"))


def test_s3_key_grant_is_limited_to_the_security_lake_buckets_in_this_account() -> None:
    grants = [s for s in statements(resource(KMS_KEY, "rSecurityLakeKey")) if any(line.strip() == "Service: s3.amazonaws.com" for line in s)]
    assert len(grants) == 1
    assert condition_values(grants[0], "StringEquals", "aws:SourceAccount") == ["!Ref AWS::AccountId"]
    assert condition_values(grants[0], "ArnLike", "aws:SourceArn") == ["!Sub arn:${AWS::Partition}:s3:::aws-security-data-lake-*"]
