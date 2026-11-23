"""Static checks: the Security Lake key gives other accounts only kms:Decrypt (no AWS calls are made).

The key is deployed in the delegated administrator account (Log Archive). Only that account's root is delegated full key
control; the Audit and Management accounts get kms:Decrypt, as in the GuardDuty, Macie and Config delivery keys.
"""

from __future__ import annotations

import sys
from fnmatch import fnmatchcase
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cfn_yaml import file_block, statements, values  # noqa: E402

KMS_KEY = (
    Path(__file__).resolve().parents[2] / "aws_sra_examples/solutions/security_lake/security_lake_org/templates/sra-security-lake-org-kms-key.yaml"
)
OWN_ROOT = "!Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
OTHER_ACCOUNTS = ["pAuditAccountId", "pManagementAccountId"]
# Actions beyond Decrypt that KMS allows from another account, and key administration actions
NOT_FOR_OTHER_ACCOUNTS = ["kms:CreateGrant", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncryptTo", "kms:PutKeyPolicy"]


def key_statements() -> list:
    return statements(["  rSecurityLakeKey:", *file_block(KMS_KEY, "  rSecurityLakeKey:")])


def actions(statement: list) -> list:
    found = values(statement, "Action")
    assert not any(value.startswith("[") for value in found), "use a block list for Action, so the test can read it"
    return found


def grants(statement: list, action: str) -> bool:
    if values(statement, "Effect") != ["Allow"]:
        return False
    assert not values(statement, "NotAction"), "key policy statement uses NotAction"
    assert not values(statement, "NotPrincipal"), "key policy statement uses NotPrincipal"
    return any(fnmatchcase(action.lower(), pattern.lower()) for pattern in actions(statement))


def test_only_the_key_accounts_root_has_full_key_access() -> None:
    full = [statement for statement in key_statements() if grants(statement, "kms:PutKeyPolicy")]
    assert [values(statement, "AWS") for statement in full] == [[OWN_ROOT]]


def test_audit_and_management_accounts_get_only_decrypt() -> None:
    for parameter in OTHER_ACCOUNTS:
        # Any statement that names the account, in any form (block or flow list, quoted or not)
        naming = [statement for statement in key_statements() if any(parameter in line for line in statement)]
        assert len(naming) == 1, parameter
        assert actions(naming[0]) == ["kms:Decrypt"], parameter
        assert not any(grants(naming[0], action) for action in NOT_FOR_OTHER_ACCOUNTS), parameter


def test_no_statement_allows_any_principal_or_any_account() -> None:
    for statement in key_statements():
        assert values(statement, "Principal") != ["*"], statement
        for principal in values(statement, "AWS"):
            assert principal.strip("'\"") != "*" and "iam::*:" not in principal, principal
