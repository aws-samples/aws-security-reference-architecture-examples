"""Unit tests for the Security Hub member-account batch and retry handling (#387).

No AWS calls are made: the Security Hub client is a fake, and `sleep` is replaced by a counter.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lambda_module import load_lambda_module  # noqa: E402
from member_batches_fake import FakeMemberApi, account_ids, account_records  # noqa: E402

SRC = "aws_sra_examples/solutions/securityhub/securityhub_org/lambda/src"


@pytest.fixture
def securityhub(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = load_lambda_module(SRC, "securityhub", "sra_securityhub_org_securityhub")
    module.sleeps = []
    monkeypatch.setattr(module, "sleep", module.sleeps.append)
    return module


class FakeSecurityHub:
    def __init__(self, unprocessed=lambda call, ids: []) -> None:
        self.create_members = FakeMemberApi(unprocessed, "AccountDetails")


def results(ids: list) -> list:
    return [{"AccountId": account_id, "ProcessingResult": "Unable to process, try again"} for account_id in ids]


def test_create_members_batches_of_50(securityhub: ModuleType) -> None:
    """Before the fix, every account went into one call, which CreateMembers rejects above 50."""
    client = FakeSecurityHub()
    securityhub.create_members(client, account_records(120))
    assert [len(call["account_ids"]) for call in client.create_members.calls] == [50, 50, 20]


def test_create_members_raises_when_accounts_stay_unprocessed(securityhub: ModuleType) -> None:
    """Before the fix, unprocessed accounts were only logged and the run reported success."""
    client = FakeSecurityHub(lambda call, ids: results(ids))
    with pytest.raises(ValueError, match="still unprocessed after 5 retries while creating Security Hub members"):
        securityhub.create_members(client, account_records(3))
    assert len(client.create_members.calls) == securityhub.MAX_RETRY + 1
    assert securityhub.sleeps == [securityhub.SLEEP_SECONDS] * securityhub.MAX_RETRY


def test_create_members_retries_only_unprocessed_accounts(securityhub: ModuleType) -> None:
    client = FakeSecurityHub(lambda call, ids: results(ids[:1]) if call == 1 else [])
    securityhub.create_members(client, account_records(3))
    assert [call["account_ids"] for call in client.create_members.calls] == [account_ids(3), account_ids(1)]
