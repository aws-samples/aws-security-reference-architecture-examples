"""Unit tests for the Detective member-account batch and retry handling (#387).

No AWS calls are made: the Detective client is a fake, and `sleep` is replaced by a counter.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lambda_module import load_lambda_module  # noqa: E402
from member_batches_fake import FakeMemberApi, account_ids, account_records  # noqa: E402

SRC = "aws_sra_examples/solutions/detective/detective_org/lambda/src"


@pytest.fixture
def detective(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = load_lambda_module(SRC, "detective", "sra_detective_org_detective")
    module.sleeps = []
    monkeypatch.setattr(module, "sleep", module.sleeps.append)
    return module


class FakeDetective:
    def __init__(self, unprocessed=lambda call, ids: [], existing_members: tuple = ()) -> None:
        self.create_members = FakeMemberApi(unprocessed, "Accounts")
        self.existing_members = existing_members

    def list_members(self, **kwargs: object) -> dict:
        return {"MemberDetails": [{"AccountId": account_id, "Status": "ENABLED"} for account_id in self.existing_members]}


def reasons(ids: list, reason: str = "Account could not be added, try again") -> list:
    return [{"AccountId": account_id, "Reason": reason} for account_id in ids]


def test_create_members_batches_of_50_and_skips_existing_members(detective: ModuleType) -> None:
    client = FakeDetective(existing_members=tuple(account_ids(5)))
    detective.create_members(account_records(125), client, "graph")
    assert [len(call["account_ids"]) for call in client.create_members.calls] == [50, 50, 20]
    assert not set(account_ids(5)) & {i for call in client.create_members.calls for i in call["account_ids"]}


def test_create_members_raises_when_accounts_stay_unprocessed(detective: ModuleType) -> None:
    """Before the fix, unprocessed accounts were dropped silently: the raise could never fire (#387)."""
    client = FakeDetective(lambda call, ids: reasons(ids))
    with pytest.raises(ValueError, match="still unprocessed after 5 retries while creating Detective members"):
        detective.create_members(account_records(3), client, "graph")
    assert len(client.create_members.calls) == detective.MAX_RETRY + 1


def test_create_members_sleeps_between_every_retry(detective: ModuleType) -> None:
    """Before the fix, it slept once and then retried back to back."""
    client = FakeDetective(lambda call, ids: reasons(ids) if call <= 3 else [])
    detective.create_members(account_records(3), client, "graph")
    assert detective.sleeps == [detective.SLEEP_SECONDS] * 3


def test_create_members_treats_already_a_member_as_done(detective: ModuleType) -> None:
    client = FakeDetective(lambda call, ids: reasons(ids[:1], "Account is already a member"))
    detective.create_members(account_records(3), client, "graph")
    assert len(client.create_members.calls) == 1
    assert detective.sleeps == []


def test_create_members_raises_at_once_on_an_error_reason(detective: ModuleType) -> None:
    client = FakeDetective(lambda call, ids: reasons(ids[:1], "Internal error"))
    with pytest.raises(ValueError, match="Error while creating Detective members"):
        detective.create_members(account_records(3), client, "graph")
    assert len(client.create_members.calls) == 1
