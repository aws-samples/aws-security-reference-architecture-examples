"""Unit tests for the GuardDuty member-account batch and retry handling (#387).

No AWS calls are made: the GuardDuty client is a fake, and `sleep` is replaced by a counter.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lambda_module import load_lambda_module  # noqa: E402
from member_batches_fake import FakeMemberApi, account_ids, account_records  # noqa: E402

SRC = "aws_sra_examples/solutions/guardduty/guardduty_org/lambda/src"
RETRYABLE = "The request is rejected because the input detectorId is not owned by the current account."  # any Result without "error"


@pytest.fixture
def guardduty(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = load_lambda_module(SRC, "guardduty", "sra_guardduty_org_guardduty")
    module.sleeps = []
    monkeypatch.setattr(module, "sleep", module.sleeps.append)
    return module


class FakeGuardDuty:
    def __init__(self, unprocessed=lambda call, ids: [], max_calls: int = 50) -> None:
        self.create_members = FakeMemberApi(unprocessed, "AccountDetails", max_calls)
        self.update_member_detectors = FakeMemberApi(unprocessed, "AccountIds", max_calls)
        self.disassociate_members = FakeMemberApi(unprocessed, "AccountIds", max_calls)
        self.delete_members = FakeMemberApi(unprocessed, "AccountIds", max_calls)


def unprocessed_entries(ids: list, result: str = RETRYABLE) -> list:
    return [{"AccountId": account_id, "Result": result} for account_id in ids]


def test_create_members_batches_of_50(guardduty: ModuleType) -> None:
    client = FakeGuardDuty()
    guardduty.create_members(client, "detector", account_records(120))
    assert [len(call["account_ids"]) for call in client.create_members.calls] == [50, 50, 20]
    assert guardduty.sleeps == []


def test_create_members_finishes_after_a_successful_retry(guardduty: ModuleType) -> None:
    """Before the fix, this busy-looped until the Lambda timed out (#387)."""
    client = FakeGuardDuty(lambda call, ids: unprocessed_entries(ids[:2]) if call == 1 else [])
    guardduty.create_members(client, "detector", account_records(10))
    assert len(client.create_members.calls) == 2
    assert client.create_members.calls[1]["account_ids"] == account_ids(2)
    assert guardduty.sleeps == [guardduty.SLEEP_SECONDS]


def test_create_members_raises_after_max_retries(guardduty: ModuleType) -> None:
    client = FakeGuardDuty(lambda call, ids: unprocessed_entries(ids))
    with pytest.raises(ValueError, match="still unprocessed after 5 retries while creating members"):
        guardduty.create_members(client, "detector", account_records(3))
    assert len(client.create_members.calls) == guardduty.MAX_RETRY + 1
    assert len(guardduty.sleeps) == guardduty.MAX_RETRY


def test_create_members_raises_at_once_on_an_error_result(guardduty: ModuleType) -> None:
    client = FakeGuardDuty(lambda call, ids: unprocessed_entries(ids[:1], "Internal error while creating member"))
    with pytest.raises(ValueError, match="Error while creating members"):
        guardduty.create_members(client, "detector", account_records(3))
    assert len(client.create_members.calls) == 1
    assert guardduty.sleeps == []


def test_update_member_detectors_raises_when_a_non_last_batch_never_succeeds(guardduty: ModuleType) -> None:
    """Before the fix, the first batch's failure was ignored and the function returned normally (#387)."""
    first_batch = set(account_ids(50))
    client = FakeGuardDuty(lambda call, ids: unprocessed_entries([i for i in ids if i in first_batch]))
    with pytest.raises(ValueError, match="while updating member detectors"):
        guardduty.update_member_detectors(client, "detector", account_ids(60), {})
    assert len(client.update_member_detectors.calls) == guardduty.MAX_RETRY + 1
    assert all(set(call["account_ids"]) <= first_batch for call in client.update_member_detectors.calls)


def test_update_member_detectors_retries_only_unprocessed_accounts_once(guardduty: ModuleType) -> None:
    """The #353 scenario: one account in the last batch is unprocessed once. Before the fix: 3 calls and 2 sleeps."""
    target = account_ids(60)[55]
    client = FakeGuardDuty(lambda call, ids: unprocessed_entries([target]) if call == 2 else [])
    guardduty.update_member_detectors(client, "detector", account_ids(60), {})
    assert [call["account_ids"] for call in client.update_member_detectors.calls][2] == [target]
    assert len(client.update_member_detectors.calls) == 3
    assert guardduty.sleeps == [guardduty.SLEEP_SECONDS]


def test_update_member_detectors_keeps_the_configuration_on_every_batch(guardduty: ModuleType) -> None:
    client = FakeGuardDuty()
    features = {"S3_DATA_EVENTS": "ENABLED"}
    expected = guardduty.set_configuration_params("detector", account_ids(1), features)
    guardduty.update_member_detectors(client, "detector", account_ids(51), features)
    for call in client.update_member_detectors.calls:
        assert {k: v for k, v in call["kwargs"].items() if k != "AccountIds"} == {k: v for k, v in expected.items() if k != "AccountIds"}
    assert [len(call["account_ids"]) for call in client.update_member_detectors.calls] == [50, 1]


def test_remove_members_batches_and_does_not_block_teardown(guardduty: ModuleType) -> None:
    """Before the fix, all members went into one call; GuardDuty processes 50 and returned the rest as "Maximum number of results exceeded", which was ignored."""
    client = FakeGuardDuty(lambda call, ids: unprocessed_entries(ids[:1]))
    guardduty.remove_members(client, "detector", account_ids(120), "us-east-1")
    assert [len(call["account_ids"]) for call in client.disassociate_members.calls] == [50, 50, 20]
    assert [len(call["account_ids"]) for call in client.delete_members.calls] == [50, 50, 20]
    assert guardduty.sleeps == []


class FakeRegionalGuardDuty(FakeGuardDuty):
    def __init__(self, region: str) -> None:
        super().__init__()
        self.region = region

    def list_detectors(self) -> dict:
        return {"DetectorIds": [f"detector-{self.region}"]}


class FakeSession:
    def __init__(self) -> None:
        self.clients: dict = {}

    def client(self, service: str, region_name: str, **kwargs: object) -> FakeRegionalGuardDuty:
        return self.clients.setdefault(region_name, FakeRegionalGuardDuty(region_name))


def test_verify_and_update_members_uses_each_regions_client(guardduty: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Before the fix, this loop reused the last Region's client, so the other Regions' members were never updated."""
    checked: list = []
    monkeypatch.setattr(guardduty, "check_members", lambda client, detector_id, accounts: checked.append((client.region, detector_id)) or [])
    session = FakeSession()
    guardduty.verify_and_update_members(session, ["us-east-2", "us-east-1"], account_records(3), account_ids(3), {})
    assert checked == [("us-east-2", "detector-us-east-2"), ("us-east-1", "detector-us-east-1")]
    for region in ("us-east-2", "us-east-1"):
        calls = session.clients[region].update_member_detectors.calls
        assert [call["kwargs"]["DetectorId"] for call in calls] == [f"detector-{region}"]


def test_verify_and_update_members_raises_when_a_region_has_no_detector(guardduty: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guardduty, "check_members", lambda client, detector_id, accounts: [])

    class NoDetectorSession(FakeSession):
        def client(self, service: str, region_name: str, **kwargs: object) -> FakeRegionalGuardDuty:
            client = super().client(service, region_name)
            client.list_detectors = lambda: {"DetectorIds": []}
            return client

    with pytest.raises(ValueError, match="No GuardDuty detector found .* us-east-2"):
        guardduty.verify_and_update_members(NoDetectorSession(), ["us-east-2"], account_records(1), account_ids(1), {})
