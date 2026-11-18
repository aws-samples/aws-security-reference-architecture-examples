"""Retry behaviour tests for the ``guardduty_org`` Lambda handler.

The handler talks to GuardDuty only through the boto3 client it is given, so a
fake client plus a counted ``sleep`` reproduces every row of the issue table
without touching AWS.
"""

import guardduty
import pytest

MAX_RETRY = guardduty.MAX_RETRY


class FakeGuardDutyClient:
    """GuardDuty client double that replays prepared responses."""

    def __init__(self, update_responses, create_responses):
        self.update_responses = list(update_responses)
        self.create_responses = list(create_responses)
        self.update_calls = []
        self.create_calls = []

    def update_member_detectors(self, **kwargs):
        self.update_calls.append(kwargs["AccountIds"])
        return self.update_responses.pop(0)

    def create_members(self, **kwargs):
        self.create_calls.append(kwargs["AccountDetails"])
        return self.create_responses.pop(0)


class Sleeper:
    """Counted replacement for ``guardduty.sleep`` that refuses to busy-loop."""

    def __init__(self, limit=20):
        self.limit = limit
        self.calls = 0

    def __call__(self, seconds):
        self.calls += 1
        if self.calls > self.limit:
            raise RuntimeError("retry loop never stops sleeping")


def unprocessed(accounts):
    """Return an ``UnprocessedAccounts`` response for ids or account details."""
    account_ids = [account["AccountId"] if isinstance(account, dict) else account for account in accounts]
    return {"UnprocessedAccounts": [{"AccountId": account_id, "Result": "InternalServerError"} for account_id in account_ids]}


def account_ids(count):
    """Return ``count`` account id strings."""
    return [str(100000000000 + number) for number in range(count)]


def member_details(count):
    """Return ``count`` GuardDuty account details."""
    return [{"AccountId": account_id} for account_id in account_ids(count)]


@pytest.fixture
def sleeper(mocker):
    """Replace ``sleep`` with a counter."""
    counter = Sleeper()
    mocker.patch.object(guardduty, "sleep", counter)
    return counter


def test_update_raises_when_a_non_last_batch_never_succeeds(sleeper):
    """A batch that never gets configured must fail the whole call."""
    accounts = account_ids(60)
    client = FakeGuardDutyClient(
        update_responses=[unprocessed(accounts[:50]) for _ in range(MAX_RETRY + 1)],
        create_responses=[],
    )

    with pytest.raises(ValueError, match="Unprocessed Member Accounts while Updating Member Detectors"):
        guardduty.update_member_detectors(client, "detector", accounts, {"GUARDDUTY": True})

    assert len(client.update_calls) == MAX_RETRY + 1
    assert sleeper.calls == MAX_RETRY
    assert all(len(call) == 50 for call in client.update_calls)


def test_update_retries_a_successful_batch_exactly_once(sleeper):
    """One retry is enough when the second attempt is clean."""
    accounts = account_ids(1)
    client = FakeGuardDutyClient(update_responses=[unprocessed(accounts), {"UnprocessedAccounts": []}], create_responses=[])

    guardduty.update_member_detectors(client, "detector", accounts, {"GUARDDUTY": True})

    assert len(client.update_calls) == 2
    assert sleeper.calls == 1


def test_update_raises_after_max_retry(sleeper):
    """The retry cap is ``MAX_RETRY``, not one failed attempt."""
    accounts = account_ids(1)
    client = FakeGuardDutyClient(update_responses=[unprocessed(accounts) for _ in range(MAX_RETRY + 1)], create_responses=[])

    with pytest.raises(ValueError, match="Unprocessed Member Accounts while Updating Member Detectors"):
        guardduty.update_member_detectors(client, "detector", accounts, {"GUARDDUTY": True})

    assert len(client.update_calls) == MAX_RETRY + 1
    assert sleeper.calls == MAX_RETRY


def test_create_returns_after_a_successful_retry(sleeper):
    """``create_members`` must not spin once the retry succeeds."""
    details = member_details(1)
    client = FakeGuardDutyClient(update_responses=[], create_responses=[unprocessed(details), {"UnprocessedAccounts": []}])

    guardduty.create_members(client, "detector", details)

    assert len(client.create_calls) == 2
    assert sleeper.calls == 1


def test_create_sleeps_between_retries_and_then_raises(sleeper):
    """Sleeping belongs inside the retry loop, and the cap is ``MAX_RETRY``."""
    details = member_details(1)
    client = FakeGuardDutyClient(update_responses=[], create_responses=[unprocessed(details) for _ in range(MAX_RETRY + 1)])

    with pytest.raises(ValueError, match="Unprocessed Member Accounts while Creating Members"):
        guardduty.create_members(client, "detector", details)

    assert len(client.create_calls) == MAX_RETRY + 1
    assert sleeper.calls == MAX_RETRY
