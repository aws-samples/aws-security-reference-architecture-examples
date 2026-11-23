"""Fake member-API client shared by the GuardDuty, Detective and Security Hub member-batch tests."""

from __future__ import annotations

from typing import Any, Callable


class CountedResponse(dict):
    """An API response that fails the test if it is read many times, so a retry loop that stops calling
    the API (and would spin forever on the same response) fails instead of hanging."""

    MAX_READS = 200

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.reads = 0

    def _count(self) -> None:
        self.reads += 1
        assert self.reads <= self.MAX_READS, "retry loop kept reading the same response without calling the API again"

    def __getitem__(self, key: Any) -> Any:
        self._count()
        return super().__getitem__(key)

    def get(self, key: Any, default: Any = None) -> Any:
        self._count()
        return super().get(key, default)

    def __contains__(self, key: object) -> bool:
        self._count()
        return super().__contains__(key)


class FakeMemberApi:
    """Records each call's account IDs and answers with UnprocessedAccounts chosen by a callback.

    `unprocessed(call_number, account_ids)` returns the UnprocessedAccounts entries for that call.
    A call cap turns an accidental infinite retry loop into a test failure instead of a hang.
    """

    def __init__(self, unprocessed: Callable[[int, list], list], ids_key: str, max_calls: int = 50) -> None:
        self.unprocessed = unprocessed
        self.ids_key = ids_key
        self.max_calls = max_calls
        self.calls: list = []

    def __call__(self, **kwargs: Any) -> dict:
        items = kwargs[self.ids_key]
        account_ids = [item if isinstance(item, str) else item["AccountId"] for item in items]
        self.calls.append({"account_ids": account_ids, "kwargs": kwargs})
        assert len(self.calls) <= self.max_calls, "retry loop did not terminate"
        return CountedResponse(UnprocessedAccounts=self.unprocessed(len(self.calls), account_ids))


def account_ids(count: int) -> list:
    return [f"{100000000000 + number}" for number in range(count)]


def account_records(count: int, email_key: str = "Email") -> list:
    return [{"AccountId": account_id, email_key: f"{account_id}@example.invalid"} for account_id in account_ids(count)]
