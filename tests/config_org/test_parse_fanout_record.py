"""Unit tests for the config_org SNS fan-out record validation (no AWS calls are made)."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lambda_module import load_lambda_module  # noqa: E402

# app.py builds boto3 clients at import (inert credentials are supplied during the load) and imports
# its sibling `common`; loading it under a unique name keeps both out of sys.modules for later tests.
app = load_lambda_module("aws_sra_examples/solutions/config/config_org/lambda/src", "app", "sra_config_org_app")
common = app.common

TOPIC = "arn:aws:sns:us-east-1:111111111111:sra-config-org-configuration"
REGIONS = {"us-east-1", "us-west-2"}
ACCOUNT_IDS = {"222222222222", "333333333333"}


def record(message: object, topic: str = TOPIC) -> dict:
    body = message if isinstance(message, str) else json.dumps(message)
    return {"Sns": {"TopicArn": topic, "MessageId": "id-1", "Message": body}}


def parse(rec: dict) -> tuple | None:
    return app.parse_fanout_record(rec, TOPIC, REGIONS, ACCOUNT_IDS)


def test_valid_record_is_returned() -> None:
    message = {"Action": "configure", "Region": "us-west-2", "Accounts": [{"AccountId": "222222222222"}, {"AccountId": "333333333333"}]}
    assert parse(record(message)) == ("us-west-2", message["Accounts"])


@pytest.mark.parametrize(
    "rec",
    [
        record(
            {"Action": "configure", "Region": "us-east-1", "Accounts": [{"AccountId": "222222222222"}]},
            topic="arn:aws:sns:us-east-1:999999999999:other",
        ),
        record("not json"),
        record([1, 2]),
        record({"Region": "us-east-1", "Accounts": [{"AccountId": "222222222222"}]}),
        record({"Action": "delete", "Region": "us-east-1", "Accounts": [{"AccountId": "222222222222"}]}),
        record({"Action": "configure", "Region": "eu-west-1", "Accounts": [{"AccountId": "222222222222"}]}),
        record({"Action": "configure", "Region": ["us-east-1"], "Accounts": [{"AccountId": "222222222222"}]}),
        record({"Action": "configure", "Region": None, "Accounts": [{"AccountId": "222222222222"}]}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": None}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": 5}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": "222222222222"}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": [{"AccountId": "444444444444"}]}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": [{"AccountId": ["222222222222"]}]}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": ["222222222222"]}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": [{"AccountId": 222222222222}]}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": [{"AccountId": True}]}),
        record({"Action": "configure", "Region": "us-east-1", "Accounts": [{"AccountId": "222222222222\n"}]}),
        record({"Action": "configure", "Region": "us-east-1\n", "Accounts": [{"AccountId": "222222222222"}]}),
        {"Sns": {}},
        {},
    ],
)
def test_malformed_or_untrusted_record_is_dropped(rec: dict) -> None:
    assert parse(rec) is None


def test_accounts_outside_the_organization_are_dropped_but_valid_ones_kept() -> None:
    message = {"Action": "configure", "Region": "us-east-1", "Accounts": [{"AccountId": "222222222222"}, {"AccountId": "444444444444"}, "x"]}
    assert parse(record(message)) == ("us-east-1", [{"AccountId": "222222222222"}])


def test_organization_account_list_has_no_email_addresses(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    class FakePaginator:
        def paginate(self, **_kwargs: object) -> list:
            return [
                {
                    "Accounts": [
                        {"Id": "222222222222", "Email": "root@example.com", "Status": "ACTIVE"},
                        {"Id": "333333333333", "Email": "x@example.com", "Status": "SUSPENDED"},
                    ]
                }
            ]

    class FakeOrgClient:
        def get_paginator(self, _name: str) -> FakePaginator:
            return FakePaginator()

    monkeypatch.setattr(common, "ORG_CLIENT", FakeOrgClient())
    monkeypatch.setattr(common, "ORGANIZATIONS_THROTTLE_PERIOD", 0)
    with caplog.at_level(logging.INFO, logger="sra"):
        accounts = common.get_active_organization_accounts()
    assert accounts == [{"AccountId": "222222222222"}]
    assert "example.com" not in caplog.text


def test_candidate_regions_come_from_configuration_without_probing(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("must not call AWS")

    monkeypatch.setattr(common.boto3, "client", fail)
    monkeypatch.setattr(common.boto3, "Session", fail)
    assert common.get_candidate_regions("us-east-1, us-west-2,") == ["us-east-1", "us-west-2"]
    monkeypatch.setattr(common, "get_control_tower_regions", lambda: ["us-east-1"])
    assert common.get_candidate_regions("", True) == ["us-east-1"]


def sns_event(message: dict) -> dict:
    return {"Records": [record(message)]}


def patch_handler(monkeypatch: pytest.MonkeyPatch) -> list:
    """Replace the AWS-facing parts of process_event_sns and return the list that collects configure_accounts calls."""
    calls: list = []
    monkeypatch.setattr(
        app,
        "get_validated_parameters",
        lambda _event: {"ENABLED_REGIONS": "us-east-1,us-west-2", "CONTROL_TOWER_REGIONS_ONLY": "false", "SNS_TOPIC_ARN_FANOUT": TOPIC},
    )
    monkeypatch.setattr(common, "get_active_organization_accounts", lambda: [{"AccountId": a} for a in ACCOUNT_IDS])
    monkeypatch.setattr(common, "get_enabled_regions", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not probe Regions with STS")))
    monkeypatch.setattr(app, "configure_accounts", lambda _params, region, accounts: calls.append((region, accounts)))
    return calls


def test_handler_configures_a_valid_record_without_probing_regions(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_handler(monkeypatch)
    app.process_event_sns(sns_event({"Action": "configure", "Region": "us-west-2", "Accounts": [{"AccountId": "222222222222"}]}))
    assert calls == [("us-west-2", [{"AccountId": "222222222222"}])]


def test_handler_does_nothing_for_a_forged_record(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = patch_handler(monkeypatch)
    app.process_event_sns(sns_event({"Action": "configure", "Region": "eu-west-1", "Accounts": [{"AccountId": "222222222222"}]}))
    app.process_event_sns(sns_event({"Action": "configure", "Region": "us-east-1", "Accounts": None}))
    assert calls == []
