"""Unit tests for terraform_stack.py: terraform runs as an argument list, and Region names are validated (no AWS calls are made)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "aws_sra_examples/terraform/solutions/terraform_stack.py"
ACCOUNT = "123456789012"
REGION = "us-east-1"


def load_script() -> ModuleType:
    # Loaded under a unique name so it can't collide with another solution's module in sys.modules.
    spec = importlib.util.spec_from_file_location("sra_terraform_stack", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def stack() -> ModuleType:
    return load_script()


@pytest.fixture
def calls(stack: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list:
    recorded: list = []

    def fake_run(cmd: object, **kwargs: object) -> subprocess.CompletedProcess:
        recorded.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(stack.subprocess, "run", fake_run)
    return recorded


def fake_ssm(stack: ModuleType, monkeypatch: pytest.MonkeyPatch, regions: str, home_region: str = REGION) -> None:
    values = {"/sra/regions/customer-control-tower-regions": regions, "/sra/control-tower/home-region": home_region}
    client = SimpleNamespace(get_parameter=lambda Name, WithDecryption: {"Parameter": {"Value": values[Name]}})  # noqa: N803
    monkeypatch.setattr(stack.boto3, "client", lambda service: client)


def test_every_command_is_an_argument_list_without_a_shell(stack: ModuleType, calls: list) -> None:
    stack.init()
    stack.workspace_exists(ACCOUNT, REGION)
    stack.create_workspace(ACCOUNT, REGION)
    stack.switch_to_workspace(ACCOUNT, REGION)
    stack.plan(ACCOUNT, REGION)
    stack.apply(ACCOUNT, REGION)
    stack.destroy(ACCOUNT, REGION)

    assert len(calls) == 7
    for cmd, kwargs in calls:
        assert isinstance(cmd, list) and cmd[0] == "terraform"
        assert not kwargs.get("shell")
        assert kwargs.get("check") is True


def test_commands_have_the_expected_arguments(stack: ModuleType, calls: list) -> None:
    stack.init()
    stack.create_workspace(ACCOUNT, REGION)
    stack.switch_to_workspace(ACCOUNT, REGION)
    stack.plan(ACCOUNT, REGION)
    stack.apply(ACCOUNT, REGION)
    stack.destroy(ACCOUNT, REGION)

    variables = ["-var-file=config.tfvars", "-var", f"account_id={ACCOUNT}", "-var", f"account_region={REGION}"]
    assert [cmd for cmd, _ in calls] == [
        ["terraform", "init", "-backend-config=backend.tfvars"],
        ["terraform", "workspace", "new", f"{ACCOUNT}-{REGION}"],
        ["terraform", "workspace", "select", f"{ACCOUNT}-{REGION}"],
        ["terraform", "plan", *variables],
        ["terraform", "apply", *variables, "-auto-approve"],
        ["terraform", "destroy", *variables, "-auto-approve"],
    ]


def test_only_workspace_list_captures_output_and_stderr_is_never_captured(stack: ModuleType, calls: list) -> None:
    stack.workspace_exists(ACCOUNT, REGION)
    stack.plan(ACCOUNT, REGION)

    (_, list_kwargs), (_, plan_kwargs) = calls
    assert list_kwargs.get("stdout") == subprocess.PIPE
    assert plan_kwargs.get("stdout") is None
    for kwargs in (list_kwargs, plan_kwargs):
        assert "stderr" not in kwargs and not kwargs.get("capture_output")


def test_unknown_command_is_rejected_before_any_aws_or_terraform_call(stack: ModuleType, calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["terraform_stack.py", "aply"])
    monkeypatch.setattr(stack.boto3, "client", lambda service: pytest.fail("no AWS call expected"))

    with pytest.raises(SystemExit) as error:
        stack.main()

    assert error.value.code == 2
    assert calls == []


def test_init_runs_only_terraform_init(stack: ModuleType, calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ssm(stack, monkeypatch, REGION)
    monkeypatch.setattr(sys, "argv", ["terraform_stack.py", "init"])

    stack.main()

    assert [cmd for cmd, _ in calls] == [["terraform", "init", "-backend-config=backend.tfvars"]]


@pytest.mark.parametrize("command", ["plan", "apply", "destroy"])
def test_stack_command_runs_in_each_account_and_region_workspace(
    stack: ModuleType, calls: list, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    fake_ssm(stack, monkeypatch, "us-east-1,us-west-2")
    monkeypatch.setattr(stack, "get_accounts", lambda: [ACCOUNT])
    monkeypatch.setattr(sys, "argv", ["terraform_stack.py", command])

    stack.main()

    steps = [cmd[1:4] if cmd[1] == "workspace" else cmd[1] for cmd, _ in calls]
    assert steps == [
        ["workspace", "list"],
        ["workspace", "new", f"{ACCOUNT}-us-east-1"],
        ["workspace", "select", f"{ACCOUNT}-us-east-1"],
        command,
        ["workspace", "list"],
        ["workspace", "new", f"{ACCOUNT}-us-west-2"],
        ["workspace", "select", f"{ACCOUNT}-us-west-2"],
        command,
    ]


def test_shell_metacharacters_stay_inside_one_argument(stack: ModuleType, calls: list) -> None:
    stack.plan(ACCOUNT, "us-east-1; touch /tmp/sra-pwned")

    cmd, _ = calls[0]
    assert "account_region=us-east-1; touch /tmp/sra-pwned" in cmd


@pytest.mark.parametrize(
    ("listing", "expected"),
    [
        (f"* default\n  {ACCOUNT}-{REGION}\n", True),
        (f"  default\n* {ACCOUNT}-{REGION}\n", True),
        (f"* default\n  {ACCOUNT}-us-east-2\n", False),
        (f"* default\n  {ACCOUNT}-{REGION}-old\n", False),
        ("* default\n", False),
    ],
)
def test_workspace_exists_matches_the_exact_name(stack: ModuleType, monkeypatch: pytest.MonkeyPatch, listing: str, expected: bool) -> None:
    monkeypatch.setattr(stack.subprocess, "run", lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=listing, stderr=""))

    assert stack.workspace_exists(ACCOUNT, REGION) is expected


@pytest.mark.parametrize("region", ["us-east-1", "eu-central-2", "ap-southeast-4", "us-gov-west-1", "us-isob-east-1", "cn-north-1", "eusc-de-east-1"])
def test_region_pattern_accepts_region_names(stack: ModuleType, region: str) -> None:
    assert stack.REGION_PATTERN.fullmatch(region)


@pytest.mark.parametrize(
    "region", ["", " us-east-1", "us-east-1\n", "us-east-1;id", "us-east-1 && id", "$(id)", "US-EAST-1", "us-east", "us--east-1"]
)
def test_region_pattern_rejects_other_values(stack: ModuleType, region: str) -> None:
    assert not stack.REGION_PATTERN.fullmatch(region)


def test_supported_regions_are_loaded_with_the_home_region_first(stack: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ssm(stack, monkeypatch, "us-west-2,us-east-1,eu-west-1")

    stack.set_supported_region()

    assert stack.SUPPORTED_REGIONS == ["us-east-1", "us-west-2", "eu-west-1"]


def test_invalid_region_in_the_parameter_raises(stack: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ssm(stack, monkeypatch, "us-east-1,us-west-2;id")

    with pytest.raises(ValueError, match="not Region names"):
        stack.set_supported_region()
