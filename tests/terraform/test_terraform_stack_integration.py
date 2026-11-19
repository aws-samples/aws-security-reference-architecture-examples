"""Integration tests for terraform_stack.py with a real terraform binary and a local-only configuration.

Only boto3 is stubbed. Terraform runs against a local backend with no providers, so no AWS call or credential is needed.
The tests are skipped when terraform is not on PATH.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(shutil.which("terraform") is None, reason="needs a terraform binary on PATH")

SCRIPT = Path(__file__).resolve().parents[2] / "aws_sra_examples/terraform/solutions/terraform_stack.py"
ACCOUNTS = ["111111111111", "222222222222"]
REGIONS = ["us-east-1", "us-west-2"]
CONFIG = """terraform {
  backend "local" {}
}

variable "account_id" {
  type = string
}

variable "account_region" {
  type = string
}

output "seen" {
  value = "${terraform.workspace}|${var.account_id}|${var.account_region}"
}
"""


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    (tmp_path / "main.tf").write_text(CONFIG)
    (tmp_path / "backend.tfvars").write_text('path = "state/terraform.tfstate"\n')
    (tmp_path / "config.tfvars").write_text("")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TF_IN_AUTOMATION", "1")

    spec = importlib.util.spec_from_file_location("sra_terraform_stack_integration", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    parameters = {"/sra/regions/customer-control-tower-regions": ",".join(REGIONS), "/sra/control-tower/home-region": REGIONS[0]}
    ssm = SimpleNamespace(get_parameter=lambda Name, WithDecryption: {"Parameter": {"Value": parameters[Name]}})  # noqa: N803
    monkeypatch.setattr(module.boto3, "client", lambda service: ssm)
    monkeypatch.setattr(module, "get_accounts", lambda: ACCOUNTS)
    return module


def run(stack: ModuleType, monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    monkeypatch.setattr(sys, "argv", ["terraform_stack.py", command])
    stack.main()


def workspace_outputs() -> dict:
    listing = subprocess.run(["terraform", "workspace", "list"], check=True, capture_output=True, text=True).stdout
    outputs = {}
    for workspace in (line.lstrip("*").strip() for line in listing.splitlines()):
        if workspace and workspace != "default":
            subprocess.run(["terraform", "workspace", "select", workspace], check=True, capture_output=True)
            outputs[workspace] = subprocess.run(["terraform", "output", "-raw", "seen"], check=True, capture_output=True, text=True).stdout
    return outputs


def test_init_apply_twice_and_destroy_across_accounts_and_regions(stack: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    run(stack, monkeypatch, "init")
    run(stack, monkeypatch, "plan")
    run(stack, monkeypatch, "apply")
    run(stack, monkeypatch, "apply")  # every workspace now exists, so this takes the select-only path

    expected = {f"{account}-{region}": f"{account}-{region}|{account}|{region}" for account in ACCOUNTS for region in REGIONS}
    assert workspace_outputs() == expected

    run(stack, monkeypatch, "destroy")
    states = list(tmp_path.rglob("*.tfstate"))
    assert len(states) == len(expected) + 1  # one per workspace, plus default
    assert not any(json.loads(state.read_text()).get("outputs") for state in states)


def test_terraform_errors_are_shown_when_a_command_fails(stack: ModuleType, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture) -> None:
    # Without init, terraform workspace list fails; its own error message must reach the user.
    with pytest.raises(subprocess.CalledProcessError):
        run(stack, monkeypatch, "plan")

    assert "Backend initialization required" in capfd.readouterr().err
