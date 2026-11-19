"""Multi-account and region terraform deployment for AWS SRA code library.

Version: 1.0

AWS SRA terraform edition in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import argparse
import re
import subprocess

import boto3

SUPPORTED_REGIONS: list = []
# AWS Region names, for example us-east-1, us-gov-west-1 or eusc-de-east-1
REGION_PATTERN = re.compile(r"[a-z]{2,}(?:-[a-z]+){1,2}-\d+")


def terraform(*args: str, capture_stdout: bool = False) -> subprocess.CompletedProcess[str]:
    """Run a terraform command as an argument list, without a shell.

    Args:
        *args: terraform subcommand and its arguments
        capture_stdout: capture stdout instead of passing it through. stderr always passes through, so terraform's errors stay visible.

    Returns:
        subprocess.CompletedProcess[str]: the completed terraform process
    """
    stdout = subprocess.PIPE if capture_stdout else None
    return subprocess.run(["terraform", *args], check=True, stdout=stdout, text=True)  # noqa: S603, S607


def stack_variables(account: str, region: str) -> list[str]:
    """Build the variable arguments shared by plan, apply and destroy.

    Args:
        account (str): Account ID
        region (str): Region

    Returns:
        list: terraform -var-file and -var arguments
    """
    return ["-var-file=config.tfvars", "-var", f"account_id={account}", "-var", f"account_region={region}"]


def init() -> None:
    """Initialize the terraform project."""
    terraform("init", "-backend-config=backend.tfvars")


def set_supported_region() -> None:
    """Set the supported regions from parameter store."""
    global SUPPORTED_REGIONS

    ssm_client = boto3.client("ssm")
    customer_regions_parameter_name = "/sra/regions/customer-control-tower-regions"
    home_region = "/sra/control-tower/home-region"

    response = ssm_client.get_parameter(Name=customer_regions_parameter_name, WithDecryption=True)  # Use this if the parameter is encrypted with KMS

    customer_regions = response["Parameter"]["Value"]

    # Split the comma-separated values into a list
    SUPPORTED_REGIONS = customer_regions.split(",")
    invalid_regions = [region for region in SUPPORTED_REGIONS if not REGION_PATTERN.fullmatch(region)]
    if invalid_regions:
        raise ValueError(f"{customer_regions_parameter_name} contains values that are not Region names: {invalid_regions}")

    response = ssm_client.get_parameter(Name=home_region, WithDecryption=True)  # Use this if the parameter is encrypted with KMS

    home_region = response["Parameter"]["Value"]

    if home_region in SUPPORTED_REGIONS:
        SUPPORTED_REGIONS.remove(home_region)
        SUPPORTED_REGIONS.insert(0, home_region)


def get_audit_account() -> str:
    """Get audit account from AWS Organization.

    Returns:
        str: audit account id
    """
    ssm_client = boto3.client("ssm")
    response = ssm_client.get_parameter(
        Name="/sra/control-tower/audit-account-id", WithDecryption=True  # Use this if the parameter is encrypted with KMS
    )

    return response["Parameter"]["Value"]


def get_accounts() -> list:
    """Get all accounts from AWS Organization.

    Returns:
        list: list of accounts in org
    """
    organizations = boto3.client("organizations")
    paginator = organizations.get_paginator("list_accounts")

    accounts = []
    for page in paginator.paginate():
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE":
                accounts.append(account["Id"])

    audit_account = get_audit_account()

    # audit account needs to go last
    if audit_account in accounts:
        accounts.remove(audit_account)
        accounts.append(audit_account)

    return accounts


def workspace_exists(account: str, region: str) -> bool:
    """Check to see if workspace already exists for current terraform project.

    Args:
        account (str): Account ID
        region (str): Region

    Returns:
        bool: Returns true if workspace already exists, false otherwise.
    """
    workspaces = terraform("workspace", "list", capture_stdout=True).stdout.splitlines()
    # The current workspace is listed with a leading "*"
    return f"{account}-{region}" in {workspace.lstrip("*").strip() for workspace in workspaces}


def create_workspace(account: str, region: str) -> None:
    """Create new workspace for terraform and saves it into state file.

    Args:
        account (str): Account ID
        region (str): Region
    """
    terraform("workspace", "new", f"{account}-{region}")


def switch_to_workspace(account: str, region: str) -> None:
    """Switch to a created workspace in Terraform.

    Args:
        account (str): Account ID
        region (str): Region
    """
    terraform("workspace", "select", f"{account}-{region}")


def plan(account: str, region: str) -> None:
    """Perform a terraform plan operation on all stacks.

    Args:
        account (str): Account ID
        region (str): Region
    """
    terraform("plan", *stack_variables(account, region))


def apply(account: str, region: str) -> None:
    """Perform a terraform apply operation on all stacks.

    Args:
        account (str): Account ID
        region (str): Region
    """
    terraform("apply", *stack_variables(account, region), "-auto-approve")


def destroy(account: str, region: str) -> None:
    """Perform a terraform destroy operation on all stacks.

    Args:
        account (str): Account ID
        region (str): Region
    """
    terraform("destroy", *stack_variables(account, region), "-auto-approve")


def main() -> None:
    """Run the script."""
    stack_commands = {"plan": plan, "apply": apply, "destroy": destroy}
    parser = argparse.ArgumentParser(description="Terraform Script to Deploy Stacksets")
    parser.add_argument("cmd", choices=["init", *stack_commands], help="terraform command to run")
    args = parser.parse_args()

    set_supported_region()

    if args.cmd == "init":
        init()
        return

    for account in get_accounts():
        for region in SUPPORTED_REGIONS:
            if not workspace_exists(account, region):
                create_workspace(account, region)

            switch_to_workspace(account, region)
            stack_commands[args.cmd](account, region)


if __name__ == "__main__":
    main()
