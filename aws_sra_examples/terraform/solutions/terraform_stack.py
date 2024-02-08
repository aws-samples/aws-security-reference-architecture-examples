"""Multi-account and region terraform deployment for AWS SRA code library.

Version: 1.0

AWS SRA terraform edition in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import subprocess  # noqa: S404
import argparse
import boto3

SUPPORTED_REGIONS: list = []


def init() -> None:
    """Initialize the terraform project."""
    subprocess.run("terraform init -backend-config=backend.tfvars", check=True, shell=True)  # nosec B602  # noqa: S602,S607,DUO116


def set_supported_region() -> None:
    """Set the supported regions from parameter store."""
    global SUPPORTED_REGIONS

    ssm_client = boto3.client('ssm')
    customer_regions_parameter_name = '/sra/regions/customer-control-tower-regions'
    home_region = "/sra/control-tower/home-region"

    response = ssm_client.get_parameter(
        Name=customer_regions_parameter_name,
        WithDecryption=True  # Use this if the parameter is encrypted with KMS
    )

    customer_regions = response['Parameter']['Value']

    # Split the comma-separated values into a list
    SUPPORTED_REGIONS = customer_regions.split(',')

    response = ssm_client.get_parameter(
        Name=home_region,
        WithDecryption=True  # Use this if the parameter is encrypted with KMS
    )

    home_region = response['Parameter']['Value']

    if home_region in SUPPORTED_REGIONS:
        SUPPORTED_REGIONS.remove(home_region)
        SUPPORTED_REGIONS.insert(0, home_region)


def get_audit_account() -> str:
    """Get audit account from AWS Organization.

    Returns:
        str: audit account id
    """
    ssm_client = boto3.client('ssm')
    response = ssm_client.get_parameter(
        Name="/sra/control-tower/audit-account-id",
        WithDecryption=True  # Use this if the parameter is encrypted with KMS
    )

    return response['Parameter']['Value']


def get_accounts() -> list:
    """Get all accounts from AWS Organization.

    Returns:
        list: list of accounts in org
    """
    organizations = boto3.client('organizations')
    paginator = organizations.get_paginator("list_accounts")

    accounts = [
        account["Id"]
        for page in paginator.paginate()
        for account in page["Accounts"]
    ]
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
    completed_process = subprocess.run(f"terraform workspace list | grep {account}-{region}", shell=True)  # nosec B602  # noqa: S602,DUO116
    return completed_process.returncode == 0


def create_workspace(account: str, region: str) -> None:
    """Create new workspace for terraform and saves it into state file.

    Args:
        account (str): Account ID
        region (str): Region
    """
    subprocess.run(f"terraform workspace new {account}-{region}", check=True, shell=True)  # nosec B602  # noqa: S602,DUO116


def switch_to_workspace(account: str, region: str) -> None:
    """Switch to a created workspace in Terraform.

    Args:
        account (str): Account ID
        region (str): Region
    """
    subprocess.run(f"terraform workspace select {account}-{region}", check=True, shell=True)  # nosec B602  # noqa: S602,DUO116


def plan(account: str, region: str) -> None:
    """Perform a terraform plan operation on all stacks.

    Args:
        account (str): Account ID
        region (str): Region
    """
    subprocess.run(f"terraform plan -var-file=config.tfvars -var account_id={account} -var account_region={region}",
                   check=True, shell=True)  # nosec B602  # noqa: S602,DUO116


def apply(account: str, region: str) -> None:
    """Perform a terraform apply operation on all stacks.

    Args:
        account (str): Account ID
        region (str): Region
    """
    subprocess.run(f"terraform apply -var-file=config.tfvars -var account_id={account} -var account_region={region} -auto-approve",
                   check=True, shell=True)  # nosec B602  # noqa: S602,DUO116


def destroy(account: str, region: str) -> None:
    """Perform a terraform destroy operation on all stacks.

    Args:
        account (str): Account ID
        region (str): Region
    """
    subprocess.run(f"terraform destroy -var-file=config.tfvars -var account_id={account} -var account_region={region} -auto-approve",
                   check=True, shell=True)  # nosec B602  # noqa: S602,DUO116


def main() -> None:  # noqa: CCR001
    """Run the script."""
    # parse arguments
    parser = argparse.ArgumentParser(description="Terraform Script to Deploy Stacksets")
    parser.add_argument("cmd", help="terraform command to run")
    args = parser.parse_args()

    set_supported_region()

    if args.cmd == "init":
        init()
    elif args.cmd == "plan":
        for account in get_accounts():
            for region in SUPPORTED_REGIONS:
                if not workspace_exists(account, region):
                    create_workspace(account, region)

                switch_to_workspace(account, region)
                plan(account, region)
    elif args.cmd == "apply":
        for account in get_accounts():
            for region in SUPPORTED_REGIONS:
                if not workspace_exists(account, region):
                    create_workspace(account, region)

                switch_to_workspace(account, region)
                apply(account, region)
    elif args.cmd == "destroy":
        for account in get_accounts():
            for region in SUPPORTED_REGIONS:
                if not workspace_exists(account, region):
                    create_workspace(account, region)

                switch_to_workspace(account, region)
                destroy(account, region)


if __name__ == "__main__":
    main()
