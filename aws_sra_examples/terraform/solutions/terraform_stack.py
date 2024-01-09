########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################

import subprocess
import argparse
import boto3

SUPPORTED_REGIONS = []
def init():
    """Performs an init on the terraform project
    """
    subprocess.run(f"terraform init -backend-config=backend.tfvars", check=True, shell=True)

def set_supported_region():
    """Sets The supported regions from parameter store
    """
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

def get_audit_account():
    """Get audit account from AWS Organization

    Returns:
        string: audit account id
    """

    ssm_client = boto3.client('ssm')
    response = ssm_client.get_parameter(
        Name="/sra/control-tower/audit-account-id",
        WithDecryption=True  # Use this if the parameter is encrypted with KMS
    )

    audit_account = response['Parameter']['Value']

    return audit_account

def get_accounts():
    """Get all accounts from AWS Organization

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

def workspace_exists(account, region):
    """Checks to see if workspace already exists for current terraform project

    Args:
        account (int): Account ID
        region (string): Region

    Returns:
        boolean: Returns true if workspace already exists, false otherwise
    """
    completed_process = subprocess.run(f"terraform workspace list | grep {account}-{region}", shell=True)
    return completed_process.returncode == 0

def create_workspace(account, region):
    """Create new workspace for terraform and saves it into statefile

    Args:
        account (int): Account ID
        region (string): Region
    """
    subprocess.run(f"terraform workspace new {account}-{region}", check=True, shell=True)

def switch_to_workspace(account, region):
    """Switch to a created workspace in Terraform

    Args:
        account (int): Account ID
        region (string): Region
    """
    subprocess.run(f"terraform workspace select {account}-{region}", check=True, shell=True)

def plan(account, region):
    """Performs a terraform plan operation on all stacks

    Args:
        account (int): Account ID
        region (string): Region
    """
    subprocess.run(f"terraform plan -var-file=config.tfvars -var account_id={account} -var account_region={region}", check=True, shell=True)

def apply(account, region):
    """Performs a terraform apply operation on all stacks

    Args:
        account (int): Account ID
        region (string): Region
    """
    subprocess.run(f"terraform apply -var-file=config.tfvars -var account_id={account} -var account_region={region} -auto-approve", check=True, shell=True)

def destroy(account, region):
    """Performs a terraform destroy operation on all stacks

    Args:
        account (int): Account ID
        region (string): Region
    """
    subprocess.run(f"terraform destroy -var-file=config.tfvars -var account_id={account} -var account_region={region} -auto-approve", check=True, shell=True)

def main():
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