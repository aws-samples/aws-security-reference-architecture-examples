# type: ignore
"""This script includes common functions.

Version: 1.1

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep
from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_sts.client import STSClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)

# Global variables
ORG_PAGE_SIZE = 20  # Max page size for list_accounts
ORG_THROTTLE_PERIOD = 0.2
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
except Exception as error:
    LOGGER.error({"Unexpected_Error": error})
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def assume_role(role: str, role_session_name: str, account: str = None, session: boto3.Session = None) -> boto3.Session:
    """Assumes the provided role in the given account and returns a session.

    Args:
        role: Role to assume in target account.
        role_session_name: Identifier for the assumed role session.
        account: AWS account number. Defaults to None.
        session: Boto3 session. Defaults to None.

    Returns:
        Session object for the specified AWS account
    """
    # TODO(liamschn): move this to correct place
    os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = "regional"

    if not session:
        session = boto3.Session()
    sts_client: STSClient = session.client("sts", config=BOTO3_CONFIG)
    sts_arn = sts_client.get_caller_identity()["Arn"]
    LOGGER.info(f"USER: {sts_arn}")
    if not account:
        account = sts_arn.split(":")[4]
    partition = sts_arn.split(":")[1]
    role_arn = f"arn:{partition}:iam::{account}:role/{role}"

    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)
    LOGGER.info(f"ASSUMED ROLE: {response['AssumedRoleUser']['Arn']}")
    return boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )


def get_all_organization_accounts(exclude_accounts: list = None) -> list:
    """Get all the active AWS Organization accounts.

    Args:
        exclude_accounts: list of account IDs to exclude

    Returns:
        List of active account IDs
    """
    if exclude_accounts is None:
        exclude_accounts = ["00000000000"]
    accounts = []
    management_account_session = boto3.Session()
    org_client: OrganizationsClient = management_account_session.client("organizations", config=BOTO3_CONFIG)
    paginator = org_client.get_paginator("list_accounts")

    for page in paginator.paginate(PaginationConfig={"PageSize": ORG_PAGE_SIZE}):
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE" and acct["Id"] not in exclude_accounts:  # Store active accounts in a dict
                account_record = {"AccountId": acct["Id"], "Email": acct["Email"]}
                accounts.append(account_record)
        sleep(ORG_THROTTLE_PERIOD)

    return accounts


def get_account_ids(accounts: list, exclude_accounts: list = None) -> list:
    """Get Account IDs from account list dictionary.

    Args:
        accounts: List of accounts. {'AccountId': '', 'Email': ''}
        exclude_accounts: List of account IDs to exclude.

    Returns:
        Account ID list of strings
    """
    account_ids: list[str] = []
    if not accounts:
        accounts = get_all_organization_accounts(exclude_accounts)

    for account in accounts:
        account_ids.append(account["AccountId"])
    return account_ids


def get_control_tower_regions() -> list:  # noqa: CCR001
    """Query 'AWSControlTowerBP-BASELINE-CLOUDWATCH' CloudFormation stack to identify customer regions.

    Returns:
        Customer regions chosen in Control Tower
    """
    customer_regions = []
    ssm_response = SSM_CLIENT.get_parameter(Name="/sra/regions/customer-control-tower-regions")
    customer_regions = ssm_response["Parameter"]["Value"].split(",")
    return list(customer_regions)


def get_enabled_regions(customer_regions: str, control_tower_regions_only: bool = False) -> list:  # noqa: CCR001
    """Query STS to identify enabled regions.

    Args:
        customer_regions: customer provided comma delimited string of regions
        control_tower_regions_only: Use the Control Tower governed regions. Defaults to False.

    Returns:
        Enabled regions
    """
    if customer_regions.strip():
        LOGGER.debug(f"CUSTOMER PROVIDED REGIONS: {str(customer_regions)}")
        region_list = [value.strip() for value in customer_regions.split(",") if value != ""]
    elif control_tower_regions_only:
        region_list = get_control_tower_regions()
    else:
        default_available_regions = []
        for region in boto3.client("account").list_regions(RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"])["Regions"]:
            default_available_regions.append(region["RegionName"])
        LOGGER.info({"Default_Available_Regions": default_available_regions})
        region_list = default_available_regions

    enabled_regions = []
    disabled_regions = []
    invalid_regions = []
    region_session = boto3.Session()
    for region in region_list:
        try:
            sts_client = region_session.client("sts", endpoint_url=f"https://sts.{region}.amazonaws.com", region_name=region, config=BOTO3_CONFIG)
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidClientTokenId":
                disabled_regions.append(region)
            LOGGER.error(f"Error {error.response['Error']} occurred testing region {region}")
        except Exception as error:
            if "Could not connect to the endpoint URL" in str(error):
                invalid_regions.append(region)
                LOGGER.error(f"Region: '{region}' is not valid")
            LOGGER.error(f"{error}")
    LOGGER.info({"Disabled_Regions": disabled_regions})
    LOGGER.info({"Invalid_Regions": invalid_regions})
    return enabled_regions


def create_service_linked_role(service_linked_role_name: str, service_name: str, description: str = "") -> None:
    """Create the service linked role, if it does not exist.

    Args:
        service_linked_role_name: Service Linked Role Name
        service_name: AWS Service Name
        description: Description
    """
    iam_client: IAMClient = boto3.client("iam", config=BOTO3_CONFIG)
    try:
        iam_client.get_role(RoleName=service_linked_role_name)
    except iam_client.exceptions.NoSuchEntityException:
        iam_client.create_service_linked_role(AWSServiceName=service_name, Description=description)
