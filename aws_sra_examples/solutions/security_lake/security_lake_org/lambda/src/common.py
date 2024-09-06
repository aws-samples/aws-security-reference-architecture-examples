# type: ignore
"""This script includes common functions.

Version: 1.0

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from time import sleep
from typing import TYPE_CHECKING

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

if TYPE_CHECKING:
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_sts.client import STSClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)

# Global variables
ORGANIZATIONS_PAGE_SIZE = 20
ORGANIZATIONS_THROTTLE_PERIOD = 0.2

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
except Exception as error:
    LOGGER.error({"Unexpected_Error": error})
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def assume_role(
    role: str,
    role_session_name: str,
    account: str = None,
    session: boto3.Session = None,
) -> boto3.Session:
    """Assumes the provided role in the given account and returns a session.

    Args:
        role: Role to assume in target account.
        role_session_name: Identifier for the assumed role session.
        account: AWS account number. Defaults to None.
        session: Boto3 session. Defaults to None.

    Returns:
        Session object for the specified AWS account
    """
    if not session:
        session = boto3.Session()
    sts_client: STSClient = session.client("sts")
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


def get_active_organization_accounts(exclude_accounts: list = None) -> list:
    """Get all the active AWS Organization accounts.

    Args:
        exclude_accounts: list of account IDs to exclude

    Returns:
        List of active account IDs
    """
    if exclude_accounts is None:
        exclude_accounts = ["00000000000"]
    accounts: list[dict] = []
    paginator = ORG_CLIENT.get_paginator("list_accounts")

    for page in paginator.paginate(PaginationConfig={"PageSize": ORGANIZATIONS_PAGE_SIZE}):
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE" and account["Id"] not in exclude_accounts:
                accounts.append({"AccountId": account["Id"], "Email": account["Email"]})
        sleep(ORGANIZATIONS_THROTTLE_PERIOD)

    return accounts


def get_control_tower_regions() -> list:  # noqa: CCR001
    """Query SSM Parameter Store to identify customer regions.

    Returns:
        Customer regions
    """
    ssm_response = SSM_CLIENT.get_parameter(Name="/sra/regions/customer-control-tower-regions")
    customer_regions = ssm_response["Parameter"]["Value"].split(",")

    return list(customer_regions)


def get_enabled_regions(customer_regions: str, control_tower_regions_only: bool = False) -> list:  # noqa: CCR001, C901
    """Query STS to identify enabled regions.

    Args:
        customer_regions: customer provided comma delimited string of regions
        control_tower_regions_only: Use the Control Tower governed regions. Defaults to False.

    Returns:
        Enabled regions
    """
    if customer_regions.strip():
        LOGGER.info({"CUSTOMER PROVIDED REGIONS": customer_regions})
        region_list = []
        for region in customer_regions.split(","):
            if region != "":
                region_list.append(region.strip())
    elif control_tower_regions_only:
        region_list = get_control_tower_regions()
    else:
        default_available_regions = []
        for region in boto3.client("account").list_regions(RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"])["Regions"]:
            default_available_regions.append(region["RegionName"])

        LOGGER.info({"Default_Available_Regions": default_available_regions})
        region_list = default_available_regions

    region_session = boto3.Session()
    enabled_regions = []
    disabled_regions = []
    invalid_regions = []
    for region in region_list:
        try:
            sts_client = region_session.client(
                "sts",
                endpoint_url=f"https://sts.{region}.amazonaws.com",
                region_name=region,
            )
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except EndpointConnectionError:
            invalid_regions.append(region)
            LOGGER.error(f"Region: ({region}) is not valid")
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidClientTokenId":
                disabled_regions.append(region)
            LOGGER.error(f"Error {error.response['Error']} occurred testing region {region}")
        except Exception:
            LOGGER.exception("Unexpected!")

    LOGGER.info(
        {
            "Enabled_Regions": enabled_regions,
            "Disabled_Regions": disabled_regions,
            "Invalid_Regions": invalid_regions,
        }
    )
    return enabled_regions
