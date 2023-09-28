"""Get a list of accounts that do not have AWS Config enabled.

The purpose of this script is to check if AWS Config is enabled in each AWS account and region within an AWS Control
Tower environment. The script will output Account IDs that have any regions that are not enabled.

Usage:
Assume an IAM role in the AWS Organizations management account that has the ability to assume the
AWSControlTowerExecution IAM role within each member account.

python3 list-config-recorder-status.py

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from time import sleep
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_sts.client import STSClient

# Logging Settings
LOGGER = logging.getLogger()
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)

# Global Variables
MAX_THREADS = 20
ORG_PAGE_SIZE = 20  # Max page size for list_accounts
ORG_THROTTLE_PERIOD = 0.2
ASSUME_ROLE_NAME = "sra-execution"
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
    CFN_CLIENT: CloudFormationClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation", config=BOTO3_CONFIG)
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


def get_all_organization_accounts() -> list:
    """Get all the active AWS Organization accounts.

    Returns:
        List of active account IDs
    """
    account_ids = []
    paginator = ORG_CLIENT.get_paginator("list_accounts")

    for page in paginator.paginate(PaginationConfig={"PageSize": ORG_PAGE_SIZE}):
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                account_ids.append(acct["Id"])
        sleep(ORG_THROTTLE_PERIOD)

    return account_ids


def get_control_tower_regions() -> list:  # noqa: CCR001
    """Query SSM Parameter Store to identify customer regions.

    Returns:
        Customer regions
    """
    customer_regions = []
    ssm_response = SSM_CLIENT.get_parameter(Name="/sra/regions/customer-control-tower-regions")
    customer_regions = ssm_response["Parameter"]["Value"].split(",")

    return list(customer_regions)


def get_enabled_regions(control_tower_regions_only: bool = False) -> list:  # noqa: CCR001
    """Query STS to identify enabled regions.

    Args:
        control_tower_regions_only: Use the Control Tower governed regions. Defaults to False.

    Returns:
        Enabled regions
    """
    if control_tower_regions_only:
        region_list = get_control_tower_regions()
    else:
        default_available_regions = [
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ca-central-1",
            "eu-central-1",
            "eu-north-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "sa-east-1",
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
        ]
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


def get_account_config(account_id: str, regions: list) -> dict:
    """Get Account AWS Config Information.

    Args:
        account_id: AWS Account Id
        regions: Enabled regions

    Returns:
        _description_
    """
    region_count = len(regions)
    config_recorder_count = 0
    all_regions_enabled = False
    enabled_regions = []
    not_enabled_regions = []

    account_session = assume_role(ASSUME_ROLE_NAME, "sra-aws-config-recorder-check", account_id)

    for region in regions:
        session_config = account_session.client("config", region_name=region, config=BOTO3_CONFIG)
        config_recorders = session_config.describe_configuration_recorders()

        if config_recorders.get("ConfigurationRecorders", ""):
            LOGGER.debug(f"{account_id} {region} - CONFIG ENABLED")
            config_recorder_count += 1
            enabled_regions.append(region)
        else:
            LOGGER.debug(f"{account_id} {region} - CONFIG NOT ENABLED")
            not_enabled_regions.append(region)

    if region_count == config_recorder_count:
        all_regions_enabled = True

    return {
        "AccountId": account_id,
        "AllRegionsEnabled": all_regions_enabled,
        "EnabledRegions": enabled_regions,
        "NotEnabledRegions": not_enabled_regions,
    }


def setup_pool(max_concurrency: int) -> ProcessPoolExecutor:
    """Pool setup.

    Args:
        max_concurrency: maximum concurrency

    Returns:
        ProcessPoolExecutor
    """
    return ProcessPoolExecutor(max_concurrency)


def start_multiprocess(pool: ProcessPoolExecutor, *args: Any) -> Future:
    """Start Multiprocess.

    Args:
        pool: Process pool executor
        *args: arguments

    Returns:
        A future representing a given call
    """
    return pool.submit(*args)


def get_multiprocess_result(process_list: list, timeout: int = 60) -> list:
    """Get multiprocess result.

    Args:
        process_list: List of processes
        timeout: Defaults to 60.

    Returns:
        List of outputs
    """
    output = []
    for future in as_completed(process_list, timeout=timeout):
        result = future.result()
        LOGGER.info(f"Account ID: {result['AccountId']}")
        LOGGER.info(f"Regions Enabled = {result['EnabledRegions']}")
        LOGGER.info(f"Regions Not Enabled = {result['NotEnabledRegions']}\n")
        if not result["AllRegionsEnabled"]:
            output.append(result["AccountId"])
    return output


def close_pool(pool: ProcessPoolExecutor) -> None:
    """Close the process pool.

    Args:
        pool: Process pool
    """
    pool.shutdown()


def get_config_recorder_status() -> None:
    """Get AWS Config recorder status."""
    try:
        account_ids = get_all_organization_accounts()
        available_regions = get_enabled_regions(True)

        if len(available_regions) > 0:
            thread_cnt = MAX_THREADS
            if MAX_THREADS > len(account_ids):
                thread_cnt = max(len(account_ids) - 2, 1)
            processes = []
            pool: ProcessPoolExecutor = setup_pool(thread_cnt)

            for account in account_ids:
                processes.append(start_multiprocess(pool, get_account_config, account, available_regions))

            results = get_multiprocess_result(processes, 900)
            if results:
                LOGGER.info(f'--> Accounts to exclude from Organization Conformance Packs: {",".join(results)}')
            else:
                LOGGER.info("--> AWS Config is enabled in all Accounts and Regions")
    except Exception as error:
        LOGGER.error(f"{error}")
        exit(1)


if __name__ == "__main__":
    # Set Log Level
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    get_config_recorder_status()
