########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import boto3
import logging
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

"""
The purpose of this script is to check if AWS Config is enabled in each AWS account and region within an AWS Control
Tower environment. The script will output Account IDs that have any regions that are not enabled.

Usage:
Assume an IAM role in the AWS Organizations management account that has the ability to assume the 
AWSControlTowerExecution IAM role within each account.

python3 list-config-recorder-status.py 
"""

# Logging Settings
LOGGER = logging.getLogger()
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
logging.getLogger("s3transfer").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

SESSION = boto3.Session()
STS_CLIENT = boto3.client('sts')
AWS_PARTITION = "aws"
ASSUME_ROLE_NAME = "AWSControlTowerExecution"
MAX_THREADS = 16


def assume_role(aws_account_number: str, role_name: str, session_name: str):
    """
    Assumes the provided role in the provided account and returns a session
    :param aws_account_number: AWS Account Number
    :param role_name: Role name to assume in target account
    :param session_name: Session name
    :return: session for the account and role name
    """
    try:
        response = STS_CLIENT.assume_role(
            RoleArn=f"arn:{AWS_PARTITION}:iam::{aws_account_number}:role/{role_name}",
            RoleSessionName=session_name,
        )
        # Storing STS credentials
        session = boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )
        LOGGER.debug(f"...Assumed session for {aws_account_number}")

        return session
    except Exception as exc:
        LOGGER.error(f"Unexpected error: {exc}")
        exit(1)


def get_all_organization_accounts(account_info: bool, exclude_account_id: str):
    """
    Gets a list of active AWS Accounts in the AWS Organization
    :param account_info: True = return account info dict, False = return account id list
    :param exclude_account_id
    :return: accounts dict or account_id list
    """
    accounts = []  # used for create_members
    account_ids = []  # used for disassociate_members

    try:
        organizations = boto3.client("organizations")
        paginator = organizations.get_paginator("list_accounts")

        for page in paginator.paginate(PaginationConfig={"PageSize": 20}):
            for acct in page["Accounts"]:
                if (exclude_account_id and acct["Id"] not in exclude_account_id) or not exclude_account_id:
                    # if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                    account_record = {"AccountId": acct["Id"], "Email": acct["Email"]}
                    accounts.append(account_record)
                    account_ids.append(acct["Id"])
    except ClientError as ce:
        LOGGER.error(f"get_all_organization_accounts error: {ce}")
        raise ValueError("Error getting accounts")
    except Exception as exc:
        LOGGER.error(f"get_all_organization_accounts error: {exc}")
        exit(1)

    if account_info:
        return accounts

    return account_ids


def is_region_available(region):
    """
    Check if the region is available
    :param region:
    :return:
    """
    regional_sts = boto3.client('sts', region_name=region)
    try:
        regional_sts.get_caller_identity()
        return True
    except ClientError as error:
        if "InvalidClientTokenId" in str(error):
            LOGGER.error(f"Region: {region} is not available")
            return False
        else:
            LOGGER.error(f"{error}")


def get_available_service_regions(user_regions: str, aws_service: str,
                                  control_tower_regions_only: bool = False) -> list:
    """
    Get the available regions for the AWS service
    :param: user_regions
    :param: aws_service
    :param: control_tower_regions_only
    :return: available region list
    """
    available_regions = []
    service_regions = []
    try:
        if user_regions.strip():
            LOGGER.info(f"USER REGIONS: {user_regions}")
            service_regions = [value.strip() for value in user_regions.split(",") if value != '']
        elif control_tower_regions_only:
            cf_client = SESSION.client('cloudformation')
            paginator = cf_client.get_paginator("list_stack_instances")
            region_set = set()
            for page in paginator.paginate(
                StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH"
            ):
                for summary in page["Summaries"]:
                    region_set.add(summary["Region"])
            service_regions = list(region_set)
        else:
            service_regions = boto3.session.Session().get_available_regions(aws_service)
        LOGGER.info(f"SERVICE REGIONS: {service_regions}")
    except ClientError as ce:
        LOGGER.error(f"get_available_service_regions error: {ce}")
        exit(1)

    for region in service_regions:
        if is_region_available(region):
            available_regions.append(region)

    LOGGER.info(f"AVAILABLE REGIONS: {available_regions}")
    return available_regions


def get_service_client(aws_service: str, aws_region: str, session=None):
    """
    Get boto3 client for an AWS service
    :param session:
    :param aws_service:
    :param aws_region:
    :return: service client
    """
    if aws_region:
        if session:
            service_client = session.client(aws_service, region_name=aws_region)
        else:
            service_client = boto3.client(aws_service, aws_region)
    else:
        if session:
            service_client = session.client(aws_service)
        else:
            service_client = boto3.client(aws_service)
    return service_client


def get_account_config(account_id, regions):
    """
    get_account_config
    :param account_id:
    :param regions:
    :return:
    """
    region_count = 0
    config_recorder_count = 0
    all_regions_enabled = False
    enabled_regions = []
    not_enabled_regions = []

    session = assume_role(account_id, ASSUME_ROLE_NAME, "ConfigRecorderCheck")

    for region in regions:
        region_count += 1
        session_config = get_service_client("config", region, session)
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

    return account_id, all_regions_enabled, enabled_regions, not_enabled_regions


def get_config_recorder_status():
    """
    get_config_recorder_status
    :return:
    """
    try:
        account_ids = get_all_organization_accounts(False, "")
        available_regions = get_available_service_regions("", "config", True)
        account_set = set()
        processes = []

        if MAX_THREADS > len(account_ids):
            thread_cnt = len(account_ids) - 2
        else:
            thread_cnt = MAX_THREADS

        with ThreadPoolExecutor(max_workers=thread_cnt) as executor:
            for account_id in account_ids:
                try:
                    processes.append(executor.submit(
                        get_account_config,
                        account_id,
                        available_regions
                    ))
                except Exception as error:
                    LOGGER.error(f"{error}")
                    continue

        for task in as_completed(processes, timeout=300):
            account_id, all_regions_enabled, enabled_regions, not_enabled_regions = task.result()
            LOGGER.info(f"Account ID: {account_id}")
            LOGGER.info(f"Regions Enabled = {enabled_regions}")
            LOGGER.info(f"Regions Not Enabled = {not_enabled_regions}\n")
            if not all_regions_enabled:
                account_set.add(account_id)

        LOGGER.info(f'!!! Accounts to exclude from Organization Conformance Packs: {",".join(list(account_set))}')
    except Exception as error:
        LOGGER.error(f"{error}")
        exit(1)


if __name__ == "__main__":
    # Set Log Level
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    get_config_recorder_status()
