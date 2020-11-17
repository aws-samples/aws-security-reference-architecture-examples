########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import boto3
from botocore.exceptions import ClientError
import logging

"""
The purpose of this script is to check if AWS Config is enabled in each AWS account and region within an AWS Control
Tower environment. The script will output Account IDs that have any regions that are not enabled.

Usage:
Assume an IAM role in the AWS Organizations management account that has the ability to assume the 
AWSControlTowerExecution IAM role within each account.

python3 list-config-recorder-status.py 
"""

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SESSION = boto3.Session()
STS_CLIENT = boto3.client('sts')
AWS_PARTITION = "aws"
ASSUME_ROLE_NAME = "AWSControlTowerExecution"


def assume_role(aws_account_number, role_name, session_name):
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
        logger.debug(f"Assumed session for {aws_account_number}")

        return session
    except Exception as exc:
        print(f"Unexpected error: {exc}")
        raise ValueError("Error assuming role")


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
        print(f"get_all_organization_accounts error: {ce}")
        raise ValueError("Error getting accounts")
    except Exception as exc:
        print(f"get_all_organization_accounts error: {exc}")
        raise ValueError("Unexpected error getting accounts")

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
            print(f"Region: {region} is not available")
            return False
        else:
            print(f"{error}")


def get_available_service_regions(user_regions: str, aws_service: str, control_tower_regions_only: bool = False) -> list:
    """
    Get the available regions for the AWS service
    :param: user_regions
    :param: aws_service
    :param: control_tower_regions_only
    :return: available region list
    """
    available_regions = []
    try:
        if user_regions.strip():
            print(f"USER REGIONS: {str(user_regions)}")
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
            service_regions = boto3.session.Session().get_available_regions(
                aws_service
            )
        print(f"SERVICE REGIONS: {service_regions}")
    except ClientError as ce:
        print(f"get_available_service_regions error: {ce}")
        raise ValueError("Error getting service regions")

    for region in service_regions:
        if is_region_available(region):
            available_regions.append(region)

    print(f"AVAILABLE REGIONS: {available_regions}")
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


if __name__ == "__main__":
    account_ids = get_all_organization_accounts(False, "")
    available_regions = get_available_service_regions("", "config", True)
    account_set = set()
    for account_id in account_ids:
        try:
            session = assume_role(account_id, ASSUME_ROLE_NAME, "ConfigRecorderCheck")
        except Exception as error:
            print(f"Unable to assume {ASSUME_ROLE_NAME} in {account_id} {error}")
            continue

        for region in available_regions:
            try:
                session_config = get_service_client("config", region, session)
                response = session_config.describe_configuration_recorders()
                if "ConfigurationRecorders" in response and response["ConfigurationRecorders"]:
                    # print(f"{account_id} {region} - CONFIG ENABLED")
                    continue
                else:
                    print(f"{account_id} {region} - CONFIG NOT ENABLED")
                    account_set.add(account_id)
            except ClientError as error:
                print(f"Client Error - {error}")
    print(f'Accounts to exclude from Organization Conformance Pack: {",".join(list(account_set))}')


