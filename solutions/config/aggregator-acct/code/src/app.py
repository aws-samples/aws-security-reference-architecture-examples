########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
import re
import json
import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

"""
The purpose of this script is to setup an AWS Config Aggregator in a designated
account and adds all the AWS Organization accounts.
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level="CRITICAL")

PAGE_SIZE = 20  # 20 is the max for the list_accounts paginator
STS_CLIENT = boto3.client("sts")

try:
    # Process Environment Variables
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

    AWS_CONFIG_MANAGEMENT_ACCOUNT_ID = os.environ.get("AWS_CONFIG_MANAGEMENT_ACCOUNT_ID", "")
    if not AWS_CONFIG_MANAGEMENT_ACCOUNT_ID or not re.match("^[0-9]{12}$", AWS_CONFIG_MANAGEMENT_ACCOUNT_ID):
        raise ValueError("AWS_CONFIG_MANAGEMENT_ACCOUNT_ID parameter is missing or invalid")

    ASSUME_ROLE_NAME = os.environ.get("ASSUME_ROLE_NAME", "")
    if not ASSUME_ROLE_NAME or not re.match("[\\w+=,.@-]+", ASSUME_ROLE_NAME):
        raise ValueError("ASSUME_ROLE_NAME parameter is missing or invalid")

    AWS_CONFIG_AGGREGATOR_NAME = os.environ.get("AWS_CONFIG_AGGREGATOR_NAME", "")
    if not AWS_CONFIG_AGGREGATOR_NAME or not re.match("[\\w_-]+", AWS_CONFIG_AGGREGATOR_NAME):
        raise ValueError("AWS_CONFIG_AGGREGATOR_NAME parameter is missing or invalid")

    AWS_PARTITION = os.environ.get("AWS_PARTITION", "")
    if AWS_PARTITION not in ("aws", "aws-cn", "aws-us-gov"):
        raise ValueError("AWS_PARTITION parameter is missing or invalid")

except Exception as e:
    helper.init_failure(e)


def get_all_organization_accounts() -> dict:
    """
    Gets a list of Active AWS Accounts in the Organization.

    :return: AWS Account Dictionary
    """
    aws_accounts_dict = dict()

    try:
        session = boto3.Session()
        org_client = session.client("organizations", region_name="us-east-1")
        paginator = org_client.get_paginator("list_accounts")

        for page in paginator.paginate(PaginationConfig={"PageSize": PAGE_SIZE}):
            for acct in page["Accounts"]:
                if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                    aws_accounts_dict.update({acct["Id"]: acct["Email"]})

        logger.info(f"Active accounts count: {len(aws_accounts_dict.keys())}, "
                    f"Active accounts: {json.dumps(aws_accounts_dict)}")
    except Exception as exc:
        logger.error(f"Unexpected error: {str(exc)}")
        raise ValueError("Error retrieving accounts")

    return aws_accounts_dict


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in the provided account and returns a session
    :param aws_account_number: AWS Account Number
    :param role_name: Role name to assume in target account
    :return: session for the account and role name
    """
    try:
        response = STS_CLIENT.assume_role(
            RoleArn=f"arn:{AWS_PARTITION}:iam::{aws_account_number}:role/{role_name}",
            RoleSessionName="EnableConfigAggregator",
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
        logger.error(f"Unexpected error: {str(exc)}")
        raise ValueError("Error assuming role")


def enable_config_aggregator():
    """
    Enables an AWS Config Aggregator in the provided account
    :return: None
    """

    try:
        aws_account_dict = get_all_organization_accounts()
        session = assume_role(AWS_CONFIG_MANAGEMENT_ACCOUNT_ID, ASSUME_ROLE_NAME)

        config_client = session.client("config")
        update_config = config_client.put_configuration_aggregator(
            ConfigurationAggregatorName=AWS_CONFIG_AGGREGATOR_NAME,
            AccountAggregationSources=[
                {"AccountIds": list(aws_account_dict.keys()), "AllAwsRegions": True}
            ],
        )
        logger.debug(update_config)
    except Exception as exc:
        logger.error(f"Unexpected error: {str(exc)}")
        raise ValueError("Error enabling config aggregator")


@helper.create
@helper.update
def create(event, context):
    """
     CloudFormation Create Event.
     :param event: event data
     :param context: runtime information
     :return: Resource ID
    """
    logger.info(f"Event: {event.get('RequestType')}")
    enable_config_aggregator()

    return "AWSConfigAggregatorResourceId"


@helper.delete
def delete(event, context):
    """
    CloudFormation Delete Event.
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("Delete Event")
    try:
        session = assume_role(AWS_CONFIG_MANAGEMENT_ACCOUNT_ID, ASSUME_ROLE_NAME)

        config_client = session.client("config")
        delete_config = config_client.delete_configuration_aggregator(
            ConfigurationAggregatorName=AWS_CONFIG_AGGREGATOR_NAME
        )
        logger.debug(delete_config)
        logger.info("Deleted the AWS Config Aggregator")
    except ClientError as exc:
        logger.error(f"Unexpected error: {str(exc)}")
        raise


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response or True
    """
    logger.info("....Lambda Handler Started....")
    if "detail-type" in event:
        enable_config_aggregator()
        return True
    else:
        helper(event, context)
