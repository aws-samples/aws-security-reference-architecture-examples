########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
import re
import time
import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

"""
The purpose of this script is to associate a Firewall manager administrator account
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level="CRITICAL")
STS_CLIENT = boto3.client("sts")

try:
    # Process Environment Variables
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

    ASSUME_ROLE_NAME = os.environ.get("ASSUME_ROLE_NAME", "")
    if not ASSUME_ROLE_NAME or not re.match("[\\w+=,.@-]+", ASSUME_ROLE_NAME):
        raise ValueError("ASSUME_ROLE_NAME parameter is missing or invalid")

    AWS_PARTITION = os.environ.get("AWS_PARTITION", "")
    if AWS_PARTITION not in ("aws", "aws-cn", "aws-us-gov"):
        raise ValueError("AWS_PARTITION parameter is missing or invalid")
except Exception as e:
    helper.init_failure(e)


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
            RoleSessionName="FirewallManager",
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


def associate_admin_account(delegated_admin_account_id: str):
    """
    Associate an administrator account for Firewall Manager
    :param delegated_admin_account_id: Delegated admin account ID
    :return: None
    """
    firewall_manager = boto3.client("fms")

    try:
        logger.info("Making sure there is no existing admin account")
        admin_account = firewall_manager.get_admin_account()
        if "AdminAccount" in admin_account:
            logger.error("Admin account already exists. Disassociate the account first")
            raise ValueError(
                "Admin account already exists. Disassociate the account first"
            )
    except ClientError as ce:
        if "ResourceNotFoundException" in str(ce):
            logger.info(f"No existing administrator account. {ce}")
        else:
            logger.error(f"Unexpected error: {ce}")
            raise ValueError("Error getting existing admin account.")

    try:
        logger.info("Associating admin account in Firewall Manager")
        firewall_manager.associate_admin_account(AdminAccount=delegated_admin_account_id)
        time.sleep(60)  # use 1 minute wait
        while True:
            try:
                logger.info("Getting admin account status in Firewall Manager ")
                get_admin_account_status = firewall_manager.get_admin_account()
                logger.info(
                    "get admin account status is "
                    + get_admin_account_status["RoleStatus"]
                )
                if get_admin_account_status["RoleStatus"] == "READY":
                    break
                logger.info("going to sleep 20 sec")
                time.sleep(20)
                continue
            except ClientError:
                logger.error(
                    "There was an getting admin account info in Firewall Manager"
                )
                raise
    except ClientError as ce:
        logger.error(
            f"There was an issue associating admin account in Firewall Manager: {ce}"
        )
        raise ValueError("Unexpected error. Check logs for details.")
    except Exception as exc:
        logger.error(f"Unexpected error: {exc}")
        raise ValueError("Unexpected error. Check logs for details.")


@helper.create
def create(event, context):
    """
    CloudFormation Create Event. Delegates an administrator account
    :param event: event data
    :param context: runtime information
    :return: FMSDelegateAdminResourceId
    """
    logger.info("Create Event")
    try:
        delegated_admin_account_id = event["ResourceProperties"].get("DELEGATED_ADMIN_ACCOUNT_ID", "")
        associate_admin_account(delegated_admin_account_id)
    except Exception as exc:
        logger.error(f"Exception: {exc}")
        raise ValueError("Error delegating the admin account")

    return "FMSDelegateAdminResourceId"


@helper.update
def update(event, context):
    """
    CloudFormation Update Event. Updates Firewall Manager delegated admin account.
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("Update Event")
    try:
        logger.info(f"stack is being {event['RequestType']}d")
        firewall_manager = boto3.client("fms")
        admin_account = firewall_manager.get_admin_account()

        if "AdminAccount" in admin_account:
            current_delegated_admin_account_id = admin_account["AdminAccount"]
            # Assume a role in the FW Manager Delegated Admin Account
            # and create a boto3 fms client with the creds
            session = assume_role(current_delegated_admin_account_id, ASSUME_ROLE_NAME)
            firewall_manager_new = session.client("fms")
            firewall_manager_new.disassociate_admin_account()
            time.sleep(120)
            logger.info("Waiting 2 minutes before associating new account")
    except ClientError as ce:
        logger.error(
            f"There was an error while disassociating the Firewall Manager admin account. {ce}"
        )
        raise ValueError("Error disassociating the Firewall Manager admin account")

    try:
        delegated_admin_account_id = event["ResourceProperties"].get("DELEGATED_ADMIN_ACCOUNT_ID", "")
        associate_admin_account(delegated_admin_account_id)
    except Exception as exc:
        logger.error(f"Exception: {exc}")
        raise ValueError("Error updating the admin account")


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
        delegated_admin_account_id = event["ResourceProperties"].get("DELEGATED_ADMIN_ACCOUNT_ID", "")
        session = assume_role(delegated_admin_account_id, ASSUME_ROLE_NAME)
        firewall_manager = session.client("fms")
        logger.info("Disassociate admin account in Firewall Manager")
        firewall_manager.disassociate_admin_account()
    except ClientError as ce:
        logger.error(
            f"There was an error disassociating admin account in Firewall Manager: {str(ce)}"
        )
        raise ValueError("There was an error disassociating admin account in Firewall Manager")
    except Exception as exc:
        logger.error(f"Unexpected Error: {str(exc)}")
        raise ValueError("There was an error disassociating admin account in Firewall Manager")


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("....Lambda Handler Started....")
    helper(event, context)
