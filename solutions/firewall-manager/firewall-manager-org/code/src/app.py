########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
import time
import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

"""
The purpose of this script is to associate a Firewall manager administrator account
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="INFO", boto_level="CRITICAL")

CLOUDFORMATION_PARAMETERS = ["ASSUME_ROLE_NAME", "AWS_PARTITION", "DELEGATED_ADMIN_ACCOUNT_ID"]
STS_CLIENT = boto3.client("sts")

try:
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

except Exception as e:
    helper.init_failure(e)


def check_parameters(event: dict):
    """
    Check event for required parameters in the ResourceProperties
    :param event:
    :return:
    """
    try:
        if "StackId" not in event or "ResourceProperties" not in event:
            raise ValueError("Invalid CloudFormation request, missing StackId or ResourceProperties.")

        # Check CloudFormation parameters
        for parameter in CLOUDFORMATION_PARAMETERS:
            if parameter not in event.get("ResourceProperties", ""):
                raise ValueError("Invalid CloudFormation request, missing one or more ResourceProperties.")

        logger.debug(f"Stack ID : {event.get('StackId')}")
        logger.debug(f"Stack Name : {event.get('StackId').split('/')[1]}")
    except Exception as error:
        logger.error(f"Exception checking parameters {error}")
        raise ValueError("Error checking parameters")


def assume_role(aws_partition: str, aws_account_number: str, role_name: str):
    """
    Assumes the provided role in the provided account and returns a session
    :param aws_partition
    :param aws_account_number: AWS Account Number
    :param role_name: Role name to assume in target account
    :return: session for the account and role name
    """
    try:
        response = STS_CLIENT.assume_role(
            RoleArn=f"arn:{aws_partition}:iam::{aws_account_number}:role/{role_name}",
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
        logger.error(f"Unexpected error: {exc}")
        raise ValueError("Error assuming role")


def associate_admin_account(delegated_admin_account_id: str):
    """
    Associate an administrator account for Firewall Manager
    :param delegated_admin_account_id: Delegated admin account ID
    :return: None
    """
    firewall_manager_client = boto3.client("fms", region_name="us-east-1")  # APIs only work in us-east-1 region

    try:
        logger.info("Making sure there is no existing admin account")
        admin_account = firewall_manager_client.get_admin_account()
        if "AdminAccount" in admin_account:
            logger.error("Admin account already exists. Disassociate the account first")
            raise ValueError("Admin account already exists. Disassociate the account first")
    except ClientError as ce:
        if "ResourceNotFoundException" in str(ce):
            logger.info(f"Administrator account does not exist. Continuing... {ce}")
        else:
            logger.error(f"Unexpected error: {ce}")
            raise ValueError("Error getting existing admin account.")

    try:
        logger.info("Associating admin account in Firewall Manager")
        firewall_manager_client.associate_admin_account(AdminAccount=delegated_admin_account_id)
        logger.info("...waiting 1 minute")
        time.sleep(60)  # use 1 minute wait
        while True:
            try:
                logger.info("Getting admin account status in Firewall Manager")
                admin_account_status = firewall_manager_client.get_admin_account()
                logger.info(f"get admin account status is {admin_account_status['RoleStatus']}")
                if admin_account_status["RoleStatus"] == "READY":
                    logger.info("Admin account status = READY")
                    break
                logger.info("...waiting 20 seconds")
                time.sleep(20)
                continue
            except ClientError:
                logger.error("There was an getting admin account info in Firewall Manager")
                raise ValueError("Error getting admin account info in Firewall Manager")
    except ClientError as ce:
        logger.error(f"There was an issue associating admin account in Firewall Manager: {ce}")
        raise ValueError("Unexpected error. Check logs for details.")
    except Exception as exc:
        logger.error(f"Unexpected error: {exc}")
        raise ValueError("Unexpected error. Check logs for details.")


@helper.create
def create(event, _):
    """
    CloudFormation Create Event. Delegates an administrator account
    :param event: event data
    :param _: ignore value
    :return: FMSDelegateAdminResourceId
    """
    logger.info("Create Event")
    try:
        check_parameters(event)
        params = event.get("ResourceProperties")

        associate_admin_account(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""))
    except Exception as exc:
        logger.error(f"Exception: {exc}")
        raise ValueError("Error delegating the admin account")

    return "FMSDelegateAdminResourceId"


@helper.update
def update(event, _):
    """
    CloudFormation Update Event. Updates Firewall Manager delegated admin account.
    :param event: event data
    :param _: ignore value
    :return: CloudFormation response
    """
    logger.info("Update Event")
    try:
        logger.info(f"stack is being {event['RequestType']}d")
        check_parameters(event)
        params = event.get("ResourceProperties")

        firewall_manager_client = boto3.client("fms", region_name="us-east-1")  # APIs only work in us-east-1 region
        admin_account = firewall_manager_client.get_admin_account()

        if "AdminAccount" in admin_account:
            current_delegated_admin_account_id = admin_account["AdminAccount"]
            # Assume a role in the FW Manager Delegated Admin Account
            # and create a boto3 fms client with the creds
            session = assume_role(params.get("AWS_PARTITION", "aws"), current_delegated_admin_account_id,
                                  params.get("ASSUME_ROLE_NAME", ""))
            firewall_manager_session = session.client("fms", region_name="us-east-1")
            firewall_manager_session.disassociate_admin_account()
            logger.info("...waiting 10 minutes before associating new account")
            time.sleep(600)
    except ClientError as ce:
        logger.error(f"There was an error while disassociating the Firewall Manager admin account. {ce}")
        raise ValueError("Error disassociating the Firewall Manager admin account")

    try:
        associate_admin_account(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""))
    except Exception as exc:
        logger.error(f"Exception: {exc}")
        raise ValueError("Error updating the admin account")


@helper.delete
def delete(event, _):
    """
    CloudFormation Delete Event. 
    :param event: event data
    :param _:
    :return: CloudFormation response
    """
    logger.info("Delete Event")
    try:
        check_parameters(event)
        params = event.get("ResourceProperties")

        session = assume_role(params.get("AWS_PARTITION", "aws"), params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
                              params.get("ASSUME_ROLE_NAME", ""))
        firewall_manager_session = session.client("fms", region_name="us-east-1")  # APIs only work in us-east-1 region
        logger.info("Disassociate admin account in Firewall Manager")
        firewall_manager_session.disassociate_admin_account()
    except ClientError as ce:
        logger.error(f"There was an error disassociating admin account in Firewall Manager: {ce}")
        raise ValueError("There was an error disassociating admin account in Firewall Manager")
    except Exception as exc:
        if "AccessDenied" in str(exc):
            logger.debug(f"Continuing...Role doesn't exist or cannot be assumed: {exc}")
        else:
            logger.error(f"Unexpected Error: {exc}")
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
