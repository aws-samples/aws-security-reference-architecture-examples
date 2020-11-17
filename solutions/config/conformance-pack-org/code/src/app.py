########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

"""
The purpose of this script is to enable AWS service access for AWS Config
multi-account setup and delegate an administrator account. The delete event
removes the delegated administrator account and disables the AWS service 
access for AWS Config.
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level="CRITICAL")

try:
    # Process Environment Variables
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

    DELEGATED_ADMIN_ACCOUNT_ID = os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID", "")
    if not DELEGATED_ADMIN_ACCOUNT_ID or not isinstance(
        DELEGATED_ADMIN_ACCOUNT_ID, str
    ):
        raise ValueError("DELEGATED_ADMIN_ACCOUNT_ID parameter is missing or invalid")

    AWS_SERVICE_PRINCIPAL = os.environ.get(
        "AWS_SERVICE_PRINCIPAL", ""
    )  # "config-multiaccountsetup.amazonaws.com"
    if not AWS_SERVICE_PRINCIPAL or not isinstance(AWS_SERVICE_PRINCIPAL, str):
        raise ValueError("AWS_SERVICE_PRINCIPAL parameter is missing or invalid")
except Exception as e:
    helper.init_failure(e)


def enable_aws_service_access(service_principal: str):
    """
    Enables the AWS Service Access for the provided service principal
    :param service_principal: AWS Service Principal
    :return: None
    """
    logger.info("Enable AWS Service Access for: " + str(service_principal))

    try:
        organizations = boto3.client("organizations")
        organizations.enable_aws_service_access(ServicePrincipal=service_principal)
    except ClientError as ce:
        logger.error(f"enable_aws_service_access error: {str(ce)}")
        raise ValueError("Error enabling aws service access")


def disable_aws_service_access(service_principal: str):
    """
    Disables aws service access for the service principal
    :param service_principal: AWS Service Principal
    :return: None
    """
    logger.info("Disable AWS Service Access for: " + str(service_principal))

    try:
        organizations = boto3.client("organizations")
        organizations.disable_aws_service_access(ServicePrincipal=service_principal)
    except ClientError as ce:
        logger.error(f"disable_aws_service_access error: {str(ce)}")
        raise ValueError("Error disabling aws service access")


def register_delegated_administrator(account_id: str, service_principal: str):
    """
    Registers the delegated administrator account for the provided service principal
    :param account_id: Delegated Administrator Account ID
    :param service_principal: AWS Service Principal
    :return: None
    """
    logger.info(
        f"Register delegated administrator account for : {service_principal}"
    )

    try:
        organizations = boto3.client("organizations")
        organizations.register_delegated_administrator(
            AccountId=account_id, ServicePrincipal=service_principal
        )

        delegated_administrators = organizations.list_delegated_administrators(
            ServicePrincipal=service_principal
        )

        print(str(delegated_administrators))

        if not delegated_administrators:
            logger.debug(
                f"Delegated administrator for the service principle {service_principal} does not exist"
            )

    except ClientError as ce:
        logger.error(f"register_delegated_administrator error: {str(ce)}")
        raise ValueError("Error registering the delegated administrator account")


def deregister_delegated_administrator(account_id: str, service_principal: str):
    """
    Deregister the delegated administrator account for the provided service principal
    :param account_id: Delegated administrator account ID
    :param service_principal: AWS service principal
    :return: None
    """
    logger.info(f"Deregister AWS Service Access for: {str(service_principal)}")

    try:
        organizations = boto3.client("organizations")
        organizations.deregister_delegated_administrator(
            AccountId=account_id, ServicePrincipal=service_principal
        )

        delegated_administrators = organizations.list_delegated_administrators(
            ServicePrincipal=service_principal
        )

        logger.debug(str(delegated_administrators))

        if not delegated_administrators:
            logger.debug(
                f"Delegated administrator for the service principle {service_principal} does not exist"
            )

    except ClientError as ce:
        logger.error(f"deregister_delegated_administrator error: {str(ce)}")
        raise ValueError("Error trying to deregister delegated administrator account")


@helper.create
def create(event, context):
    """
    CloudFormation Create Event.
    :param event: event data
    :param context: runtime information
    :return: ConfigDelegatedAdminResourceId
    """
    logger.info("Create Event")
    try:
        enable_aws_service_access(AWS_SERVICE_PRINCIPAL)
        register_delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID, AWS_SERVICE_PRINCIPAL)
    except Exception as exc:
        logger.error(f"Exception: {exc}")
        raise ValueError("Error delegating the admin account")

    return "ConfigDelegatedAdminResourceId"


@helper.update
def update(event, context):
    """
    CloudFormation Update Event.
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("Update Event. Nothing processed")


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
        deregister_delegated_administrator(
            DELEGATED_ADMIN_ACCOUNT_ID, AWS_SERVICE_PRINCIPAL
        )
        disable_aws_service_access(AWS_SERVICE_PRINCIPAL)
    except Exception as exc:
        logger.error(f"Exception: {exc}")
        raise ValueError("Error disabling the admin account")


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("....Lambda Handler Started....")
    helper(event, context)
