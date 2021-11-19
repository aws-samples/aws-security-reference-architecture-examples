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
The purpose of this script is to enable AWS service access for multi-account setup and delegate an administrator 
account. The delete event removes the delegated administrator account and disables the AWS service 
access for the service principal.
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level="CRITICAL")

CLOUDFORMATION_PARAMETERS = ["AWS_SERVICE_PRINCIPAL_LIST", "DELEGATED_ADMIN_ACCOUNT_ID"]
VALID_SERVICE_PRINCIPAL_LIST = ["access-analyzer.amazonaws.com", "auditmanager.amazonaws.com",
                                  "config-multiaccountsetup.amazonaws.com", "config.amazonaws.com",
                                  "macie.amazonaws.com", "securityhub.amazonaws.com",
                                  "stacksets.cloudformation.amazonaws.com", "storage-lens.s3.amazonaws.com"]
ORGANIZATIONS_CLIENT = boto3.client("organizations")

try:
    # Process Environment Variables
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")
except Exception as e:
    helper.init_failure(e)


def enable_aws_service_access(service_principal: str):
    """
    Enables the AWS Service Access for the provided service principal
    :param service_principal: AWS Service Principal
    :return: None
    """
    logger.info(f"Enabling AWS Service Access for: {service_principal}")

    try:
        ORGANIZATIONS_CLIENT.enable_aws_service_access(ServicePrincipal=service_principal)
    except ClientError as error:
        logger.error(f"enable_aws_service_access error: {error}")
        raise ValueError("Error enabling aws service access")


def disable_aws_service_access(service_principal: str):
    """
    Disables aws service access for the service principal
    :param service_principal: AWS Service Principal
    :return: None
    """
    logger.info(f"Disabling AWS Service Access for: {service_principal}")

    try:
        ORGANIZATIONS_CLIENT.disable_aws_service_access(ServicePrincipal=service_principal)
    except ClientError as error:
        logger.error(f"disable_aws_service_access error: {error}")
        raise ValueError("Error disabling aws service access")


def register_delegated_administrator(account_id: str, service_principal: str):
    """
    Registers the delegated administrator account for the provided service principal
    :param account_id: Delegated Administrator Account ID
    :param service_principal: AWS Service Principal
    :return: None
    """
    logger.info(f"Registering a delegated administrator account for : {service_principal}")

    try:
        # Register the delegated administrator
        ORGANIZATIONS_CLIENT.register_delegated_administrator(AccountId=account_id,
                                                              ServicePrincipal=service_principal)

        # Get the delegated administrators
        delegated_administrators = ORGANIZATIONS_CLIENT.list_delegated_administrators(
            ServicePrincipal=service_principal)
        logger.info(f"{delegated_administrators}")

        if not delegated_administrators:
            logger.info(f"The delegated administrator {service_principal} was not registered")
            raise ValueError("Error registering the delegated administrator account")
    except ORGANIZATIONS_CLIENT.exceptions.AccountAlreadyRegisteredException:
        logger.debug(f"Account: {account_id} already registered for {service_principal}")
    except Exception as error:
        logger.error(f"register_delegated_administrator error: {error}")
        raise ValueError("Error registering the delegated administrator account")


def deregister_delegated_administrator(account_id: str, service_principal: str):
    """
    Deregister the delegated administrator account for the provided service principal
    :param account_id: Delegated administrator account ID
    :param service_principal: AWS service principal
    :return: None
    """
    logger.info(f"Deregister AWS Service Access for: {service_principal}")

    try:
        # Deregister the delegated administrator
        ORGANIZATIONS_CLIENT.deregister_delegated_administrator(AccountId=account_id,
                                                                ServicePrincipal=service_principal)
        # Get the delegated administrator
        delegated_administrators = ORGANIZATIONS_CLIENT.list_delegated_administrators(
            ServicePrincipal=service_principal)

        logger.debug(str(delegated_administrators))

        if not delegated_administrators:
            logger.info(f"The deregister was successful for the {service_principal} delegated administrator")
    except ORGANIZATIONS_CLIENT.exceptions.AccountNotRegisteredException:
        logger.debug(f"Account: {account_id} not registered for {service_principal}")
    except Exception as error:
        logger.error(f"deregister_delegated_administrator error: {error}")
        raise ValueError("Error trying to deregister delegated administrator account")


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


def check_service_principals(service_principal_list: list):
    """
    Check Service Principals
    :param service_principal_list:
    :return: None
    """
    try:
        for service_principal in service_principal_list:
            if service_principal not in VALID_SERVICE_PRINCIPAL_LIST:
                logger.error(f"Invalid service principal provided - {service_principal}. "
                             f"Valid Values={VALID_SERVICE_PRINCIPAL_LIST}")
                raise ValueError(f"Invalid Service Principal - {service_principal}")
    except Exception as error:
        logger.error(f"Error checking service principals - {error}")


@helper.create
def create(event, _):
    """
    CloudFormation Create Event.
    :param event: event data
    :param _:
    :return: DelegatedAdminResourceId
    """
    request_type = event["RequestType"]
    logger.info(f"{request_type} Event")
    try:
        check_parameters(event)
        params = event.get("ResourceProperties")
        logger.debug(f"{params.get('AWS_SERVICE_PRINCIPAL_LIST', '')}")
        aws_service_principal_list = [value.strip() for value in params.get("AWS_SERVICE_PRINCIPAL_LIST", "")
                                      if value != '']
        check_service_principals(aws_service_principal_list)

        for aws_service_principal in aws_service_principal_list:
            enable_aws_service_access(aws_service_principal)
            register_delegated_administrator(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), aws_service_principal)
    except Exception as error:
        logger.error(f"Exception: {error}")
        raise ValueError("Error delegating the administrator account")

    return "DelegatedAdminResourceId"


@helper.update
def update(event, _):
    """
    CloudFormation Update Event
    :param event:
    :param _:
    :return:
    """
    logger.info(f"Update Event: {event}")
    try:
        check_parameters(event)
        params = event.get("ResourceProperties")
        aws_service_principal_list = [value.strip() for value in params.get("AWS_SERVICE_PRINCIPAL_LIST", "")
                                      if value != '']
        check_service_principals(aws_service_principal_list)

        old_params = event.get("OldResourceProperties")
        old_aws_service_principal_list = [value.strip() for value in old_params.get("AWS_SERVICE_PRINCIPAL_LIST", "")
                                          if value != '']
        add_list = list(set(aws_service_principal_list) - set(old_aws_service_principal_list))
        remove_list = list(set(old_aws_service_principal_list) - set(aws_service_principal_list))

        if add_list:
            for aws_service_principal in add_list:
                enable_aws_service_access(aws_service_principal)
                register_delegated_administrator(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), aws_service_principal)

        if remove_list:
            for aws_service_principal in remove_list:
                deregister_delegated_administrator(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), aws_service_principal)
                disable_aws_service_access(aws_service_principal)
    except Exception as error:
        logger.error(f"Exception: {error}")
        raise ValueError("Error updating delegated administrators")


@helper.delete
def delete(event, _):
    """
    CloudFormation Delete Event.
    :param event: event data
    :param _:
    :return: CloudFormation response
    """
    logger.info(f"Delete Event: {event}")
    try:
        check_parameters(event)
        params = event.get("ResourceProperties")

        aws_service_principal_list = [value.strip() for value in params.get("AWS_SERVICE_PRINCIPAL_LIST", "")
                                      if value != '']
        check_service_principals(aws_service_principal_list)

        for aws_service_principal in aws_service_principal_list:
            deregister_delegated_administrator(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), aws_service_principal)
            disable_aws_service_access(aws_service_principal)
    except Exception as error:
        logger.error(f"Exception: {error}")
        raise ValueError("Error disabling delegated administrators")


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("....Lambda Handler Started....")
    helper(event, context)
