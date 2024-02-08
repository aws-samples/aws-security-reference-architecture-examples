"""Custom Resource to enable AWS service access for multi-account setup and delegate an administrator account in the Control Tower management account.

Version: 1.1

'common_register_delegated_administrator' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Union

import boto3
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceCreate, CloudFormationCustomResourceDelete, CloudFormationCustomResourceUpdate
    from mypy_boto3_organizations.client import OrganizationsClient

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Initialize the helper
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

CLOUDFORMATION_PARAMETERS = ["AWS_SERVICE_PRINCIPAL_LIST", "DELEGATED_ADMIN_ACCOUNT_ID"]
VALID_SERVICE_PRINCIPAL_LIST = [
    "access-analyzer.amazonaws.com",
    "auditmanager.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "config.amazonaws.com",
    "macie.amazonaws.com",
    "securityhub.amazonaws.com",
    "stacksets.cloudformation.amazonaws.com",
    "storage-lens.s3.amazonaws.com",
]
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
management_account_session = boto3.Session()
ORGANIZATIONS_CLIENT: OrganizationsClient = management_account_session.client("organizations", config=BOTO3_CONFIG)
UNEXPECTED = "Unexpected!"


def enable_aws_service_access(service_principal: str) -> None:
    """Enable AWS Service Access for the provided service principal.

    Args:
        service_principal: AWS Service Principal
    """
    LOGGER.info(f"Enabling AWS Service Access for: {service_principal}")

    ORGANIZATIONS_CLIENT.enable_aws_service_access(ServicePrincipal=service_principal)


def disable_aws_service_access(service_principal: str) -> None:
    """Disables aws service access for the service principal.

    Args:
        service_principal: AWS Service Principal
    """
    LOGGER.info(f"Disabling AWS Service Access for: {service_principal}")

    ORGANIZATIONS_CLIENT.disable_aws_service_access(ServicePrincipal=service_principal)


def register_delegated_administrator(account_id: str, service_principal: str) -> None:
    """Register the delegated administrator account for the provided service principal.

    Args:
        account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal

    Raises:
        ValueError: Error registering the delegated administrator account
    """
    LOGGER.info(f"Registering a delegated administrator account for : {service_principal}")

    try:
        # Register the delegated administrator
        ORGANIZATIONS_CLIENT.register_delegated_administrator(AccountId=account_id, ServicePrincipal=service_principal)

        # Get the delegated administrators
        delegated_administrators = ORGANIZATIONS_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)
        LOGGER.info(f"{delegated_administrators}")

        if not delegated_administrators:
            LOGGER.info(f"The delegated administrator {service_principal} was not registered")
            raise ValueError("Error registering the delegated administrator account")
    except ORGANIZATIONS_CLIENT.exceptions.AccountAlreadyRegisteredException:
        LOGGER.debug(f"Account: {account_id} already registered for {service_principal}")


def deregister_delegated_administrator(account_id: str, service_principal: str) -> None:
    """Deregister the delegated administrator account for the provided service principal.

    Args:
        account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal
    """
    LOGGER.info(f"Deregister AWS Service Access for: {service_principal}")

    try:
        # Deregister the delegated administrator
        ORGANIZATIONS_CLIENT.deregister_delegated_administrator(AccountId=account_id, ServicePrincipal=service_principal)
        # Get the delegated administrator
        delegated_administrators = ORGANIZATIONS_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

        LOGGER.debug(str(delegated_administrators))

        if not delegated_administrators:
            LOGGER.info(f"The deregister was successful for the {service_principal} delegated administrator")
    except ORGANIZATIONS_CLIENT.exceptions.AccountNotRegisteredException:
        LOGGER.debug(f"Account: {account_id} not registered for {service_principal}")


def check_parameters(
    event: Union[CloudFormationCustomResourceCreate, CloudFormationCustomResourceUpdate, CloudFormationCustomResourceDelete]
) -> None:
    """Check event for required parameters in the ResourceProperties.

    Args:
        event: CloudFormationCustomResourceEvent

    Raises:
        ValueError: Invalid CloudFormation request, missing StackId or ResourceProperties
        ValueError: Invalid CloudFormation request, missing one or more ResourceProperties.
    """
    if "StackId" not in event or "ResourceProperties" not in event:
        raise ValueError("Invalid CloudFormation request, missing StackId or ResourceProperties.")

    # Check CloudFormation parameters
    for parameter in CLOUDFORMATION_PARAMETERS:
        if parameter not in event["ResourceProperties"]:
            raise ValueError("Invalid CloudFormation request, missing one or more ResourceProperties.")

    LOGGER.debug(f"Stack ID : {event.get('StackId')}")
    LOGGER.debug(f"Stack Name : {event['StackId'].split('/')[1]}")


def check_service_principals(service_principal_list: list) -> None:
    """Check Service Principals.

    Args:
        service_principal_list: AWS service principal list

    Raises:
        ValueError: Invalid Service Principal
    """
    for service_principal in service_principal_list:
        if service_principal not in VALID_SERVICE_PRINCIPAL_LIST:
            LOGGER.error(f"Invalid service principal provided - {service_principal}. Valid Values={VALID_SERVICE_PRINCIPAL_LIST}")
            raise ValueError(f"Invalid Service Principal - {service_principal}")


@helper.create
def create(event: CloudFormationCustomResourceCreate, context: Context) -> str:  # noqa U100
    """Process CloudFormation Create Event.

    Args:
        event: event data
        context: runtime information

    Returns:
        Resource ID
    """
    request_type = event["RequestType"]
    LOGGER.info(f"{request_type} Event")

    check_parameters(event)
    params = event["ResourceProperties"]
    LOGGER.debug(f"{params['AWS_SERVICE_PRINCIPAL_LIST']}")
    aws_service_principal_list = [value.strip() for value in params["AWS_SERVICE_PRINCIPAL_LIST"] if value != ""]
    check_service_principals(aws_service_principal_list)

    for aws_service_principal in aws_service_principal_list:
        enable_aws_service_access(aws_service_principal)
        register_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], aws_service_principal)

    return f"DelegatedAdminResourceId-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


@helper.update
def update(event: CloudFormationCustomResourceUpdate, context: Context) -> str:  # noqa U100
    """Process CloudFormation Update Event.

    Args:
        event: event data
        context: runtime information

    Returns:
        Resource ID
    """
    LOGGER.info(f"Update Event: {event}")

    check_parameters(event)
    params = event["ResourceProperties"]
    aws_service_principal_list = [value.strip() for value in params.get("AWS_SERVICE_PRINCIPAL_LIST", "") if value != ""]
    check_service_principals(aws_service_principal_list)

    old_params = event["OldResourceProperties"]
    old_aws_service_principal_list = [value.strip() for value in old_params.get("AWS_SERVICE_PRINCIPAL_LIST", "") if value != ""]
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
    return f"DelegatedAdminResourceId-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


@helper.delete
def delete(event: CloudFormationCustomResourceDelete, context: Context) -> str:  # noqa U100
    """Process CloudFormation Delete Event.

    Args:
        event: event data
        context: runtime information

    Returns:
        Resource ID
    """
    LOGGER.info(f"Delete Event: {event}")

    check_parameters(event)
    params = event["ResourceProperties"]

    aws_service_principal_list = [value.strip() for value in params["AWS_SERVICE_PRINCIPAL_LIST"] if value != ""]
    check_service_principals(aws_service_principal_list)

    for aws_service_principal in aws_service_principal_list:
        deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], aws_service_principal)
        disable_aws_service_access(aws_service_principal)
    return f"DelegatedAdminResourceId-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def lambda_handler(
    event: Union[CloudFormationCustomResourceCreate, CloudFormationCustomResourceUpdate, CloudFormationCustomResourceDelete], context: Context
) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function

    """
    try:
        helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None


def terraform_handler(event: dict, context: Context) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Lambda Handler Started....")
    event_info = {"Event": event}
    LOGGER.info(event_info)
    try:
        request_type = event["RequestType"]

        if request_type == "Create":
            create(event, context)
        elif request_type == "Delete":
            delete(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
