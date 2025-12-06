"""Custom Resource to configure an Organization CloudTrail in the Control Tower management account.

Version: 1.1

'cloudtrail_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING, Optional

import boto3
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_cloudtrail.client import CloudTrailClient
    from mypy_boto3_cloudtrail.type_defs import DataResourceTypeDef, EventSelectorTypeDef
    from mypy_boto3_organizations.client import OrganizationsClient

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Initialize the helper
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

AWS_SERVICE_PRINCIPAL = "cloudtrail.amazonaws.com"
UNEXPECTED = "Unexpected!"
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

try:
    management_account_session = boto3.Session()
    CLOUDTRAIL_CLIENT: CloudTrailClient = management_account_session.client("cloudtrail", config=BOTO3_CONFIG)
    ORG_CLIENT: OrganizationsClient = management_account_session.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def list_delegated_administrator(delegated_admin_account_id: str, service_principal: str) -> None:
    """Check if the delegated administrator account for the provided service principal exists.

    Args:
        delegated_admin_account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal

    Raises:
        ValueError: Error registering the delegated administrator account
    """
    LOGGER.info(f"Checking if delegated administrator already registered for: {service_principal}")

    try:
        delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

        if not delegated_administrators:
            LOGGER.info(f"The delegated administrator {service_principal} was not registered")
            raise ValueError("Error registering the delegated administrator account")
    except ORG_CLIENT.exceptions.AccountAlreadyRegisteredException:
        LOGGER.debug(f"Account: {delegated_admin_account_id} already registered for {service_principal}")


def set_delegated_admin(delegated_admin_account_id: str) -> None:
    """Set the delegated admin account.

    Args:
        delegated_admin_account_id: Admin account ID

    Raises:
        Exception: raises exception as e
    """
    try:
        delegated_admin_response = CLOUDTRAIL_CLIENT.register_organization_delegated_admin(MemberAccountId=delegated_admin_account_id)
        api_call_details = {"API_Call": "cloudtrail:RegisterOrganizationDelegatedAdmin", "API_Response": delegated_admin_response}
        LOGGER.info(api_call_details)
        LOGGER.info(f"Delegated admin ({delegated_admin_account_id}) enabled")
    except CLOUDTRAIL_CLIENT.exceptions.AccountRegisteredException:
        LOGGER.info("Delegated admin already registered")
    except Exception as e:
        LOGGER.error(f"Failed to enable delegated admin. {e}")
        raise


def deregister_delegated_administrator(delegated_admin_account_id: str, service_principal: str) -> None:
    """Deregister the delegated administrator account for the provided service principal.

    Args:
        delegated_admin_account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal format: service_name.amazonaws.com

    """
    LOGGER.info(f"Deregistering AWS Service Access for: {service_principal}")

    try:
        delegated_admin_response = CLOUDTRAIL_CLIENT.deregister_organization_delegated_admin(DelegatedAdminAccountId=delegated_admin_account_id)
        api_call_details = {"API_Call": "cloudtrail:DeregisterOrganizationDelegatedAdmin", "API_Response": delegated_admin_response}
        LOGGER.info(api_call_details)
        LOGGER.info(f"Delegated admin ({delegated_admin_account_id}) deregistered")
        delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

        LOGGER.debug(str(delegated_administrators))

        if not delegated_administrators:
            LOGGER.info(f"The deregister was successful for the {service_principal} delegated administrator")
    except ORG_CLIENT.exceptions.AccountNotRegisteredException:
        LOGGER.info(f"Account: {delegated_admin_account_id} not registered for {service_principal}")


def get_data_event_config(
    aws_partition: str, enable_data_events_only: bool, enable_s3_data_events: bool, enable_lambda_data_events: bool
) -> EventSelectorTypeDef:
    """Create the CloudTrail event selectors configuration.

    Args:
        aws_partition: AWS partition
        enable_data_events_only: Enable Data Events Only
        enable_s3_data_events: Enable S3 Data Events
        enable_lambda_data_events: Enable Lambda Data Events

    Returns:
        event selectors
    """
    event_selectors: EventSelectorTypeDef = {}

    if enable_data_events_only:
        event_selectors = {
            "ReadWriteType": "All",
            "IncludeManagementEvents": False,
            "DataResources": [],
        }
    else:
        event_selectors = {
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [],
        }
    event_list: list = []
    if enable_s3_data_events:
        s3_data_resource: DataResourceTypeDef = {"Type": "AWS::S3::Object", "Values": [f"arn:{aws_partition}:s3:::"]}
        event_list.append(s3_data_resource)
        LOGGER.info("S3 Data Events Added to Event Selectors")

    if enable_lambda_data_events:
        lambda_data_resource: DataResourceTypeDef = {
            "Type": "AWS::Lambda::Function",
            "Values": [f"arn:{aws_partition}:lambda"],
        }
        event_list.append(lambda_data_resource)
        LOGGER.info("Lambda Data Events Added to Event Selectors")
    event_selectors["DataResources"] = event_list

    return event_selectors


def enable_aws_service_access(service_principal: str) -> None:
    """Enable AWS Service Access for the provided service principal.

    Args:
        service_principal: AWS Service Principal format: service_name.amazonaws.com
    """
    LOGGER.info(f"Enable AWS Service Access for: {service_principal}")

    organizations = boto3.client("organizations", config=BOTO3_CONFIG)
    organizations.enable_aws_service_access(ServicePrincipal=service_principal)


def get_cloudtrail_parameters(is_create: bool, params: dict) -> dict:
    """Dynamically creates a parameter dict for the CloudTrail create_trail and update_trail API calls.

    Args:
        is_create: true, false
        params: parameters

    Returns:
        CloudTrail params
    """
    cloudtrail_params = {
        "Name": params["cloudtrail_name"],
        "S3BucketName": params["s3_bucket_name"],
        "IncludeGlobalServiceEvents": True,
        "IsMultiRegionTrail": True,
        "EnableLogFileValidation": True,
        "KmsKeyId": params["kms_key_id"],
        "IsOrganizationTrail": True,
    }

    if is_create:
        cloudtrail_params["TagsList"] = [{"Key": "sra-solution", "Value": params["sra_solution_name"]}]

    if params.get("cloudwatch_log_group_arn", "") and params.get("cloudwatch_log_group_role_arn", ""):
        cloudtrail_params["CloudWatchLogsLogGroupArn"] = params["cloudwatch_log_group_arn"]
        cloudtrail_params["CloudWatchLogsRoleArn"] = params["cloudwatch_log_group_role_arn"]

    return cloudtrail_params


def parameter_pattern_validator(parameter_name: str, parameter_value: Optional[str], pattern: str) -> None:
    """Validate CloudFormation Custom Resource Parameters.

    Args:
        parameter_name: CloudFormation custom resource parameter name
        parameter_value: CloudFormation custom resource parameter value
        pattern: REGEX pattern to validate against.

    Raises:
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern
    """
    if not parameter_value:
        raise ValueError(f"'{parameter_name}' parameter is missing.")
    elif not re.match(pattern, parameter_value):
        raise ValueError(f"'{parameter_name}' parameter with value of '{parameter_value}' does not follow the allowed pattern: {pattern}.")


def get_validated_parameters(event: CloudFormationCustomResourceEvent) -> dict:
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = event["ResourceProperties"].copy()
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event["RequestType"]]

    true_false_pattern = r"(?i)^true|false$"

    parameter_pattern_validator("AWS_PARTITION", params.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$")
    parameter_pattern_validator("CLOUDTRAIL_NAME", params.get("CLOUDTRAIL_NAME"), pattern=r"^[A-Za-z0-9][a-zA-Z0-9-\-_.]{2,127}$")
    parameter_pattern_validator(
        "KMS_KEY_ID",
        params.get("KMS_KEY_ID"),
        pattern=r"^arn:(aws[a-zA-Z-]*){1}:kms:[a-z0-9-]+:\d{12}:key\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    )
    parameter_pattern_validator("S3_BUCKET_NAME", params.get("S3_BUCKET_NAME"), pattern=r"^[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$")
    parameter_pattern_validator("SRA_SOLUTION_NAME", params.get("SRA_SOLUTION_NAME"), pattern=r"^.{1,256}$")
    parameter_pattern_validator(
        "DELEGATED_ADMIN_ACCOUNT_ID",
        params.get("DELEGATED_ADMIN_ACCOUNT_ID"),
        pattern=r"^\d{12}$",
    )
    parameter_pattern_validator("ENABLE_DATA_EVENTS_ONLY", params.get("ENABLE_DATA_EVENTS_ONLY"), pattern=true_false_pattern)
    parameter_pattern_validator("ENABLE_LAMBDA_DATA_EVENTS", params.get("ENABLE_LAMBDA_DATA_EVENTS"), pattern=true_false_pattern)
    parameter_pattern_validator("ENABLE_S3_DATA_EVENTS", params.get("ENABLE_S3_DATA_EVENTS"), pattern=true_false_pattern)

    if params.get("CLOUDWATCH_LOG_GROUP_ARN", "") or params.get("CLOUDWATCH_LOG_GROUP_ROLE_ARN", ""):
        parameter_pattern_validator(
            "CLOUDWATCH_LOG_GROUP_ARN",
            params.get("CLOUDWATCH_LOG_GROUP_ARN"),
            pattern=r"^arn:(aws[a-zA-Z-]*)?:logs:[a-z0-9-]+:\d{12}:log-group:[a-zA-Z0-9/_-]+:[*]$",
        )

        parameter_pattern_validator(
            "CLOUDWATCH_LOG_GROUP_ROLE_ARN",
            params.get("CLOUDWATCH_LOG_GROUP_ROLE_ARN"),
            pattern=r"^arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role\/([\w+=,.@-]*\/)*[\w+=,.@-]+$",
        )

    return params


def process_create_update(params: dict) -> None:
    """Process Create and Update event.

    Args:
        params: parameters
    """
    enable_aws_service_access(AWS_SERVICE_PRINCIPAL)
    list_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], AWS_SERVICE_PRINCIPAL)
    set_delegated_admin(params["DELEGATED_ADMIN_ACCOUNT_ID"])
    cloudtrail_params = {
        "cloudtrail_name": params["CLOUDTRAIL_NAME"],
        "cloudwatch_log_group_arn": params["CLOUDWATCH_LOG_GROUP_ARN"],
        "cloudwatch_log_group_role_arn": params["CLOUDWATCH_LOG_GROUP_ROLE_ARN"],
        "kms_key_id": params["KMS_KEY_ID"],
        "s3_bucket_name": params["S3_BUCKET_NAME"],
        "sra_solution_name": params["SRA_SOLUTION_NAME"],
    }

    if params["action"] == "Add":
        try:
            CLOUDTRAIL_CLIENT.create_trail(**get_cloudtrail_parameters(True, cloudtrail_params))
        except CLOUDTRAIL_CLIENT.exceptions.TrailAlreadyExistsException:
            LOGGER.info(f"{params['CLOUDTRAIL_NAME']} already exists.")
    elif params["action"] == "Update":
        CLOUDTRAIL_CLIENT.update_trail(**get_cloudtrail_parameters(False, cloudtrail_params))
    LOGGER.info(f"Successful {params['action']} of the Organization CloudTrail")

    event_selectors = get_data_event_config(
        aws_partition=params.get("AWS_PARTITION", "aws"),
        enable_data_events_only=(params.get("ENABLE_DATA_EVENTS_ONLY", "false")).lower() in "true",
        enable_lambda_data_events=(params.get("ENABLE_LAMBDA_DATA_EVENTS", "false")).lower() in "true",
        enable_s3_data_events=(params.get("ENABLE_S3_DATA_EVENTS", "false")).lower() in "true",
    )

    if event_selectors:
        CLOUDTRAIL_CLIENT.put_event_selectors(TrailName=params["CLOUDTRAIL_NAME"], EventSelectors=[event_selectors])
        LOGGER.info("Data Events Enabled")

    CLOUDTRAIL_CLIENT.start_logging(Name=params["CLOUDTRAIL_NAME"])


@helper.create
@helper.update
@helper.delete
def process_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa: U100
    """Process CloudFormation Event. Creates, updates, and deletes a CloudTrail with the provided parameters.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    LOGGER.debug(f"{context}")

    params = get_validated_parameters(event)

    if params["action"] in "Add, Update":
        process_create_update(params)
    elif params["action"] == "Remove":
        try:
            deregister_delegated_administrator(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), AWS_SERVICE_PRINCIPAL)
            CLOUDTRAIL_CLIENT.delete_trail(Name=params["CLOUDTRAIL_NAME"])
            LOGGER.info("Deleted the Organizations CloudTrail")
        except CLOUDTRAIL_CLIENT.exceptions.TrailNotFoundException:
            LOGGER.info(f"{params['CLOUDTRAIL_NAME']} not found to delete.")

    return f"{params['CLOUDTRAIL_NAME']}-CloudTrail"


def lambda_handler(event: CloudFormationCustomResourceEvent, context: Context) -> None:  # noqa: U100
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


def terraform_handler(event: CloudFormationCustomResourceEvent, context: Context) -> None:  # noqa: U100
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function

    """
    try:
        process_event(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
