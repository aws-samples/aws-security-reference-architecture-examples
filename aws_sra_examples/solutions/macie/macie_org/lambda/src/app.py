"""This script configures Macie within the delegated administrator account.

Configures Macie in all provided regions:
- adds existing accounts
- enables new accounts automatically
- publishes findings to an S3 bucket

Version: 1.2

'macie_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Dict

import boto3
import common
import macie
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

# Global variables
UNEXPECTED = "Unexpected!"
ACCOUNT_ID_PATTERN = re.compile(r"\d{12}")
REGION_PATTERN = re.compile(r"[a-z0-9-]{1,32}")
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


def enable_aws_service_access(service_principal: str) -> None:
    """Enable the AWS Service Access for the provided service principal.

    Args:
        service_principal: AWS Service Principal format: service_name.amazonaws.com
    """
    LOGGER.info(f"Enable AWS Service Access for: {service_principal}")

    organizations = boto3.client("organizations", config=BOTO3_CONFIG)
    organizations.enable_aws_service_access(ServicePrincipal=service_principal)


def process_create_update_event(params: dict, regions: list) -> None:
    """Process create update events.

    Args:
        params: input parameters
        regions: AWS regions
    """
    if (params.get("DISABLE_MACIE", "false")).lower() in "true" and params["action"] == "Update":
        account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])
        macie.process_delete_event(params, regions, account_ids, True)
    else:
        common.create_service_linked_role(
            "AWSServiceRoleForAmazonMacie",
            "macie.amazonaws.com",
            "A service-linked role required for Amazon Macie to access your resources.",
        )
        macie.process_organization_admin_account(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), regions)
        delegated_admin_session = common.assume_role(
            params.get("CONFIGURATION_ROLE_NAME", ""), "sra-macie-org", params.get("DELEGATED_ADMIN_ACCOUNT_ID", "")
        )

        LOGGER.info("Enabling Macie in the Management Account")
        macie.enable_macie(
            params["MANAGEMENT_ACCOUNT_ID"],
            "",
            regions,
            params["FINDING_PUBLISHING_FREQUENCY"],
        )

        macie.configure_macie(
            delegated_admin_session,
            params["DELEGATED_ADMIN_ACCOUNT_ID"],
            regions,
            params["PUBLISHING_DESTINATION_BUCKET_NAME"],
            params["KMS_KEY_ARN"],
            params["FINDING_PUBLISHING_FREQUENCY"],
        )


def parameter_pattern_validator(parameter_name: str, parameter_value: str, pattern: str) -> None:
    """Validate CloudFormation Custom Resource Parameters.

    Args:
        parameter_name: CloudFormation custom resource parameter name
        parameter_value: CloudFormation custom resource parameter value
        pattern: REGEX pattern to validate against.

    Raises:
        ValueError: Parameter does not follow the allowed pattern
    """
    if not re.fullmatch(pattern, parameter_value):
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

    parameter_pattern_validator("CONFIGURATION_ROLE_NAME", params.get("CONFIGURATION_ROLE_NAME", ""), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY", ""), pattern=r"^true|false$")
    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), pattern=ACCOUNT_ID_PATTERN.pattern)
    parameter_pattern_validator("DISABLE_MACIE", params.get("DISABLE_MACIE", ""), pattern=r"^true|false$")
    parameter_pattern_validator("DISABLE_MACIE_ROLE_NAME", params.get("DISABLE_MACIE_ROLE_NAME", ""), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("ENABLED_REGIONS", params.get("ENABLED_REGIONS", ""), pattern=r"^$|[a-z0-9-, ]+$")
    parameter_pattern_validator(
        "FINDING_PUBLISHING_FREQUENCY", params.get("FINDING_PUBLISHING_FREQUENCY", ""), pattern=r"^FIFTEEN_MINUTES|ONE_HOUR|SIX_HOURS$"
    )
    parameter_pattern_validator(
        "KMS_KEY_ARN",
        params.get("KMS_KEY_ARN", ""),
        pattern=r"^arn:(aws[a-zA-Z-]*){1}:kms:[a-z0-9-]+:\d{12}:key\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    )
    parameter_pattern_validator(
        "PUBLISHING_DESTINATION_BUCKET_NAME",
        params.get("PUBLISHING_DESTINATION_BUCKET_NAME", ""),
        pattern=r"^[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$",
    )
    parameter_pattern_validator(
        "SNS_TOPIC_ARN",
        params.get("SNS_TOPIC_ARN", ""),
        pattern=r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$",
    )
    parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", params.get("MANAGEMENT_ACCOUNT_ID", ""), pattern=ACCOUNT_ID_PATTERN.pattern)

    return params


def parse_disable_message(sns_info: dict, expected_topic_arn: str) -> dict | None:
    """Validate an SNS disable record and return its message, or None if the record must be dropped.

    Organization membership is not looked up per message: the fan-out sends one message per account, and
    listing the organization in every invocation throttles AWS Organizations in large organizations. The
    topic policy allows only this Lambda's role to publish, and the assumed role name comes from the
    Lambda environment.

    Args:
        sns_info: the "Sns" element of an SNS event record
        expected_topic_arn: ARN of the solution's own SNS topic

    Returns:
        The parsed message, or None if it is not a well-formed disable request
    """
    if sns_info.get("TopicArn") != expected_topic_arn:
        LOGGER.error(f"Dropping SNS record: TopicArn {sns_info.get('TopicArn')} is not the solution topic.")
        return None
    try:
        message = json.loads(sns_info["Message"])
    except (KeyError, TypeError, ValueError):
        LOGGER.error("Dropping SNS record: message body is not valid JSON.")
        return None
    if not isinstance(message, dict) or message.get("Action") != "disable":
        LOGGER.error("Dropping SNS record: message is not a disable request.")
        return None
    account_id = message.get("AccountId")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        LOGGER.error(f"Dropping SNS record: AccountId {account_id} is not a 12-digit account ID.")
        return None
    regions = message.get("Regions")
    if not isinstance(regions, list) or not all(isinstance(region, str) and REGION_PATTERN.fullmatch(region) for region in regions):
        LOGGER.error("Dropping SNS record: Regions must be a list of Region names.")
        return None
    return message


def process_sns_records(records: list) -> None:
    """Process SNS records.

    The SNS message body is treated as untrusted input: only well-formed disable requests published to the
    solution's own topic are processed. The role assumed in the member account comes from the Lambda
    environment, not from the message.

    Args:
        records: list of SNS event records
    """
    expected_topic_arn = os.environ["SNS_TOPIC_ARN"]
    disable_macie_role_name = os.environ["DISABLE_MACIE_ROLE_NAME"]

    for record in records:
        sns_info = record["Sns"]
        LOGGER.info(f"SNS Record: {sns_info}")
        message = parse_disable_message(sns_info, expected_topic_arn)
        if message:
            macie.disable_member_account(message["AccountId"], disable_macie_role_name, message["Regions"])


@helper.create
@helper.update
@helper.delete
def process_cloudformation_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    request_type = event["RequestType"]
    LOGGER.info(f"{request_type} Event")
    LOGGER.debug(f"Lambda Context: {context}")

    params = get_validated_parameters(event)
    regions = common.get_enabled_regions(params.get("ENABLED_REGIONS", ""), (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true")

    if params["action"] in "Add, Update":
        process_create_update_event(params, regions)
    elif params["action"] == "Remove":
        account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])
        macie.process_delete_event(params, regions, account_ids, False)

    return f"sra-macie-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def lambda_handler(event: Dict[str, Any], context: Context) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Lambda Handler Started....")
    try:
        if "Records" not in event and "RequestType" not in event and ("source" not in event and event["source"] != "aws.controltower"):
            raise ValueError(
                f"The event did not include Records, RequestType, or source. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
        elif "Records" in event and event["Records"][0]["EventSource"] == "aws:sns":
            process_sns_records(event["Records"])
        elif "RequestType" in event:
            helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None


def terraform_handler(event: Dict[str, Any], context: Context) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Terraform Lambda Handler Started....")
    try:
        if "Records" not in event and "RequestType" not in event and ("source" not in event and event["source"] != "aws.controltower"):
            raise ValueError(
                f"The event did not include Records, RequestType, or source. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
        elif "Records" in event and event["Records"][0]["EventSource"] == "aws:sns":
            process_sns_records(event["Records"])
        elif "RequestType" in event:
            process_cloudformation_event(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
