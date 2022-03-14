"""This script configures GuardDuty within the delegated administrator account.

Configures GuardDuty in all provided regions:
- adds existing accounts
- enables new accounts automatically
- publishes findings to an S3 bucket

Version: 1.1

'guardduty_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, Dict

import boto3
import common
import guardduty
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

# Global variables
UNEXPECTED = "Unexpected!"
MAX_RUN_COUNT = 30  # 5 minute wait = 30 x 10 seconds
SLEEP_SECONDS = 10

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def parameter_pattern_validator(parameter_name: str, parameter_value: str, pattern: str) -> None:
    """Validate CloudFormation Custom Resource Parameters.

    Args:
        parameter_name: CloudFormation custom resource parameter name
        parameter_value: CloudFormation custom resource parameter value
        pattern: REGEX pattern to validate against.

    Raises:
        ValueError: Parameter does not follow the allowed pattern
    """
    if not re.match(pattern, parameter_value):
        raise ValueError(f"'{parameter_name}' parameter with value of '{parameter_value}' does not follow the allowed pattern: {pattern}.")


def get_validated_parameters(event: CloudFormationCustomResourceEvent) -> dict:  # noqa: CCR001 (cognitive complexity)
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = event["ResourceProperties"].copy()
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event["RequestType"]]

    parameter_pattern_validator("AUTO_ENABLE_S3_LOGS", params.get("AUTO_ENABLE_S3_LOGS", ""), pattern=r"(?i)^true|false$")
    parameter_pattern_validator("CONFIGURATION_ROLE_NAME", params.get("CONFIGURATION_ROLE_NAME", ""), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY", ""), pattern=r"(?i)^true|false$")
    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), pattern=r"^\d{12}$")
    parameter_pattern_validator("DELETE_DETECTOR_ROLE_NAME", params.get("DELETE_DETECTOR_ROLE_NAME", ""), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("DISABLE_GUARD_DUTY", params.get("DISABLE_GUARD_DUTY", ""), pattern=r"(?i)^true|false$")
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
        "PUBLISHING_DESTINATION_BUCKET_ARN",
        params.get("PUBLISHING_DESTINATION_BUCKET_ARN", ""),
        pattern=r"^arn:(aws[a-zA-Z-]*){1}:s3:::[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$",
    )
    parameter_pattern_validator(
        "SNS_TOPIC_ARN",
        params.get("SNS_TOPIC_ARN", ""),
        pattern=r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$",
    )

    return params


def process_create_update_event(params: dict, regions: list) -> None:
    """Process create update events.

    Args:
        params: input parameters
        regions: AWS regions

    Raises:
        ValueError: GuardDuty detectors didn't get created in the allowed time
    """
    if (params.get("DISABLE_GUARD_DUTY", "false")).lower() in "true" and params["action"] == "Update":
        account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])
        guardduty.process_delete_event(params, regions, account_ids, True)
    else:
        common.create_service_linked_role(
            "AWSServiceRoleForAmazonGuardDuty",
            "guardduty.amazonaws.com",
            "A service-linked role required for Amazon GuardDuty to access your resources.",
        )
        guardduty.process_organization_admin_account(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), regions)
        sleep(60)
        session = common.assume_role(params.get("CONFIGURATION_ROLE_NAME", ""), "CreateGuardDuty", params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""))
        detectors_exist = False
        run_count = 0

        while not detectors_exist and run_count < MAX_RUN_COUNT:
            run_count += 1
            detectors_exist = guardduty.check_for_detectors(session, regions)
            LOGGER.info(f"All Detectors Exist?: {detectors_exist} Count: {run_count}")
            if not detectors_exist:
                sleep(SLEEP_SECONDS)

        if not detectors_exist:
            raise ValueError("GuardDuty Detectors did not get created in the allowed time. Check the Org Management delegated admin setup.")
        else:
            auto_enable_s3_logs = (params.get("AUTO_ENABLE_S3_LOGS", "false")).lower() in "true"

            guardduty.configure_guardduty(
                session,
                params["DELEGATED_ADMIN_ACCOUNT_ID"],
                auto_enable_s3_logs,
                regions,
                params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES"),
                params["KMS_KEY_ARN"],
                params["PUBLISHING_DESTINATION_BUCKET_ARN"],
            )


def process_sns_records(records: list) -> None:
    """Process SNS records.

    Args:
        records: list of SNS event records
    """
    for record in records:
        sns_info = record["Sns"]
        LOGGER.info(f"SNS INFO: {sns_info}")
        message = json.loads(sns_info["Message"])
        guardduty.cleanup_member_account(message["AccountId"], message["DeleteDetectorRoleName"], message["Regions"])


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
        guardduty.process_delete_event(params, regions, account_ids, False)

    return f"sra-guardduty-{params['DELEGATED_ADMIN_ACCOUNT_ID']}-{(params.get('AUTO_ENABLE_S3_LOGS', 'false')).lower() in 'true'}"


def lambda_handler(event: Dict[str, Any], context: Context) -> None:
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
        if "Records" not in event and "RequestType" not in event and ("source" not in event and event["source"] != "aws.controltower"):
            raise ValueError(
                f"The event did not include Records or RequestType. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
        elif "Records" in event and event["Records"][0]["EventSource"] == "aws:sns":
            process_sns_records(event["Records"])
        elif "RequestType" in event:
            helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
