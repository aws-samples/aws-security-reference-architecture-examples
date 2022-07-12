"""Create or Update password policy on an account.

ResourceProperties:
    AllowUsersToChangePassword: [ True | False ]
    HardExpiry: [ True | False ]
    MaxPasswordAge: int (1 - 1095)
    PasswordReusePrevention: int (1 - 24)
    MinimumPasswordLength: int (6 - 128)
    RequireLowerCaseCharacters: [ True | False ]
    RequireNumbers: [ True | False ]
    RequireSymbols: [ True | False ]
    RequireUppercaseCharacters [ True | False ]

Version: 1.1

'iam_password_policy' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING, Optional

import boto3
from botocore.client import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_iam.client import IAMClient

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

UNEXPECTED = "Unexpected!"

boto3_config = Config(retries={"max_attempts": 4})

try:
    management_account_session = boto3.Session()
    IAM_CLIENT: IAMClient = management_account_session.client("iam", config=boto3_config)
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


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
    actions = {"Create": "Add", "Update": "Add", "Delete": "Remove"}
    params["action"] = actions[event["RequestType"]]

    parameter_pattern_validator("MAX_PASSWORD_AGE", params.get("MAX_PASSWORD_AGE", ""), pattern=r"^[0-9]$|^[0-9][0-9]$|^[0-9][0-2][0-8]$")
    parameter_pattern_validator(
        "MINIMUM_PASSWORD_LENGTH", params.get("MINIMUM_PASSWORD_LENGTH", ""), pattern=r"^[6-9]$|^[0-9][0-9]$|^[0-9][0-2][0-8]$"
    )
    parameter_pattern_validator("PASSWORD_REUSE_PREVENTION", params.get("PASSWORD_REUSE_PREVENTION", ""), pattern=r"^[1-9]$|^[2-9][0-4]$")
    parameter_pattern_validator("ALLOW_USERS_TO_CHANGE_PASSWORD", params.get("ALLOW_USERS_TO_CHANGE_PASSWORD", ""), pattern=r"^true|false$")
    parameter_pattern_validator("HARD_EXPIRY", params.get("HARD_EXPIRY", ""), pattern=r"^true|false$")
    parameter_pattern_validator("REQUIRE_LOWERCASE_CHARACTERS", params.get("REQUIRE_LOWERCASE_CHARACTERS"), pattern=r"^true|false$")
    parameter_pattern_validator("REQUIRE_NUMBERS", params.get("REQUIRE_NUMBERS", ""), pattern=r"^true|false$")
    parameter_pattern_validator("REQUIRE_SYMBOLS", params.get("REQUIRE_SYMBOLS", ""), pattern=r"^true|false$")
    parameter_pattern_validator("REQUIRE_UPPERCASE_CHARACTERS", params.get("REQUIRE_UPPERCASE_CHARACTERS", ""), pattern=r"^true|false$")

    return params


@helper.create
@helper.update
@helper.delete
def process_cloudformation_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:
    """Process CloudFormation Event. Creates and updates the password policy with the provided parameters.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    LOGGER.debug(f"{context}")

    params = get_validated_parameters(event)
    if params["action"] == "Add":
        IAM_CLIENT.update_account_password_policy(
            AllowUsersToChangePassword=(params.get("ALLOW_USERS_TO_CHANGE_PASSWORD", "false")).lower() in "true",
            HardExpiry=(params.get("HARD_EXPIRY", "false")).lower() in "true",
            MaxPasswordAge=int(params.get("MAX_PASSWORD_AGE", 90)),
            MinimumPasswordLength=int(params.get("MINIMUM_PASSWORD_LENGTH", 14)),
            PasswordReusePrevention=int(params.get("PASSWORD_REUSE_PREVENTION", 24)),
            RequireLowercaseCharacters=(params.get("REQUIRE_LOWERCASE_CHARACTERS", "true")).lower() in "true",
            RequireNumbers=(params.get("REQUIRE_NUMBERS", "true")).lower() in "true",
            RequireSymbols=(params.get("REQUIRE_SYMBOLS", "true")).lower() in "true",
            RequireUppercaseCharacters=(params.get("REQUIRE_UPPERCASE_CHARACTERS", "true")).lower() in "true",
        )

    return (
        f"sra-password-policy-{params['ALLOW_USERS_TO_CHANGE_PASSWORD']}-{params['HARD_EXPIRY']}-{params['MAX_PASSWORD_AGE']}-"
        + f"{params['MINIMUM_PASSWORD_LENGTH']}-{params['PASSWORD_REUSE_PREVENTION']}-{params['REQUIRE_LOWERCASE_CHARACTERS']}-"
        + f"{params['REQUIRE_NUMBERS']}-{params['REQUIRE_SYMBOLS']}-{params['REQUIRE_UPPERCASE_CHARACTERS']}"
    )


def lambda_handler(event: CloudFormationCustomResourceEvent, context: Context) -> None:
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
