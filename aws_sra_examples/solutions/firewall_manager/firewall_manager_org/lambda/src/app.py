"""Custom Resource to associate a Firewall manager administrator account.

Version: 1.1

'firewall_manager_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import TYPE_CHECKING, Optional

import boto3
import botocore
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_fms.client import FMSClient
    from mypy_boto3_sts.client import STSClient

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

# Initialise the helper
helper = CfnResource(json_logging=True, log_level="DEBUG", boto_level="CRITICAL")

# Global Variables
UNEXPECTED = "Unexpected!"
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
MAX_RETRIES = 12
SLEEP_TIME = 5

def assume_role(role: str, role_session_name: str, account: str = None, session: boto3.Session = None) -> boto3.Session:
    """Assumes the provided role in the given account and returns a session.

    Args:
        role: Role to assume in target account.
        role_session_name: Identifier for the assumed role session.
        account: AWS account number. Defaults to None.
        session: Boto3 session. Defaults to None.

    Returns:
        Session object for the specified AWS account
    """
    if not session:
        session = boto3.Session()
    sts_client: STSClient = session.client("sts", config=BOTO3_CONFIG)
    sts_arn = sts_client.get_caller_identity()["Arn"]
    LOGGER.info(f"USER: {sts_arn}")
    if not account:
        account = sts_arn.split(":")[4]
    partition = sts_arn.split(":")[1]
    role_arn = f"arn:{partition}:iam::{account}:role/{role}"

    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)
    LOGGER.info(f"ASSUMED ROLE: {response['AssumedRoleUser']['Arn']}")
    return boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )


def associate_admin_account(delegated_admin_account_id: str) -> None:
    """Associate an administrator account for Firewall Manager.

    Args:
        delegated_admin_account_id: _description_

    Raises:
        ValueError: Admin account already exists.
    """
    LOGGER.info(f"Admin account: {delegated_admin_account_id}")
    firewall_manager_client: FMSClient = boto3.client("fms", region_name="us-east-1", config=BOTO3_CONFIG)  # APIs only work in us-east-1 region

    try:
        LOGGER.info("Making sure there is no existing admin account")
        admin_account = firewall_manager_client.get_admin_account()
        if "AdminAccount" in admin_account:
            LOGGER.error("Admin account already exists. Disassociate the account first")
            raise ValueError("Admin account already exists. Disassociate the account first")
    except firewall_manager_client.exceptions.ResourceNotFoundException:
        LOGGER.info("Administrator account does not exist. Continuing...")

    LOGGER.info("Attempting to associate the admin account in Firewall Manager")
    try:
        firewall_manager_client.associate_admin_account(AdminAccount=delegated_admin_account_id)
    except botocore.exceptions.ClientError as error:
        LOGGER.info(f"Error associating admin account: {error.response['Error']['Message']}")
        if error.response["Error"]["Code"] == "InvalidOperationException":
            LOGGER.info(f"Invalid operation exception occurred; waiting {SLEEP_TIME} seconds before trying again...")
            i_retry = 0
            while i_retry <= MAX_RETRIES:
                time.sleep(SLEEP_TIME)
                try:
                    firewall_manager_client.associate_admin_account(AdminAccount=delegated_admin_account_id)
                    associated = True
                except botocore.exceptions.ClientError as error:
                    LOGGER.info(f"Attempt {i_retry} - error associating admin account: {error.response['Error']['Message']}")
                    associated = False
                if associated is True:
                    break
                else:
                    i_retry += 1
            if associated is False:
                LOGGER.error("Unable to associate admin account.")
                raise ValueError("Unable to associate admin account.")
        else:
            LOGGER.error("Unexpected error. Unable to associate admin account due to error unrelated to an invalid operation.")
            raise ValueError("Unexpected error. Unable to associate admin account due to error unrelated to an invalid operation.")
    LOGGER.info("...Waiting 5 minutes for admin account association.")
    time.sleep(300)  # use 5 minute wait
    while True:
        LOGGER.info("Getting admin account status in Firewall Manager")
        admin_account_status = firewall_manager_client.get_admin_account()
        if admin_account_status["RoleStatus"] == "READY":
            LOGGER.info("Admin account status = READY")
            break
        else:
            LOGGER.info(f"Admin account status = {admin_account_status['RoleStatus']}")
        LOGGER.info("...Waiting 20 seconds before next admin account status check.")
        time.sleep(20)


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

    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$")
    parameter_pattern_validator("ROLE_SESSION_NAME", params.get("ROLE_SESSION_NAME"), pattern=r"^[\w=,@.-]+$")
    parameter_pattern_validator("ROLE_TO_ASSUME", params.get("ROLE_TO_ASSUME"), pattern=r"^[\w+=,.@-]{1,64}$")

    return params


@helper.create
@helper.update
@helper.delete
def process_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa U100
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id

    Raises:
        botocore.exceptions.ClientError: Client error
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters(event)

    if params["action"] == "Add":
        associate_admin_account(params["DELEGATED_ADMIN_ACCOUNT_ID"])
    elif params["action"] == "Update":
        management_fms_client: FMSClient = boto3.client("fms", region_name="us-east-1", config=BOTO3_CONFIG)  # APIs only work in us-east-1 region
        admin_account = management_fms_client.get_admin_account()

        if "AdminAccount" in admin_account:
            delegated_admin_session: boto3.Session = assume_role(params["ROLE_TO_ASSUME"], params["ROLE_SESSION_NAME"], admin_account["AdminAccount"])
            update_fms_client: FMSClient = delegated_admin_session.client("fms", region_name="us-east-1", config=BOTO3_CONFIG)
            update_fms_client.disassociate_admin_account()
            LOGGER.info("...Waiting 10 minutes before associating new account.")
            time.sleep(600)

        associate_admin_account(params["DELEGATED_ADMIN_ACCOUNT_ID"])
    elif params["action"] == "Remove":
        delegated_admin_session = assume_role(params["ROLE_TO_ASSUME"], params["ROLE_SESSION_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"])
        remove_fms_client: FMSClient = delegated_admin_session.client(
            "fms", region_name="us-east-1", config=BOTO3_CONFIG
        )  # APIs only work in us-east-1 region
        try:
            remove_fms_client.disassociate_admin_account()
        except botocore.exceptions.ClientError as error:
            if "is not currently delegated by AWS FM" not in str(error):
                raise
            else:
                LOGGER.info(f"The account: {params['DELEGATED_ADMIN_ACCOUNT_ID']} is not currently delegated by AWS FMS.")

    return f"FMSDelegateAdmin-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def lambda_handler(event: CloudFormationCustomResourceEvent, context: Context) -> None:  # noqa U100
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
