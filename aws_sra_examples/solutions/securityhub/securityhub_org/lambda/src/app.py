"""This script performs operations to enable, configure, and disable SecurityHub.

Version: 1.3

'securityhub_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Optional

import boto3
import common
import securityhub
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sns.type_defs import PublishBatchResponseTypeDef

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Global variables
UNEXPECTED = "Unexpected!"
SERVICE_NAME = "securityhub.amazonaws.com"
SLEEP_SECONDS = 60
PRE_DISABLE_SLEEP_SECONDS = 30
SNS_PUBLISH_BATCH_MAX = 10
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
    SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns", config=BOTO3_CONFIG)
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def get_standards_dictionary(params: dict) -> dict:
    """Get Standards Dictionary used to process standard configurations.

    Args:
        params: Configuration parameters

    Returns:
        Dictionary of standards data
    """
    return {
        "SecurityBestPracticesVersion": params["SECURITY_BEST_PRACTICES_VERSION"],
        "CISVersion": params["CIS_VERSION"],
        "PCIVersion": params["PCI_VERSION"],
        "NISTVersion": params["NIST_VERSION"],
        "StandardsToEnable": {
            "cis": params["ENABLE_CIS_STANDARD"] == "true",
            "pci": params["ENABLE_PCI_STANDARD"] == "true",
            "nist": params["ENABLE_NIST_STANDARD"] == "true",
            "sbp": params["ENABLE_SECURITY_BEST_PRACTICES_STANDARD"] == "true",
        },
    }


def create_sns_messages(accounts: list, regions: list, sns_topic_arn: str, action: str) -> None:
    """Create SNS Message.

    Args:
        accounts: Account List
        regions: AWS Region List
        sns_topic_arn: SNS Topic ARN
        action: Action
    """
    sns_messages = []
    for account in accounts:
        sns_message = {"AccountId": account["AccountId"], "Regions": regions, "Action": action}
        sns_messages.append({"Id": account["AccountId"], "Message": json.dumps(sns_message), "Subject": "Security Hub Configuration"})

    process_sns_message_batches(sns_messages, sns_topic_arn)


def publish_sns_message_batch(message_batch: list, sns_topic_arn: str) -> None:
    """Publish SNS Message Batches.

    Args:
        message_batch: Batch of SNS messages
        sns_topic_arn: SNS Topic ARN
    """
    LOGGER.info("Publishing SNS Message Batch")
    LOGGER.info({"SNSMessageBatch": message_batch})
    response: PublishBatchResponseTypeDef = SNS_CLIENT.publish_batch(TopicArn=sns_topic_arn, PublishBatchRequestEntries=message_batch)
    api_call_details = {"API_Call": "sns:PublishBatch", "API_Response": response}
    LOGGER.info(api_call_details)


def process_sns_message_batches(sns_messages: list, sns_topic_arn: str) -> None:
    """Process SNS Message Batches for Publishing.

    Args:
        sns_messages: SNS messages to be batched.
        sns_topic_arn: SNS Topic ARN
    """
    message_batches = []
    for i in range(SNS_PUBLISH_BATCH_MAX, len(sns_messages) + SNS_PUBLISH_BATCH_MAX, SNS_PUBLISH_BATCH_MAX):
        message_batches.append(sns_messages[i - SNS_PUBLISH_BATCH_MAX : i])

    for batch in message_batches:
        publish_sns_message_batch(batch, sns_topic_arn)


def process_event_sns(event: dict) -> None:
    """Process SNS event.

    Args:
        event: event data
    """
    params = get_validated_parameters({})

    for record in event["Records"]:
        record["Sns"]["Message"] = json.loads(record["Sns"]["Message"])
        LOGGER.info({"SNS Record": record})
        message = record["Sns"]["Message"]

        if message["Action"] == "configure":
            securityhub.enable_account_securityhub(
                message["AccountId"], message["Regions"], params["CONFIGURATION_ROLE_NAME"], params["AWS_PARTITION"], get_standards_dictionary(params)
            )
        elif message["Action"] == "disable":
            LOGGER.info("Disabling SecurityHub")
            securityhub.disable_securityhub(message["AccountId"], params["CONFIGURATION_ROLE_NAME"], message["Regions"])


def process_event_lifecycle(event: Dict[str, Any]) -> str:
    """Process Lifecycle Event.

    Args:
        event: event data

    Raises:
        ValueError: Control Tower Lifecycle Event not 'createManagedAccountStatus' or 'updateManagedAccountStatus'

    Returns:
        string with account ID
    """
    params = get_validated_parameters({})
    LOGGER.info({"Parameters": params})

    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
    aws_account_id = ""
    if event["detail"]["serviceEventDetails"].get("createManagedAccountStatus"):
        aws_account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]
    elif event["detail"]["serviceEventDetails"].get("updateManagedAccountStatus"):
        aws_account_id = event["detail"]["serviceEventDetails"]["updateManagedAccountStatus"]["account"]["accountId"]
    else:
        raise ValueError("Control Tower Lifecycle Event not 'createManagedAccountStatus' or 'updateManagedAccountStatus'")

    LOGGER.info(f"Configuring SecurityHub in {aws_account_id}")
    securityhub.configure_member_account(
        aws_account_id, params["CONFIGURATION_ROLE_NAME"], regions, get_standards_dictionary(params), params["AWS_PARTITION"]
    )

    return f"lifecycle-event-processed-for-{aws_account_id}"


def process_add_update_event(params: dict) -> str:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters

    Returns:
        Status
    """
    accounts = common.get_active_organization_accounts(params["DELEGATED_ADMIN_ACCOUNT_ID"])
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    if params["DISABLE_SECURITY_HUB"] == "true" and params["action"] == "Update":
        LOGGER.info("...Disable Security Hub")
        securityhub.disable_organization_admin_account(regions)
        securityhub.disable_securityhub(params["DELEGATED_ADMIN_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"], regions)

        LOGGER.info(f"Waiting {PRE_DISABLE_SLEEP_SECONDS} seconds before disabling member accounts.")
        sleep(PRE_DISABLE_SLEEP_SECONDS)
        create_sns_messages(accounts, regions, params["SNS_TOPIC_ARN"], "disable")
        return "DISABLE_COMPLETE"

    LOGGER.info("...Enable Security Hub")

    # Configure Security Hub in the Management Account first, or else the default standards are automatically enabled for member accounts
    securityhub.enable_account_securityhub(
        params["MANAGEMENT_ACCOUNT_ID"], regions, params["CONFIGURATION_ROLE_NAME"], params["AWS_PARTITION"], get_standards_dictionary(params)
    )
    LOGGER.info("Waiting 20 seconds before configuring the delegated admin account.")
    sleep(20)

    # Configure Security Hub Delegated Admin and Organizations
    securityhub.configure_delegated_admin_securityhub(
        accounts,
        regions,
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
        params["CONFIGURATION_ROLE_NAME"],
        params["REGION_LINKING_MODE"],
        params["HOME_REGION"],
        params["AWS_PARTITION"],
        get_standards_dictionary(params),
    )
    # Configure Security Hub in the Delegated Admin Account
    securityhub.enable_account_securityhub(
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
        regions,
        params["CONFIGURATION_ROLE_NAME"],
        params["AWS_PARTITION"],
        get_standards_dictionary(params),
    )

    if params["action"] == "Add":
        LOGGER.info(f"Waiting {SLEEP_SECONDS} seconds before configuring member accounts.")
        sleep(SLEEP_SECONDS)
    create_sns_messages(accounts, regions, params["SNS_TOPIC_ARN"], "configure")
    return "ADD_UPDATE_COMPLETE"


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({"RequestType": "Update"})
    process_add_update_event(params)


def parameter_pattern_validator(parameter_name: str, parameter_value: Optional[str], pattern: str, is_optional: bool = False) -> dict:
    """Validate CloudFormation Custom Resource Properties and/or Lambda Function Environment Variables.

    Args:
        parameter_name: CloudFormation custom resource parameter name and/or Lambda function environment variable name
        parameter_value: CloudFormation custom resource parameter value and/or Lambda function environment variable value
        pattern: REGEX pattern to validate against.
        is_optional: Allow empty or missing value when True

    Raises:
        ValueError: Parameter has a value of empty string.
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern

    Returns:
        Validated Parameter
    """
    if parameter_value == "" and not is_optional:
        raise ValueError(f"'{parameter_name}' parameter has a value of empty string.")
    elif not parameter_value and not is_optional:
        raise ValueError(f"'{parameter_name}' parameter is missing.")
    elif not re.match(pattern, str(parameter_value)):
        raise ValueError(f"'{parameter_name}' parameter with value of '{parameter_value}'" + f" does not follow the allowed pattern: {pattern}.")
    return {parameter_name: parameter_value}


def get_validated_parameters(event: Dict[str, Any]) -> dict:
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]

    true_false_pattern = r"^true|false$"
    version_pattern = r"^[0-9.]+$"
    sns_topic_pattern = r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"

    # Required Parameters
    params.update(parameter_pattern_validator("AWS_PARTITION", os.environ.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$"))
    params.update(parameter_pattern_validator("CIS_VERSION", os.environ.get("CIS_VERSION"), pattern=version_pattern))
    params.update(parameter_pattern_validator("CONFIGURATION_ROLE_NAME", os.environ.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", os.environ.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("DISABLE_SECURITY_HUB", os.environ.get("DISABLE_SECURITY_HUB"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("ENABLE_CIS_STANDARD", os.environ.get("ENABLE_CIS_STANDARD"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("ENABLE_PCI_STANDARD", os.environ.get("ENABLE_PCI_STANDARD"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("ENABLE_NIST_STANDARD", os.environ.get("ENABLE_NIST_STANDARD"), pattern=true_false_pattern))
    params.update(
        parameter_pattern_validator(
            "ENABLE_SECURITY_BEST_PRACTICES_STANDARD", os.environ.get("ENABLE_SECURITY_BEST_PRACTICES_STANDARD"), pattern=true_false_pattern
        )
    )
    params.update(
        parameter_pattern_validator("HOME_REGION", os.environ.get("HOME_REGION"), pattern=r"^(?!(.*--))(?!(.*-$))[a-z0-9]([a-z0-9-]){0,62}$")
    )
    params.update(parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", os.environ.get("MANAGEMENT_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("PCI_VERSION", os.environ.get("PCI_VERSION"), pattern=version_pattern))
    params.update(parameter_pattern_validator("NIST_VERSION", os.environ.get("NIST_VERSION"), pattern=version_pattern))
    params.update(
        parameter_pattern_validator("REGION_LINKING_MODE", os.environ.get("REGION_LINKING_MODE"), pattern=r"^ALL_REGIONS|SPECIFIED_REGIONS$")
    )
    params.update(parameter_pattern_validator("SNS_TOPIC_ARN", os.environ.get("SNS_TOPIC_ARN"), pattern=sns_topic_pattern))
    params.update(
        parameter_pattern_validator("SECURITY_BEST_PRACTICES_VERSION", os.environ.get("SECURITY_BEST_PRACTICES_VERSION"), pattern=version_pattern)
    )

    # Optional Parameters
    params.update(parameter_pattern_validator("ENABLED_REGIONS", os.environ.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True))

    return params


def deregister_delegated_administrator(delegated_admin_account_id: str, service_principal: str = SERVICE_NAME) -> None:
    """Deregister the delegated administrator account for the provided service principal within AWS Organizations.

    Args:
        delegated_admin_account_id: Delegated Admin Account
        service_principal: Service Principal
    """
    try:
        LOGGER.info(f"Deregistering the delegated admin {delegated_admin_account_id} for {service_principal}")

        ORG_CLIENT.deregister_delegated_administrator(AccountId=delegated_admin_account_id, ServicePrincipal=service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
        LOGGER.info(f"Account ({delegated_admin_account_id}) is not a registered delegated administrator: {error}")


def process_event_organizations(event: dict) -> None:
    """Process Event from AWS Organizations.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({})
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    if event["detail"]["eventName"] == "AcceptHandShake" and event["responseElements"]["handshake"]["state"] == "ACCEPTED":
        for party in event["responseElements"]["handshake"]["parties"]:
            if party["type"] == "ACCOUNT":
                aws_account_id = party["id"]
                securityhub.enable_account_securityhub(
                    aws_account_id, regions, params["CONFIGURATION_ROLE_NAME"], params["AWS_PARTITION"], get_standards_dictionary(params)
                )
                break
    elif event["detail"]["eventName"] == "CreateAccountResult":
        aws_account_id = event["detail"]["serviceEventDetails"]["createAccountStatus"]["accountId"]
        securityhub.enable_account_securityhub(
            aws_account_id, regions, params["CONFIGURATION_ROLE_NAME"], params["AWS_PARTITION"], get_standards_dictionary(params)
        )

    else:
        LOGGER.info("Organization event does not match expected values.")


@helper.create
@helper.update
@helper.delete
def process_event_cloudformation(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa U100
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)

    params = get_validated_parameters({"RequestType": event["RequestType"]})

    if params["action"] in ["Add", "Update"]:
        process_add_update_event(params)
    else:
        regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
        LOGGER.info("...Disable Security Hub")
        securityhub.disable_organization_admin_account(regions)
        securityhub.disable_securityhub(params["DELEGATED_ADMIN_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"], regions)
        deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

    return f"sra-securityhub-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        helper(event, context)
    elif event.get("source") == "aws.controltower":
        process_event_lifecycle(event)
    elif event.get("source") == "aws.organizations":
        process_event_organizations(event)
    elif event.get("Records") and event["Records"][0]["EventSource"] == "aws:sns":
        process_event_sns(event)
    else:
        process_event(event)


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
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
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
