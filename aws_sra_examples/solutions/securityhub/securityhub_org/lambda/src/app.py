"""This script performs operations to enable, configure, and disable SecurityHub.

Version: 1.0

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
from typing import TYPE_CHECKING, Any, Dict

import boto3
import common
import securityhub
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_ssm.client import SSMClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

# Global variables
UNEXPECTED = "Unexpected!"
SERVICE_NAME = "securityhub.amazonaws.com"
SLEEP_SECONDS = 60
PRE_DISABLE_SLEEP_SECONDS = 30
SSM_PARAMETER_PREFIX = os.environ.get("SSM_PARAMETER_PREFIX", "/sra/securityhub-org")
PARAMETER_LIST = [
    "AWS_PARTITION",
    "CIS_VERSION",
    "CONFIGURATION_ROLE_NAME",
    "CONTROL_TOWER_REGIONS_ONLY",
    "DELEGATED_ADMIN_ACCOUNT_ID",
    "DISABLE_SECURITY_HUB",
    "ENABLED_REGIONS",
    "ENABLE_CIS_STANDARD",
    "ENABLE_PCI_STANDARD",
    "ENABLE_SECURITY_BEST_PRACTICES_STANDARD",
    "HOME_REGION",
    "PCI_VERSION",
    "REGION_LINKING_MODE",
    "SECURITY_BEST_PRACTICES_VERSION",
    "SNS_TOPIC_ARN",
]

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


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
        if "Records" not in event and "RequestType" not in event and ("source" not in event and event["source"] != "aws.controltower"):
            raise ValueError(
                f"The event did not include Records, RequestType, or source. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
        elif "Records" in event and event["Records"][0]["EventSource"] == "aws:sns":
            process_sns_records(event["Records"])
        elif "source" in event and event["source"] == "aws.controltower":
            process_lifecycle_event(event)
        elif "RequestType" in event:
            helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None


@helper.create
@helper.update
@helper.delete
def process_cloudformation_event(event: CloudFormationCustomResourceEvent, context: Any) -> str:
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
    set_configuration_ssm_parameter(params)

    if params["action"] in "Add, Update":
        process_add_update_event(params)
    else:
        regions = common.get_enabled_regions(params.get("ENABLED_REGIONS", ""), (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true")
        LOGGER.info("...Disable Security Hub")
        securityhub.disable_organization_admin_account(regions)
        securityhub.disable_securityhub(params["DELEGATED_ADMIN_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"], regions)

    return (
        f"sra-securityhub-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}-{params['DISABLE_SECURITY_HUB']}-{params['CIS_VERSION']}-"
        + f"{params['ENABLE_CIS_STANDARD']}-{params['ENABLE_PCI_STANDARD']}-{params['ENABLE_SECURITY_BEST_PRACTICES_STANDARD']}-"
        + f"{params['PCI_VERSION']}-{params['REGION_LINKING_MODE']}-{params['SECURITY_BEST_PRACTICES_VERSION']}"
    )


def process_add_update_event(params: dict) -> str:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters

    Returns:
        Status
    """
    accounts = common.get_all_organization_accounts(params["DELEGATED_ADMIN_ACCOUNT_ID"])
    regions = common.get_enabled_regions(params.get("ENABLED_REGIONS", ""), (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true")

    if (params.get("DISABLE_SECURITY_HUB", "false")).lower() in "true" and params["action"] == "Update":
        LOGGER.info("...Disable Security Hub")
        securityhub.disable_organization_admin_account(regions)
        securityhub.disable_securityhub(params["DELEGATED_ADMIN_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"], regions)

        account_ids = common.get_account_ids(accounts)
        LOGGER.info(f"Waiting {PRE_DISABLE_SLEEP_SECONDS} seconds before disabling member accounts.")
        sleep(PRE_DISABLE_SLEEP_SECONDS)
        create_sns_messages(account_ids, regions, params["CONFIGURATION_ROLE_NAME"], params["SNS_TOPIC_ARN"], "disable")
        return "DISABLE_COMPLETE"
    else:
        LOGGER.info("...Enable or Update Security Hub")
        common.create_service_linked_role(
            "AWSServiceRoleForSecurityHub",
            "securityhub.amazonaws.com",
            "A service-linked role required for AWS Security Hub to access your resources.",
        )
        securityhub.enable_securityhub(
            params["DELEGATED_ADMIN_ACCOUNT_ID"],
            params["CONFIGURATION_ROLE_NAME"],
            accounts,
            regions,
            get_standards_dictionary(params),
            params["AWS_PARTITION"],
            params["REGION_LINKING_MODE"],
            params["HOME_REGION"],
        )
        account_ids = common.get_account_ids(accounts)
        if params["action"] == "Add":
            LOGGER.info(f"Waiting {SLEEP_SECONDS} seconds before configuring member accounts.")
            sleep(SLEEP_SECONDS)
        create_sns_messages(account_ids, regions, params["CONFIGURATION_ROLE_NAME"], params["SNS_TOPIC_ARN"], "configure")
        return "ADD_UPDATE_COMPLETE"


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
        "StandardsToEnable": {
            "cis": (params.get("ENABLE_CIS_STANDARD", "false")).lower() in "true",
            "pci": (params.get("ENABLE_PCI_STANDARD", "false")).lower() in "true",
            "sbp": (params.get("ENABLE_SECURITY_BEST_PRACTICES_STANDARD", "false")).lower() in "true",
        },
    }


def create_sns_messages(account_ids: list, regions: list, configuration_role: str, sns_topic_arn: str, action: str) -> None:
    """Create SNS Message.

    Args:
        account_ids: Account ID List
        regions: AWS Region List
        configuration_role: Configuration Role Name
        sns_topic_arn: SNS Topic ARN
        action: Action
    """
    management_sns_client: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns")
    for account_id in account_ids:
        sns_message = {
            "AccountId": account_id,
            "Regions": regions,
            "ConfigurationRoleName": configuration_role,
            "Action": action,
        }
        LOGGER.info(f"Publishing SNS message for {action} in {account_id}.")
        LOGGER.info(f"{json.dumps(sns_message)}")
        management_sns_client.publish(TopicArn=sns_topic_arn, Message=json.dumps(sns_message))


def process_sns_records(records: list) -> None:
    """Process SNS records.

    Args:
        records: list of SNS event records
    """
    params = get_configuration_ssm_parameters()

    for record in records:
        sns_info = record["Sns"]
        LOGGER.info(f"SNS INFO: {sns_info}")
        message = json.loads(sns_info["Message"])

        if message["Action"] == "configure":
            LOGGER.info("Configuring SecurityHub")
            securityhub.configure_member_account(
                message["AccountId"], params["CONFIGURATION_ROLE_NAME"], message["Regions"], get_standards_dictionary(params), params["AWS_PARTITION"]
            )
        elif message["Action"] == "disable":
            LOGGER.info("Disabling SecurityHub")
            securityhub.disable_securityhub(message["AccountId"], params["CONFIGURATION_ROLE_NAME"], message["Regions"])


def process_lifecycle_event(event: Dict[str, Any]) -> str:
    """Process Lifecycle Event.

    Args:
        event: event data

    Returns:
        string with account ID
    """
    params = get_configuration_ssm_parameters()
    LOGGER.info(f"Parameters: {params}")

    regions = common.get_enabled_regions(params.get("ENABLED_REGIONS", ""), (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true")
    account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]

    LOGGER.info(f"Configuring SecurityHub in {account_id}")
    securityhub.configure_member_account(
        account_id, params["CONFIGURATION_ROLE_NAME"], regions, get_standards_dictionary(params), params["AWS_PARTITION"]
    )

    return f"lifecycle-event-processed-for-{account_id}"


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

    parameter_pattern_validator("AWS_PARTITION", params.get("AWS_PARTITION", ""), pattern=r"^(aws[a-zA-Z-]*)?$")
    parameter_pattern_validator("CONFIGURATION_ROLE_NAME", params.get("CONFIGURATION_ROLE_NAME", ""), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY", ""), pattern=r"^true|false$")
    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), pattern=r"^\d{12}$")
    parameter_pattern_validator("DISABLE_SECURITY_HUB", params.get("DISABLE_SECURITY_HUB", ""), pattern=r"^true|false$")
    parameter_pattern_validator("ENABLE_CIS_STANDARD", params.get("ENABLE_CIS_STANDARD", ""), pattern=r"^true|false$")
    parameter_pattern_validator("ENABLE_PCI_STANDARD", params.get("ENABLE_PCI_STANDARD", ""), pattern=r"^true|false$")
    parameter_pattern_validator(
        "ENABLE_SECURITY_BEST_PRACTICES_STANDARD", params.get("ENABLE_SECURITY_BEST_PRACTICES_STANDARD", ""), pattern=r"^true|false$"
    )
    parameter_pattern_validator("ENABLED_REGIONS", params.get("ENABLED_REGIONS", ""), pattern=r"^$|[a-z0-9-, ]+$")
    parameter_pattern_validator("HOME_REGION", params.get("HOME_REGION", ""), pattern=r"^(?!(.*--))(?!(.*-$))[a-z0-9]([a-z0-9-]){0,62}$")
    parameter_pattern_validator(
        "SNS_TOPIC_ARN",
        params.get("SNS_TOPIC_ARN", ""),
        pattern=r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$",
    )
    parameter_pattern_validator("CIS_VERSION", params.get("CIS_VERSION", ""), pattern=r"^[0-9.]+$")
    parameter_pattern_validator("PCI_VERSION", params.get("PCI_VERSION", ""), pattern=r"^[0-9.]+$")
    parameter_pattern_validator("REGION_LINKING_MODE", params.get("REGION_LINKING_MODE", ""), pattern=r"^ALL_REGIONS|SPECIFIED_REGIONS$")
    parameter_pattern_validator("SECURITY_BEST_PRACTICES_VERSION", params.get("SECURITY_BEST_PRACTICES_VERSION", ""), pattern=r"^[0-9.]+$")

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
        LOGGER.debug(f"Account is not a registered delegated administrator: {error}")


def get_ssm_parameter_value(ssm_client: SSMClient, name: str) -> str:
    """Get SSM Parameter Value.

    Args:
        ssm_client: SSM Boto3 Client
        name: Parameter Name

    Returns:
        Value string
    """
    return ssm_client.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]


def put_ssm_parameter(ssm_client: SSMClient, name: str, description: str, value: str) -> None:
    """Put SSM Parameter.

    Args:
        ssm_client: SSM Boto3 Client
        name: Parameter Name
        description: Parameter description
        value: Parameter value
    """
    ssm_client.put_parameter(
        Name=name,
        Description=description,
        Value=value,
        Type="SecureString",
        Overwrite=True,
        Tier="Standard",
        DataType="text",
    )


def delete_ssm_parameter(ssm_client: SSMClient, name: str) -> None:
    """Delete SSM Parameter.

    Args:
        ssm_client: SSM Boto3 Client
        name: Parameter Name
    """
    ssm_client.delete_parameter(Name=name)


def set_configuration_ssm_parameter(params: dict) -> None:
    """Set Configuration SSM Parameter.

    Args:
        params: Parameters
    """
    ssm_parameter_value = {}
    for parameter_key in PARAMETER_LIST:
        ssm_parameter_value[parameter_key] = params[parameter_key]

    put_ssm_parameter(SSM_CLIENT, f"{SSM_PARAMETER_PREFIX}", "", json.dumps(ssm_parameter_value))


def get_configuration_ssm_parameters() -> dict:
    """Get Configuration SSM Parameters.

    Returns:
        Parameter dictionary
    """
    ssm_parameter = json.loads(get_ssm_parameter_value(SSM_CLIENT, f"{SSM_PARAMETER_PREFIX}"))
    configuration_ssm_parameters = {}
    for parameter_key in PARAMETER_LIST:
        configuration_ssm_parameters[parameter_key] = ssm_parameter[parameter_key]

    return configuration_ssm_parameters
