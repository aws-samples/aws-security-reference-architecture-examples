"""This script performs operations to enable, configure, and disable Config.

Version: 1.0

'config_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

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
import config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_config.type_defs import DeliveryChannelTypeDef
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_secretsmanager import SecretsManagerClient
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sns.type_defs import PublishBatchResponseTypeDef

LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

UNEXPECTED = "Unexpected!"
SERVICE_NAME = "config.amazonaws.com"
SLEEP_SECONDS = 60
SNS_PUBLISH_BATCH_MAX = 10

helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def process_add_update_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts
    """
    LOGGER.info("...process_add_update_event")

    if params["action"] in ["Add", "Update"]:
        accounts = common.get_active_organization_accounts()
        regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
        setup_config_global(params, regions, accounts)

    LOGGER.info("...ADD_UPDATE_NO_EVENT")


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({"RequestType": "Update"})

    accounts = common.get_active_organization_accounts()
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
    process_add_update_event(params, regions, accounts)


def process_account(aws_account_id: str, params: dict) -> None:
    """Process Account.

    Args:
        aws_account_id: AWS Account ID
        params: solution parameters
    """
    sleep(SLEEP_SECONDS)
    config.create_service_linked_role(aws_account_id, params["CONFIGURATION_ROLE_NAME"])
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
    resource_types = build_resource_types_param(params)

    for region in regions:
        role_arn = f"arn:{params['AWS_PARTITION']}:iam::{aws_account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
        config.set_config_in_org(
            aws_account_id,
            region,
            params["CONFIGURATION_ROLE_NAME"],
            params["RECORDER_NAME"],
            role_arn,
            resource_types,
            params["ALL_SUPPORTED"],
            params["INCLUDE_GLOBAL_RESOURCE_TYPES"],
        )
        delivery_channel = set_delivery_channel_params(params, region)
        config.set_delivery_channel(aws_account_id, region, params["CONFIGURATION_ROLE_NAME"], delivery_channel)


def process_event_organizations(event: dict) -> None:
    """Process Event from AWS Organizations.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({})

    if event["detail"]["eventName"] == "AcceptHandshake" and event["detail"]["responseElements"]["handshake"]["state"] == "ACCEPTED":
        for party in event["detail"]["responseElements"]["handshake"]["parties"]:
            if party["type"] == "ACCOUNT":
                aws_account_id = party["id"]
                process_account(aws_account_id, params)
                break
    elif event["detail"]["eventName"] == "CreateAccountResult":
        aws_account_id = event["detail"]["serviceEventDetails"]["createAccountStatus"]["accountId"]
        process_account(aws_account_id, params)
    else:
        LOGGER.info("Organization event does not match expected values.")


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
        raise ValueError(f"({parameter_name}) parameter has a value of empty string.")
    elif not parameter_value and not is_optional:
        raise ValueError(f"({parameter_name}) parameter is missing.")
    elif not re.match(pattern, str(parameter_value)):
        raise ValueError(f"({parameter_name}) parameter with value of ({parameter_value})" + f" does not follow the allowed pattern: {pattern}.")
    return {parameter_name: parameter_value}


def get_validated_parameters(event: dict) -> dict:  # noqa: CFQ001
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params: dict = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]
    true_false_pattern = r"^true|false$"
    sns_topic_pattern = r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"

    # Required Parameters
    params.update(
        parameter_pattern_validator(
            "AWS_PARTITION",
            os.environ.get("AWS_PARTITION"),
            pattern=r"^(aws[a-zA-Z-]*)?$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "CONFIGURATION_ROLE_NAME",
            os.environ.get("CONFIGURATION_ROLE_NAME"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "CONFIG_TOPIC_NAME",
            os.environ.get("CONFIG_TOPIC_NAME"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "DELIVERY_CHANNEL_NAME",
            os.environ.get("DELIVERY_CHANNEL_NAME"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "S3_BUCKET_NAME",
            os.environ.get("S3_BUCKET_NAME"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "DELIVERY_S3_KEY_PREFIX",
            os.environ.get("DELIVERY_S3_KEY_PREFIX"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "ALL_SUPPORTED",
            os.environ.get("ALL_SUPPORTED"),
            pattern=true_false_pattern,
        )
    )
    params.update(
        parameter_pattern_validator(
            "CONTROL_TOWER_REGIONS_ONLY",
            os.environ.get("CONTROL_TOWER_REGIONS_ONLY"),
            pattern=true_false_pattern,
        )
    )
    params.update(
        parameter_pattern_validator(
            "FREQUENCY", os.environ.get("FREQUENCY"), pattern=r"^(One_Hour|Three_Hours|Six_Hours|Twelve_Hours|TwentyFour_Hours){1}$"
        )
    )
    params.update(
        parameter_pattern_validator(
            "INCLUDE_GLOBAL_RESOURCE_TYPES",
            os.environ.get("INCLUDE_GLOBAL_RESOURCE_TYPES"),
            pattern=true_false_pattern,
        )
    )
    params.update(
        parameter_pattern_validator(
            "AUDIT_ACCOUNT",
            os.environ.get("AUDIT_ACCOUNT"),
            pattern=r"^\d{12}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "RECORDER_NAME",
            os.environ.get("RECORDER_NAME"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "KMS_KEY_SECRET_NAME",
            os.environ.get("KMS_KEY_SECRET_NAME"),
            pattern=r"^[\w+=,.@/_-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "HOME_REGION",
            os.environ.get("HOME_REGION"),
            pattern=r"^$|[a-z0-9-, ]+$",
        )
    )
    params.update(parameter_pattern_validator("SNS_TOPIC_ARN_FANOUT", os.environ.get("SNS_TOPIC_ARN_FANOUT"), pattern=sns_topic_pattern))

    # Optional Parameters
    params.update(
        parameter_pattern_validator(
            "ENABLED_REGIONS",
            os.environ.get("ENABLED_REGIONS"),
            pattern=r"^$|[a-z0-9-, ]+$",
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "RESOURCE_TYPES",
            os.environ.get("RESOURCE_TYPES"),
            pattern=r"^[\w+=,.:() @-]{1,3000}$",
            is_optional=True,
        )
    )

    # Convert true/false string parameters to boolean
    params.update({"ALL_SUPPORTED": (params["ALL_SUPPORTED"] == "true")})
    params.update({"INCLUDE_GLOBAL_RESOURCE_TYPES": (params["INCLUDE_GLOBAL_RESOURCE_TYPES"] == "true")})

    return params


def build_resource_types_param(params: dict) -> list:
    """Build list of resource types.

    Args:
        params: Configuration Parameters

    Returns:
        list of resource types
    """
    params = get_validated_parameters({"RequestType": "Update"})
    resource_types: list = []
    if params["RESOURCE_TYPES"]:
        resource_types_param = params["RESOURCE_TYPES"]
        resource_types = resource_types_param.split(",")
        return resource_types
    return resource_types


def get_kms_key(params: dict) -> str:
    """Get KMS key arn for Config delivery channel.

    Args:
        params: Configuration Parameters

    Returns:
        str: KMS key arn for Config delivery channel
    """
    LOGGER.info("Getting KMS key arn from Secrets Manager")
    account = params["AUDIT_ACCOUNT"]
    secret_name = params["KMS_KEY_SECRET_NAME"]
    region_name = params["HOME_REGION"]
    configuration_role_name = params["CONFIGURATION_ROLE_NAME"]
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-get-secret", account)
    client: SecretsManagerClient = account_session.client(service_name="secretsmanager", region_name=region_name)
    get_secret_value_response = client.get_secret_value(SecretId=secret_name, VersionStage="AWSCURRENT")
    secret = json.loads(get_secret_value_response["SecretString"])
    return secret["ConfigDeliveryKeyArn"]


def set_delivery_channel_params(params: dict, region: str) -> DeliveryChannelTypeDef:
    """Set parameters for Config delivery channel.

    Args:
        params: Configuration Parameters
        region: AWS Region

    Returns:
        DeliveryChannelTypeDef: Parameters for Config delivery channel
    """
    sns_topic_arn = f"arn:{params['AWS_PARTITION']}:sns:{region}:{params['AUDIT_ACCOUNT']}:{params['CONFIG_TOPIC_NAME']}"
    s3_kms_key_arn = get_kms_key(params)
    delivery_channel: DeliveryChannelTypeDef = {
        "name": params["DELIVERY_CHANNEL_NAME"],
        "s3BucketName": params["S3_BUCKET_NAME"],
        "s3KeyPrefix": params["DELIVERY_S3_KEY_PREFIX"],
        "s3KmsKeyArn": s3_kms_key_arn,
        "snsTopicARN": sns_topic_arn,
        "configSnapshotDeliveryProperties": {"deliveryFrequency": params["FREQUENCY"]},
    }

    return delivery_channel


def setup_config_global(params: dict, regions: list, accounts: list) -> None:
    """Enable the Config service and configure its global settings.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts
    """
    for account in accounts:
        config.create_service_linked_role(account["AccountId"], params["CONFIGURATION_ROLE_NAME"])

    create_sns_messages(accounts, regions, params["SNS_TOPIC_ARN_FANOUT"], "configure")


def create_sns_messages(accounts: list, regions: list, sns_topic_arn_fanout: str, action: str) -> None:
    """Create SNS Message.

    Args:
        accounts: Account List
        regions: list of AWS regions
        sns_topic_arn_fanout: SNS Topic ARN
        action: Action
    """
    sns_messages = []
    for region in regions:
        sns_message = {"Accounts": accounts, "Region": region, "Action": action}
        sns_messages.append(
            {
                "Id": region,
                "Message": json.dumps(sns_message),
                "Subject": "Config Configuration",
            }
        )

    process_sns_message_batches(sns_messages, sns_topic_arn_fanout)


def publish_sns_message_batch(message_batch: list, sns_topic_arn_fanout: str) -> None:
    """Publish SNS Message Batches.

    Args:
        message_batch: Batch of SNS messages
        sns_topic_arn_fanout: SNS Topic ARN
    """
    LOGGER.info("Publishing SNS Message Batch")
    LOGGER.info({"SNSMessageBatch": message_batch})
    response: PublishBatchResponseTypeDef = SNS_CLIENT.publish_batch(TopicArn=sns_topic_arn_fanout, PublishBatchRequestEntries=message_batch)
    api_call_details = {"API_Call": "sns:PublishBatch", "API_Response": response}
    LOGGER.info(api_call_details)


def process_sns_message_batches(sns_messages: list, sns_topic_arn_fanout: str) -> None:
    """Process SNS Message Batches for Publishing.

    Args:
        sns_messages: SNS messages to be batched.
        sns_topic_arn_fanout: SNS Topic ARN
    """
    message_batches = []
    for i in range(
        SNS_PUBLISH_BATCH_MAX,
        len(sns_messages) + SNS_PUBLISH_BATCH_MAX,
        SNS_PUBLISH_BATCH_MAX,
    ):
        message_batches.append(sns_messages[i - SNS_PUBLISH_BATCH_MAX : i])

    for batch in message_batches:
        publish_sns_message_batch(batch, sns_topic_arn_fanout)


def process_event_sns(event: dict) -> None:
    """Process SNS event to complete the setup process.

    Args:
        event: event data
    """
    params = get_validated_parameters({})
    for record in event["Records"]:
        record["Sns"]["Message"] = json.loads(record["Sns"]["Message"])
        LOGGER.info({"SNS Record": record})
        message = record["Sns"]["Message"]
        if message["Action"] == "configure":
            LOGGER.info("Continuing process to enable Config (sns event)")
            resource_types = build_resource_types_param(params)

            for account in message["Accounts"]:
                role_arn = (
                    f"arn:{params['AWS_PARTITION']}:iam::{account['AccountId']}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
                )
                config.set_config_in_org(
                    account["AccountId"],
                    message["Region"],
                    params["CONFIGURATION_ROLE_NAME"],
                    params["RECORDER_NAME"],
                    role_arn,
                    resource_types,
                    params["ALL_SUPPORTED"],
                    params["INCLUDE_GLOBAL_RESOURCE_TYPES"],
                )
            delivery_channel = set_delivery_channel_params(params, message["Region"])
            for account in message["Accounts"]:
                config.set_delivery_channel(account["AccountId"], message["Region"], params["CONFIGURATION_ROLE_NAME"], delivery_channel)

        LOGGER.info("...ADD_UPDATE_NO_EVENT")


@helper.create
@helper.update
@helper.delete
def process_event_cloudformation(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa: U100
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
    accounts = common.get_active_organization_accounts()
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
    configuration_role_name = params["CONFIGURATION_ROLE_NAME"]

    if params["action"] in ["Add", "Update"]:
        LOGGER.info("calling process_add_update_event")
        process_add_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable Config from (process_event_cloudformation)")
        for account in accounts:
            for region in regions:
                LOGGER.info(f"Stopping config recorder in {account} account in {region} region")
                config.stop_config_recorder(account["AccountId"], region, configuration_role_name)

    return "SRA-CONFIG-ORG"


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        LOGGER.info("...calling helper...")
        helper(event, context)
    elif event.get("Records") and event["Records"][0]["EventSource"] == "aws:sns":
        LOGGER.info("...aws:sns record...")
        process_event_sns(event)
    else:
        LOGGER.info("...else...just calling process_event...")
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
    boto3_version = boto3.__version__
    LOGGER.info(f"boto3 version: {boto3_version}")
    event_info = {"Event": event}
    LOGGER.info(event_info)
    try:
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None
