# type: ignore
"""The purpose of this script is to configure the EC2 EBS default encryption within each account and region.

Version: 1.1

'ec2_default_ebs_encryption' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, List, Optional, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_ec2.client import EC2Client
    from mypy_boto3_ec2.type_defs import GetEbsEncryptionByDefaultResultTypeDef
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_organizations.type_defs import AccountTypeDef, DescribeAccountResponseTypeDef, TagTypeDef
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sns.type_defs import PublishBatchResponseTypeDef, PublishResponseTypeDef
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_sts import STSClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Global Variables
CLOUDFORMATION_PAGE_SIZE = 20
CLOUDFORMATION_THROTTLE_PERIOD = 0.2
ORGANIZATIONS_PAGE_SIZE = 20
ORGANIZATIONS_THROTTLE_PERIOD = 0.2
SNS_PUBLISH_BATCH_MAX = 10
UNEXPECTED = "Unexpected!"
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    CFN_CLIENT: CloudFormationClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation", config=BOTO3_CONFIG)
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
    SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns", config=BOTO3_CONFIG)
    SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
except Exception as error:
    LOGGER.error({"Unexpected_Error": error})
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


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
    # set regional endpoint environment variable to account for potential opt-in regions
    os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = "regional"

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


def get_control_tower_regions() -> list:  # noqa: CCR001
    """Query ssm to identify customer regions.

    Returns:
        Customer regions chosen in Control Tower
    """
    customer_regions = []
    ssm_response = SSM_CLIENT.get_parameter(Name="/sra/regions/customer-control-tower-regions")
    customer_regions = ssm_response["Parameter"]["Value"].split(",")
    return list(customer_regions)


def get_enabled_regions(customer_regions: str = None, control_tower_regions_only: bool = False) -> list:  # noqa: CCR001
    """Query STS to identify enabled regions.

    Args:
        customer_regions: customer provided comma delimited string of regions
        control_tower_regions_only: Use the Control Tower governed regions. Defaults to False.

    Returns:
        Enabled regions
    """
    if customer_regions and customer_regions.strip():
        LOGGER.debug(f"CUSTOMER PROVIDED REGIONS: {str(customer_regions)}")
        region_list = [value.strip() for value in customer_regions.split(",") if value != ""]
    elif control_tower_regions_only:
        region_list = get_control_tower_regions()
    else:
        default_available_regions = []
        for region in boto3.client("account").list_regions(RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"])["Regions"]:
            default_available_regions.append(region["RegionName"])
        LOGGER.info({"Default_Available_Regions": default_available_regions})
        region_list = default_available_regions

    enabled_regions = []
    disabled_regions = []
    invalid_regions = []
    region_session = boto3.Session()
    for region in region_list:
        try:
            sts_client = region_session.client("sts", endpoint_url=f"https://sts.{region}.amazonaws.com", region_name=region, config=BOTO3_CONFIG)
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidClientTokenId":
                disabled_regions.append(region)
            LOGGER.error(f"Error {error.response['Error']} occurred testing region {region}")
        except Exception as error:
            if "Could not connect to the endpoint URL" in str(error):
                invalid_regions.append(region)
                LOGGER.error(f"Region: '{region}' is not valid")
            LOGGER.error(f"{error}")
    LOGGER.info({"Disabled_Regions": disabled_regions})
    LOGGER.info({"Invalid_Regions": invalid_regions})
    return enabled_regions


def get_active_organization_accounts() -> list[AccountTypeDef]:
    """Get all the active AWS Organization accounts.

    Returns:
        List of active account IDs
    """
    paginator = ORG_CLIENT.get_paginator("list_accounts")
    accounts: list[AccountTypeDef] = []
    for page in paginator.paginate(PaginationConfig={"PageSize": ORGANIZATIONS_PAGE_SIZE}):
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE":
                accounts.append(account)
            sleep(ORGANIZATIONS_THROTTLE_PERIOD)
    return accounts


def get_account_info(account_id: str) -> AccountTypeDef:
    """Get AWS Account info.

    Args:
        account_id: ID of the AWS account

    Returns:
        Account info
    """
    response: DescribeAccountResponseTypeDef = ORG_CLIENT.describe_account(AccountId=account_id)
    api_call_details = {"API_Call": "organizations:DescribeAccounts", "API_Response": response}
    LOGGER.info(api_call_details)
    return response["Account"]


def get_organization_resource_tags(resource_id: str) -> List[TagTypeDef]:
    """Get Org Resource Tags.

    Args:
        resource_id: ID of the AWS account

    Returns:
        Account Tags
    """
    paginator = ORG_CLIENT.get_paginator("list_tags_for_resource")
    tags = []
    for page in paginator.paginate(ResourceId=resource_id):
        tags += page["Tags"]
        sleep(ORGANIZATIONS_THROTTLE_PERIOD)
    return tags


def process_enable_ebs_encryption_by_default(account_session: boto3.Session, account_id: str, regions: list) -> None:
    """Process enable ec2 default EBS encryption.

    Args:
        account_session: boto3 session
        account_id: account to assume role in
        regions: regions to process
    """
    for region in regions:
        ec2_client: EC2Client = account_session.client("ec2", region, config=BOTO3_CONFIG)

        response: GetEbsEncryptionByDefaultResultTypeDef = ec2_client.get_ebs_encryption_by_default()
        if not response["EbsEncryptionByDefault"]:
            ec2_client.enable_ebs_encryption_by_default()
            LOGGER.info(f"Default EBS encryption enabled in {account_id} | {region}")
        else:
            LOGGER.info(f"Default EBS encryption is already enabled in {account_id} | {region}")


def publish_sns_message(message: dict, subject: str, sns_topic_arn: str) -> None:
    """Publish SNS Message.

    Args:
        message: SNS Message
        subject: SNS Topic Subject
        sns_topic_arn: SNS Topic ARN
    """
    LOGGER.info(f"Publishing SNS message for {message['AccountId']}.")
    LOGGER.info({"SNSMessage": message})
    response: PublishResponseTypeDef = SNS_CLIENT.publish(Message=json.dumps(message), Subject=subject, TopicArn=sns_topic_arn)
    api_call_details = {"API_Call": "sns:Publish", "API_Response": response}
    LOGGER.info(api_call_details)


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


def is_account_with_exclude_tags(aws_account: AccountTypeDef, params: dict) -> bool:
    """Validate if account has tags to be excluded.

    Args:
        aws_account: AWS account to update
        params: solution parameters

    Returns:
        If account has exclude tags
    """
    if params["EXCLUDE_ACCOUNT_TAGS"]:
        account_tags = get_organization_resource_tags(aws_account["Id"])
        for tag in params["EXCLUDE_ACCOUNT_TAGS"]:
            if tag in account_tags:
                LOGGER.info(f"Excluding account: {aws_account['Id']} ({aws_account['Name']}) matching tags: {tag}.")
                return True
    return False


def local_testing(aws_account: AccountTypeDef, params: dict) -> None:
    """Local Testing.

    Args:
        aws_account: AWS account to update
        params: solution parameters
    """
    account_session = assume_role(params["CONFIGURATION_ROLE_NAME"], params["ROLE_SESSION_NAME"], aws_account["Id"])
    regions = get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"])
    process_enable_ebs_encryption_by_default(account_session, aws_account["Id"], regions)


def process_accounts(event: Union[CloudFormationCustomResourceEvent, dict], params: dict) -> None:
    """Process Accounts and Create SNS Messages for each account for solution deployment.

    Args:
        event: event data
        params: solution parameters
    """
    sns_messages = []
    accounts = get_active_organization_accounts()
    for account in accounts:
        if is_account_with_exclude_tags(account, params):
            continue

        if event.get("local_testing") == "true" or event.get("ResourceProperties", {}).get("local_testing") == "true":
            local_testing(account, params)
        else:
            sns_message = {"Action": params["action"], "AccountId": account["Id"]}
            sns_messages.append({"Id": account["Id"], "Message": json.dumps(sns_message), "Subject": "EC2 Default EBS Encryption"})

    process_sns_message_batches(sns_messages, params["SNS_TOPIC_ARN"])


def process_account(event: dict, aws_account_id: str, params: dict) -> None:
    """Process Account and Create SNS Message for solution deployment.

    Args:
        event: event data
        aws_account_id: AWS Account ID
        params: solution parameters
    """
    aws_account = get_account_info(account_id=aws_account_id)

    if is_account_with_exclude_tags(aws_account, params):
        return

    if event.get("local_testing") == "true":
        local_testing(aws_account, params)
    else:
        sns_message = {"Action": "Add", "AccountId": aws_account["Id"]}
        publish_sns_message(sns_message, "EC2 Default EBS Encryption", params["SNS_TOPIC_ARN"])


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({})

    process_accounts(event, params)


def process_event_sns(event: dict) -> None:
    """Process SNS event.

    Args:
        event: event data
    """
    params = get_validated_parameters({})

    regions = get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"])

    for record in event["Records"]:
        record["Sns"]["Message"] = json.loads(record["Sns"]["Message"])
        LOGGER.info({"SNS Record": record})
        message = record["Sns"]["Message"]
        params["action"] = message["Action"]

        aws_account = get_account_info(account_id=message["AccountId"])
        account_session = assume_role(params["CONFIGURATION_ROLE_NAME"], params["ROLE_SESSION_NAME"], aws_account["Id"])
        process_enable_ebs_encryption_by_default(account_session, aws_account["Id"], regions)


def process_event_organizations(event: dict) -> None:
    """Process Event from AWS Organizations.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({})

    if event["detail"]["eventName"] == "TagResource" and params["EXCLUDE_ACCOUNT_TAGS"]:
        aws_account_id = event["detail"]["requestParameters"]["resourceId"]
        process_account(event, aws_account_id, params)
    elif event["detail"]["eventName"] == "AcceptHandShake" and event["responseElements"]["handshake"]["state"] == "ACCEPTED":
        for party in event["responseElements"]["handshake"]["parties"]:
            if party["type"] == "ACCOUNT":
                aws_account_id = party["id"]
                process_account(event, aws_account_id, params)
                break
    elif event["detail"]["eventName"] == "CreateAccountResult":
        aws_account_id = event["detail"]["serviceEventDetails"]["createAccountStatus"]["accountId"]
        process_account(event, aws_account_id, params)
    else:
        LOGGER.info("Organization event does not match expected values.")


def process_event_lifecycle(event: dict) -> None:
    """Process Lifecycle Event from AWS Control Tower.

    Args:
        event: event data

    Raises:
        ValueError: Control Tower Lifecycle Event not 'createManagedAccountStatus' or 'updateManagedAccountStatus'
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({})

    aws_account_id = ""
    if event["detail"]["serviceEventDetails"].get("createManagedAccountStatus"):
        aws_account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]
    elif event["detail"]["serviceEventDetails"].get("updateManagedAccountStatus"):
        aws_account_id = event["detail"]["serviceEventDetails"]["updateManagedAccountStatus"]["account"]["accountId"]
    else:
        raise ValueError("Control Tower Lifecycle Event not 'createManagedAccountStatus' or 'updateManagedAccountStatus'")

    process_account(event, aws_account_id, params)


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

    if event["RequestType"] in ["Create", "Update"]:
        params = get_validated_parameters({"RequestType": event["RequestType"]})
        process_accounts(event, params)
    else:
        LOGGER.info("No changes were made to EC2 Default EBS Encryption Configuration.")

    return "EC2-DEFAULT-EBS-ENCRYPTION"


def parameter_tags_validator(parameter_name: str, parameter_value: Optional[str]) -> dict:  # noqa: CCR001
    """Validate Resource Tags in CloudFormation Custom Resource Properties and/or Lambda Function Environment Variables.

    Args:
        parameter_name: CloudFormation custom resource parameter name and/or Lambda function environment variable name
        parameter_value: CloudFormation custom resource parameter value and/or Lambda function environment variable value

    Raises:
        ValueError: Parameter not in JSON format
        ValueError: Parameter invalid Tag Keys and/or Tag Values

    Returns:
        Validated Tags Parameter in JSON format
    """
    tag_key_pattern = r"^(?![aA][wW][sS]:).{1,128}$"
    tag_value_pattern = r"^.{0,256}$"

    invalid_tag_keys = []
    invalid_tag_values = []
    format_message = f'"{parameter_name}" not in JSON format: [{{"Key": "string", "Value": "string"}}]'
    try:
        tags_json = json.loads(str(parameter_value))
    except Exception:
        raise ValueError(format_message) from None

    for tag in tags_json:
        if not tag.get("Key") or "Value" not in tag:
            raise ValueError(format_message)
        if not re.match(tag_key_pattern, tag["Key"]):
            invalid_tag_keys.append(tag["Key"])
        if not re.match(tag_value_pattern, tag["Value"]):
            invalid_tag_values.append(tag["Value"])

        if invalid_tag_keys or invalid_tag_values:
            message = f"In '{parameter_name}' parameter, Invalid Tag Keys: {invalid_tag_keys}, Invalid Tag Values: {invalid_tag_values} entered."
            raise ValueError(message)

    return {parameter_name: tags_json}


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
    elif pattern == "tags_json" and parameter_value:
        return parameter_tags_validator(parameter_name, parameter_value)
    elif pattern == "tags_json":
        return {parameter_name: parameter_value}
    elif not re.match(pattern, str(parameter_value)):
        raise ValueError(f"'{parameter_name}' parameter with value of '{parameter_value}'" + f" does not follow the allowed pattern: {pattern}.")
    return {parameter_name: parameter_value}


def get_validated_parameters(event: dict) -> dict:
    """Validate AWS CloudFormation parameters and/or Lambda Function Environment Variables.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params: dict = {}
    cfn_params = event.get("ResourceProperties", {}).copy()  # noqa: F841 # NOSONAR
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]

    sns_topic_pattern = r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"
    true_false_pattern = r"^true|false$"

    # Required Parameters
    params.update(parameter_pattern_validator("CONFIGURATION_ROLE_NAME", os.environ.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", os.environ.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("ROLE_SESSION_NAME", os.environ.get("ROLE_SESSION_NAME"), pattern=r"^[\w=,@.-]+$"))
    params.update(parameter_pattern_validator("SNS_TOPIC_ARN", os.environ.get("SNS_TOPIC_ARN"), pattern=sns_topic_pattern))

    # Optional Parameters
    params.update(parameter_pattern_validator("ENABLED_REGIONS", os.environ.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True))
    params.update(parameter_pattern_validator("EXCLUDE_ACCOUNT_TAGS", os.environ.get("EXCLUDE_ACCOUNT_TAGS"), pattern="tags_json", is_optional=True))

    # Convert true/false string parameters to boolean
    params.update({"CONTROL_TOWER_REGIONS_ONLY": (params["CONTROL_TOWER_REGIONS_ONLY"] == "true")})

    return params


def orchestrator(event: dict, context: Any) -> None:
    """Orchestration of Events.

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


def lambda_handler(event: dict, context: Any) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Lambda Handler Started....")
    try:
        event_info = {"Event": event}
        LOGGER.info(event_info)
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
