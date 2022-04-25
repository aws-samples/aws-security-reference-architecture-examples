"""Custom Resource to update alternate contacts for the account.

Version: 1.0

'account_alternate_contacts' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, List, Literal, Optional, Union

import boto3
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_account import AccountClient
    from mypy_boto3_account.type_defs import DeleteAlternateContactRequestRequestTypeDef, PutAlternateContactRequestRequestTypeDef
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_organizations.type_defs import AccountTypeDef, DescribeAccountResponseTypeDef, TagTypeDef
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sns.type_defs import PublishBatchResponseTypeDef, PublishResponseTypeDef
    from mypy_boto3_sts import STSClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)

# Global Variables
UNEXPECTED = "Unexpected!"
ORGANIZATIONS_PAGE_SIZE = 20
ORGANIZATIONS_THROTTLE_PERIOD = 0.2
SNS_PUBLISH_BATCH_MAX = 10
# https://docs.aws.amazon.com/accounts/latest/reference/quotas.html
ACCOUNT_THROTTLE_PERIOD = 0.2

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns")
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
    if not session:
        session = boto3.Session()
    sts_client: STSClient = session.client("sts")
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


def add_alternate_contact(
    account_client: AccountClient,
    aws_account: AccountTypeDef,
    contact_type: Literal["BILLING", "OPERATIONS", "SECURITY"],
    email: str,
    name: str,
    phone: str,
    title: str,
) -> None:
    """Add the specified alternate contact for the AWS account.

    Args:
        account_client: Boto3 client for AWS Account service
        aws_account: AWS account to update
        contact_type: Alternate contact type you want to update
        email: Email address for alternate contact
        name: Name for the alternate contact
        phone: Phone number for the alternate contact
        title: Title for the alternate contact
    """
    contact_parameters: PutAlternateContactRequestRequestTypeDef = {
        "AlternateContactType": contact_type,
        "EmailAddress": email,
        "Name": name,
        "PhoneNumber": phone,
        "Title": title,
    }
    account_client.put_alternate_contact(**contact_parameters)
    LOGGER.info(f"Added {contact_type} Alternate Contact for account: {aws_account['Id']} ({aws_account['Name']})")
    sleep(ACCOUNT_THROTTLE_PERIOD)


def delete_alternate_contact(
    account_client: AccountClient, aws_account: AccountTypeDef, contact_type: Literal["BILLING", "OPERATIONS", "SECURITY"]
) -> None:
    """Delete the specified alternate contact for the AWS account.

    Args:
        account_client: Boto3 client for AWS Account service
        aws_account: AWS account to update
        contact_type: Alternate contact type you want to update
    """
    contact_parameters: DeleteAlternateContactRequestRequestTypeDef = {"AlternateContactType": contact_type}
    try:
        account_client.delete_alternate_contact(**contact_parameters)
        LOGGER.info(f"Deleted {contact_type} Alternate Contact for account: {aws_account['Id']} ({aws_account['Name']})")
    except account_client.exceptions.ResourceNotFoundException:
        LOGGER.info(f"No {contact_type} Alternate Contact to delete in account: {aws_account['Id']} ({aws_account['Name']})")
    sleep(ACCOUNT_THROTTLE_PERIOD)


def process_alternate_contacts(account_client: AccountClient, aws_account: AccountTypeDef, params: dict) -> None:
    """Update/Delete the alternate contacts with the pertinent fields.

    Args:
        account_client: Boto3 client for AWS Account service
        aws_account: AWS account to update
        params: solution parameters
    """
    if params["BILLING_CONTACT_ACTION"] == "delete":
        delete_alternate_contact(account_client, aws_account, "BILLING")
    elif params["BILLING_CONTACT_ACTION"] == "add":
        add_alternate_contact(
            account_client,
            aws_account,
            "BILLING",
            params["BILLING_EMAIL"],
            params["BILLING_NAME"],
            params["BILLING_PHONE"],
            params["BILLING_TITLE"],
        )
    else:
        LOGGER.info(f"Ignoring BILLING Alternate Contact for account: {aws_account['Id']} ({aws_account['Name']})")

    if params["OPERATIONS_CONTACT_ACTION"] == "delete":
        delete_alternate_contact(account_client, aws_account, "OPERATIONS")
    elif params["OPERATIONS_CONTACT_ACTION"] == "add":
        add_alternate_contact(
            account_client,
            aws_account,
            "OPERATIONS",
            params["OPERATIONS_EMAIL"],
            params["OPERATIONS_NAME"],
            params["OPERATIONS_PHONE"],
            params["OPERATIONS_TITLE"],
        )
    else:
        LOGGER.info(f"Ignoring OPERATIONS Alternate Contact for account: {aws_account['Id']} ({aws_account['Name']})")

    if params["SECURITY_CONTACT_ACTION"] == "delete":
        delete_alternate_contact(account_client, aws_account, "SECURITY")
    elif params["SECURITY_CONTACT_ACTION"] == "add":
        add_alternate_contact(
            account_client,
            aws_account,
            "SECURITY",
            params["SECURITY_EMAIL"],
            params["SECURITY_NAME"],
            params["SECURITY_PHONE"],
            params["SECURITY_TITLE"],
        )
    else:
        LOGGER.info(f"Ignoring SECURITY Alternate Contact for account: {aws_account['Id']} ({aws_account['Name']})")


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
    account_client: AccountClient = account_session.client("account")
    process_alternate_contacts(account_client, aws_account, params)


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

        if event.get("local_testing") == "true" or event.get("ResourceProperties", {}).get("local_testing") == "true":  # type: ignore
            local_testing(account, params)
        else:
            sns_message = {"Action": params["action"], "AccountId": account["Id"]}
            sns_messages.append({"Id": account["Id"], "Message": json.dumps(sns_message), "Subject": "Account Alternate Contacts"})

    process_sns_message_batches(sns_messages, params["SNS_TOPIC_ARN"])


def process_account(event: dict, aws_account_id: str, params: dict) -> None:
    """Process Account and Create SNS Message for account for solution deployment.

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
        publish_sns_message(sns_message, "Account Alternate Contacts", params["SNS_TOPIC_ARN"])


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

    for record in event["Records"]:
        record["Sns"]["Message"] = json.loads(record["Sns"]["Message"])
        LOGGER.info({"SNS Record": record})
        message = record["Sns"]["Message"]
        params["action"] = message["Action"]

        aws_account = get_account_info(account_id=message["AccountId"])
        account_session = assume_role(params["CONFIGURATION_ROLE_NAME"], params["ROLE_SESSION_NAME"], aws_account["Id"])
        account_client: AccountClient = account_session.client("account")
        process_alternate_contacts(account_client, aws_account, params)


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
        LOGGER.info("No changes are made to Alternate Contacts.")

    return "ACCOUNT-ALTERNATE-CONTACTS"


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
    params = {}
    cfn_params = event.get("ResourceProperties", {}).copy()  # noqa: F841 # NOSONAR
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]

    name_title_pattern = r"^(?![&<>\\%|]).*$"
    phone_pattern = r"^[\s0-9()+-]+$"
    email_pattern = r"^([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$"
    sns_topic_pattern = r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"
    action_pattern = r"^add|delete|ignore$"

    # Required Parameters
    params.update(parameter_pattern_validator("BILLING_CONTACT_ACTION", os.environ.get("BILLING_CONTACT_ACTION"), pattern=action_pattern))
    params.update(parameter_pattern_validator("CONFIGURATION_ROLE_NAME", os.environ.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("OPERATIONS_CONTACT_ACTION", os.environ.get("OPERATIONS_CONTACT_ACTION"), pattern=action_pattern))
    params.update(parameter_pattern_validator("ROLE_SESSION_NAME", os.environ.get("ROLE_SESSION_NAME"), pattern=r"^[\w=,@.-]+$"))
    params.update(parameter_pattern_validator("SECURITY_CONTACT_ACTION", os.environ.get("SECURITY_CONTACT_ACTION"), pattern=action_pattern))
    params.update(parameter_pattern_validator("SNS_TOPIC_ARN", os.environ.get("SNS_TOPIC_ARN"), pattern=sns_topic_pattern))

    # Optional Parameters
    params.update(parameter_pattern_validator("EXCLUDE_ACCOUNT_TAGS", os.environ.get("EXCLUDE_ACCOUNT_TAGS"), pattern="tags_json", is_optional=True))

    # Conditional Parameters
    if os.environ["BILLING_CONTACT_ACTION"] == "add":
        params.update(parameter_pattern_validator("BILLING_EMAIL", os.environ.get("BILLING_EMAIL"), pattern=email_pattern))
        params.update(parameter_pattern_validator("BILLING_NAME", os.environ.get("BILLING_NAME"), pattern=name_title_pattern))
        params.update(parameter_pattern_validator("BILLING_PHONE", os.environ.get("BILLING_PHONE"), pattern=phone_pattern))
        params.update(parameter_pattern_validator("BILLING_TITLE", os.environ.get("BILLING_TITLE"), pattern=name_title_pattern))
    if os.environ["OPERATIONS_CONTACT_ACTION"] == "add":
        params.update(parameter_pattern_validator("OPERATIONS_EMAIL", os.environ.get("OPERATIONS_EMAIL"), pattern=email_pattern))
        params.update(parameter_pattern_validator("OPERATIONS_NAME", os.environ.get("OPERATIONS_NAME"), pattern=name_title_pattern))
        params.update(parameter_pattern_validator("OPERATIONS_PHONE", os.environ.get("OPERATIONS_PHONE"), pattern=phone_pattern))
        params.update(parameter_pattern_validator("OPERATIONS_TITLE", os.environ.get("OPERATIONS_TITLE"), pattern=name_title_pattern))
    if os.environ["SECURITY_CONTACT_ACTION"] == "add":
        params.update(parameter_pattern_validator("SECURITY_EMAIL", os.environ.get("SECURITY_EMAIL"), pattern=email_pattern))
        params.update(parameter_pattern_validator("SECURITY_NAME", os.environ.get("SECURITY_NAME"), pattern=name_title_pattern))
        params.update(parameter_pattern_validator("SECURITY_PHONE", os.environ.get("SECURITY_PHONE"), pattern=phone_pattern))
        params.update(parameter_pattern_validator("SECURITY_TITLE", os.environ.get("SECURITY_TITLE"), pattern=name_title_pattern))

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
