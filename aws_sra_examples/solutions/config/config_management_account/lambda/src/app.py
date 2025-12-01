"""Custom Resource to Update Config Aggregator Accounts in the Control Tower audit account.

Version: 1.0

'config_management_account' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import copy
import logging
import os
import re
from typing import TYPE_CHECKING, Any, List, Optional

import boto3
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_config.client import ConfigServiceClient
    from mypy_boto3_config.type_defs import AccountAggregationSourceTypeDef
    from mypy_boto3_sts.client import STSClient


# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

# Initialize the helper
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)


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


def get_existing_account_aggregation_sources(config_client: ConfigServiceClient, aggregator: str) -> List[AccountAggregationSourceTypeDef]:
    """Get existing list of source accounts/regions being aggregated.

    Args:
        config_client: Boto3 client config
        aggregator: Name of the configuration aggregator

    Returns:
        Existing list of source accounts/regions being aggregated
    """
    response: Any = config_client.describe_configuration_aggregators(ConfigurationAggregatorNames=[aggregator])
    api_call_details = {"API_Call": "config:DescribeConfigurationAggregators", "API_Response": response}
    LOGGER.info(api_call_details)
    return response["ConfigurationAggregators"][0]["AccountAggregationSources"]


def get_updated_account_aggregation_sources(aggregation_sources: list, account: str, action: str) -> List[Any]:
    """Get updated list of source accounts/regions to be aggregated.

    Args:
        aggregation_sources: List of existing source accounts/regions being aggregated
        account: AWS account to create/delete in AWS Config aggregator
        action: Indicates whether to 'Add' or 'Remove' account from being aggregated

    Returns:
        Updated list of source accounts/regions to be aggregated
    """
    updated_aggregation_sources = copy.deepcopy(aggregation_sources)
    account_ids: list = list(updated_aggregation_sources[0]["AccountIds"])
    if action == "Add":
        account_ids.append(account)
    elif action == "Remove" and account in account_ids:
        account_ids.remove(account)
    updated_aggregation_sources[0]["AccountIds"] = list(set(account_ids))

    return updated_aggregation_sources


def update_aggregator(config_client: ConfigServiceClient, aggregator: str, aggregation_sources: List[Any]) -> None:
    """Update source accounts/regions to be aggregated to AWS Config aggregator.

    Args:
        config_client: Boto3 client for AWS Config
        aggregator: Name of the AWS Config aggregator
        aggregation_sources: Updated list of source accounts/regions to be aggregated to AWS Config aggregator
    """
    response = config_client.put_configuration_aggregator(ConfigurationAggregatorName=aggregator, AccountAggregationSources=aggregation_sources)
    api_call_details = {"API_Call": "config:PutConfigurationAggregator", "API_Response": response}
    LOGGER.info(api_call_details)


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

    parameter_pattern_validator("AGGREGATOR_NAME", params.get("AGGREGATOR_NAME"), pattern=r"^aws-controltower-GuardrailsComplianceAggregator$")
    parameter_pattern_validator("AUDIT_ACCOUNT_ID", params.get("AUDIT_ACCOUNT_ID"), pattern=r"^\d{12}$")
    parameter_pattern_validator("ROLE_SESSION_NAME", params.get("ROLE_SESSION_NAME"), pattern=r"^[\w=,@.-]+$")
    parameter_pattern_validator("ROLE_TO_ASSUME", params.get("ROLE_TO_ASSUME"), pattern=r"^[\w+=,.@-]{1,64}$")

    return params


@helper.create
@helper.update
@helper.delete
def process_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    params = get_validated_parameters(event)

    management_account: str = context.invoked_function_arn.split(":")[4]
    audit_account_session = assume_role(params["ROLE_TO_ASSUME"], params["ROLE_SESSION_NAME"], params["AUDIT_ACCOUNT_ID"])
    config_client: ConfigServiceClient = audit_account_session.client("config", config=BOTO3_CONFIG)

    existing_aggregation_sources = get_existing_account_aggregation_sources(config_client, params["AGGREGATOR_NAME"])
    updated_aggregation_sources = get_updated_account_aggregation_sources(existing_aggregation_sources, management_account, params["action"])
    if existing_aggregation_sources == updated_aggregation_sources:
        LOGGER.info(f"{params['action']} {management_account} account in Aggregator was not necessary, as it was already in that state.")
    else:
        update_aggregator(config_client, params["AGGREGATOR_NAME"], updated_aggregation_sources)
        LOGGER.info(f"{params['action']} {management_account} account in Aggregator '{params['AGGREGATOR_NAME']}' was successful.")
    return f"{params['AUDIT_ACCOUNT_ID']}-{params['AGGREGATOR_NAME']}"


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
        LOGGER.exception("Unexpected!")
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
