"""The purpose of this script is to configure the S3 account public access block settings.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Union

import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

if TYPE_CHECKING:
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_s3control.client import S3ControlClient
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_sts.client import STSClient

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)

# Global Variables
MAX_THREADS = 10
ORG_DEFAULT_THROTTLE_PERIOD = 0.2
PAGE_SIZE = 20  # 20 is the max page size for list_accounts
SSM_PARAMETER_PREFIX = os.environ.get("SSM_PARAMETER_PREFIX", "/sra/s3-block-account-public-access")

# Initialise the helper
helper = CfnResource(json_logging=True, log_level="DEBUG", boto_level="CRITICAL")


def get_all_organization_accounts() -> list:
    """Get all the active AWS Organization accounts

    Returns:
        List of active account IDs
    """
    account_ids = []
    org_client: OrganizationsClient = boto3.client("organizations")
    paginator = org_client.get_paginator("list_accounts")

    for page in paginator.paginate(PaginationConfig={"PageSize": PAGE_SIZE}):
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                account_ids.append(acct["Id"])
        sleep(ORG_DEFAULT_THROTTLE_PERIOD)

    return account_ids


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


def put_account_public_access_block(
    s3_client: S3ControlClient,
    account_id: str,
    enable_block_public_acls: bool,
    enable_ignore_public_acls: bool,
    enable_block_public_policy: bool,
    enable_restrict_public_buckets: bool,
) -> None:
    """Put account public access block

    Args:
        s3_client:
        account_id: The account to set the public access block
        enable_block_public_acls: True or False
        enable_ignore_public_acls: True or False
        enable_block_public_policy: True or False
        enable_restrict_public_buckets: True or False

    Raises:
        ValueError: Error setting account public access block
    """
    try:
        s3_client.put_public_access_block(
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": enable_block_public_acls,
                "IgnorePublicAcls": enable_ignore_public_acls,
                "BlockPublicPolicy": enable_block_public_policy,
                "RestrictPublicBuckets": enable_restrict_public_buckets,
            },
            AccountId=account_id,
        )
    except Exception as error:
        LOGGER.error(f"{error}")
        raise ValueError(f"Error setting account public access block in {account_id}") from None


def settings_changed(
    s3_client: S3ControlClient,
    account_id: str,
    enable_block_public_acls: bool,
    enable_ignore_public_acls: bool,
    enable_block_public_policy: bool,
    enable_restrict_public_buckets: bool,
) -> bool:
    """Account public access block settings changed

    Args:
        s3_client:
        account_id: The account to set the public access block
        enable_block_public_acls: True or False
        enable_ignore_public_acls: True or False
        enable_block_public_policy: True or False
        enable_restrict_public_buckets: True or False

    Returns:
        True or False
    """
    response = s3_client.get_public_access_block(AccountId=account_id)

    if (
        response["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is enable_block_public_acls
        and response["PublicAccessBlockConfiguration"]["IgnorePublicAcls"] is enable_ignore_public_acls
        and response["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is enable_block_public_policy
        and response["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"] is enable_restrict_public_buckets
    ):
        return False
    return True


def get_ssm_parameter_value(ssm_client: SSMClient, name: str) -> str:
    """Get SSM Parameter Value

    Args:
        ssm_client: SSM Boto3 Client
        names: Parameter Name

    Returns:
        Value string
    """
    return ssm_client.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]


def put_ssm_parameter(ssm_client: SSMClient, name: str, description: str, value: str) -> None:
    """Put SSM Parameter

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
    """Delete SSM Parameter

    Args:
        ssm_client: SSM Boto3 Client
        name: Parameter Name
    """
    ssm_client.delete_parameter(Name=name)


def set_configuration_ssm_parameters(management_session: boto3.Session, params: dict) -> None:
    """Set Configuration SSM Parameters

    Args:
        management_session: Management account session
        params: Parameters
    """
    ssm_client: SSMClient = management_session.client("ssm")
    ssm_parameter_value = {
        "ENABLE_BLOCK_PUBLIC_ACLS": params["ENABLE_BLOCK_PUBLIC_ACLS"],
        "ENABLE_IGNORE_PUBLIC_ACLS": params["ENABLE_IGNORE_PUBLIC_ACLS"],
        "ENABLE_BLOCK_PUBLIC_POLICY": params["ENABLE_BLOCK_PUBLIC_POLICY"],
        "ENABLE_RESTRICT_PUBLIC_BUCKETS": params["ENABLE_RESTRICT_PUBLIC_BUCKETS"],
        "ROLE_SESSION_NAME": params["ROLE_SESSION_NAME"],
        "ROLE_TO_ASSUME": params["ROLE_TO_ASSUME"],
    }

    put_ssm_parameter(ssm_client, f"{SSM_PARAMETER_PREFIX}", "", json.dumps(ssm_parameter_value))


def get_configuration_ssm_parameters() -> dict:
    """Get Configuration SSM Parameters

    Returns:
        Parameter dictionary
    """

    ssm_client: SSMClient = boto3.session.Session().client("ssm")

    ssm_parameter = json.loads(get_ssm_parameter_value(ssm_client, f"{SSM_PARAMETER_PREFIX}"))
    params = {
        "ENABLE_BLOCK_PUBLIC_ACLS": ssm_parameter["ENABLE_BLOCK_PUBLIC_ACLS"],
        "ENABLE_IGNORE_PUBLIC_ACLS": ssm_parameter["ENABLE_IGNORE_PUBLIC_ACLS"],
        "ENABLE_BLOCK_PUBLIC_POLICY": ssm_parameter["ENABLE_BLOCK_PUBLIC_POLICY"],
        "ENABLE_RESTRICT_PUBLIC_BUCKETS": ssm_parameter["ENABLE_RESTRICT_PUBLIC_BUCKETS"],
        "ROLE_SESSION_NAME": ssm_parameter["ROLE_SESSION_NAME"],
        "ROLE_TO_ASSUME": ssm_parameter["ROLE_TO_ASSUME"],
    }
    return params


def parameter_pattern_validator(parameter_name: str, parameter_value: Union[str, None], pattern: str) -> None:
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


def get_validated_parameters(event: Dict[str, Any]) -> dict:  # noqa: CCR001 (cognitive complexity)
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = event["ResourceProperties"].copy()
    actions = {"Create": "Add", "Update": "Add", "Delete": "Remove"}
    params["action"] = actions[event["RequestType"]]

    parameter_pattern_validator("ENABLE_BLOCK_PUBLIC_ACLS", params.get("ENABLE_BLOCK_PUBLIC_ACLS"), pattern=r"(?i)^true|false$")
    parameter_pattern_validator("ENABLE_IGNORE_PUBLIC_ACLS", params.get("ENABLE_IGNORE_PUBLIC_ACLS"), pattern=r"(?i)^true|false$")
    parameter_pattern_validator("ENABLE_BLOCK_PUBLIC_POLICY", params.get("ENABLE_BLOCK_PUBLIC_POLICY"), pattern=r"(?i)^true|false$")
    parameter_pattern_validator("ENABLE_RESTRICT_PUBLIC_BUCKETS", params.get("ENABLE_RESTRICT_PUBLIC_BUCKETS"), pattern=r"(?i)^true|false$")
    parameter_pattern_validator("ROLE_SESSION_NAME", params.get("ROLE_SESSION_NAME"), pattern=r"^[\w=,@.-]+$")
    parameter_pattern_validator("ROLE_TO_ASSUME", params.get("ROLE_TO_ASSUME"), pattern=r"^[\w+=,.@-]{1,64}$")

    return params


def process_put_account_public_access_block(
    management_account_session: boto3.Session,
    params: dict,
    account_id: str,
    enable_block_public_acls: bool,
    enable_ignore_public_acls: bool,
    enable_block_public_policy: bool,
    enable_restrict_public_buckets: bool,
) -> None:
    """Process put account public access block

    Args:
        management_account_session:
        params: event parameters
        account_id: account to assume role in
        enable_block_public_acls: true or false
        enable_ignore_public_acls: true or false
        enable_block_public_policy: true or false
        enable_restrict_public_buckets: true or false
    """

    account_session = assume_role(params["ROLE_TO_ASSUME"], params["ROLE_SESSION_NAME"], account_id, management_account_session)
    s3_client: S3ControlClient = account_session.client("s3control")

    if settings_changed(
        s3_client, account_id, enable_block_public_acls, enable_ignore_public_acls, enable_block_public_policy, enable_restrict_public_buckets
    ):
        put_account_public_access_block(
            s3_client,
            account_id,
            enable_block_public_acls,
            enable_ignore_public_acls,
            enable_block_public_policy,
            enable_restrict_public_buckets,
        )
        LOGGER.info(f"Enabled account S3 Block Public Access in {account_id}")


@helper.create
@helper.update
@helper.delete
def process_cloudformation_event(event: Dict[str, Any], context: Any) -> str:
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    params = get_validated_parameters(event)

    management_account_session = boto3.session.Session()
    set_configuration_ssm_parameters(management_account_session, params)

    enable_block_public_acls = (params.get("ENABLE_BLOCK_PUBLIC_ACLS", "true")).lower() in "true"
    enable_ignore_public_acls = (params.get("ENABLE_IGNORE_PUBLIC_ACLS", "true")).lower() in "true"
    enable_block_public_policy = (params.get("ENABLE_BLOCK_PUBLIC_POLICY", "true")).lower() in "true"
    enable_restrict_public_buckets = (params.get("ENABLE_RESTRICT_PUBLIC_BUCKETS", "true")).lower() in "true"

    if params["action"] in ("Add"):
        account_ids = get_all_organization_accounts()

        thread_cnt = MAX_THREADS
        if MAX_THREADS > len(account_ids):
            thread_cnt = max(len(account_ids) - 2, 1)

        processes = []
        with ThreadPoolExecutor(max_workers=thread_cnt) as executor:
            for account_id in account_ids:
                processes.append(
                    executor.submit(
                        process_put_account_public_access_block,
                        management_account_session,
                        params,
                        account_id,
                        enable_block_public_acls,
                        enable_ignore_public_acls,
                        enable_block_public_policy,
                        enable_restrict_public_buckets,
                    )
                )
            for future in as_completed(processes, timeout=60):
                try:
                    future.result()
                except Exception as error:
                    LOGGER.error(f"{error}")
                    raise ValueError(f"There was an error updating the S3 account public access settings")
    else:
        ssm_client: SSMClient = management_account_session.client("ssm")
        delete_ssm_parameter(ssm_client, SSM_PARAMETER_PREFIX)

    return (
        f"S3PublicAccessBlock-{params['ENABLE_BLOCK_PUBLIC_ACLS']}"
        f"-{params['ENABLE_IGNORE_PUBLIC_ACLS']}"
        f"-{params['ENABLE_BLOCK_PUBLIC_POLICY']}"
        f"-{params['ENABLE_RESTRICT_PUBLIC_BUCKETS']}"
    )


def process_lifecycle_event(event: Dict[str, Any]) -> str:
    """Process Lifecycle Event

    Args:
        event: event data
    Returns:
        string with account ID
    """
    params = get_configuration_ssm_parameters()
    LOGGER.info(f"Parameters: {params}")

    enable_block_public_acls = (params.get("ENABLE_BLOCK_PUBLIC_ACLS", "true")).lower() in "true"
    enable_ignore_public_acls = (params.get("ENABLE_IGNORE_PUBLIC_ACLS", "true")).lower() in "true"
    enable_block_public_policy = (params.get("ENABLE_BLOCK_PUBLIC_POLICY", "true")).lower() in "true"
    enable_restrict_public_buckets = (params.get("ENABLE_RESTRICT_PUBLIC_BUCKETS", "true")).lower() in "true"

    account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]

    account_session = assume_role(params["ROLE_TO_ASSUME"], params["ROLE_SESSION_NAME"], account_id)
    s3_client: S3ControlClient = account_session.client("s3control")
    put_account_public_access_block(
        s3_client,
        account_id,
        enable_block_public_acls,
        enable_ignore_public_acls,
        enable_block_public_policy,
        enable_restrict_public_buckets,
    )

    return f"lifecycle-event-processed-for-{account_id}"


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
        if "RequestType" in event:
            helper(event, context)
        elif "source" in event and event["source"] == "aws.controltower":
            process_lifecycle_event(event)
        else:
            raise ValueError(
                f"The event did not include source = aws.controltower or RequestType. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
    except Exception as error:
        LOGGER.error(f"Unexpected Error: {error}")
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
