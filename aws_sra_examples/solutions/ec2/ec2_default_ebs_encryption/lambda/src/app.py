"""The purpose of this script is to configure the EC2 EBS default encryption within each account and region.

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
from typing import TYPE_CHECKING, Any, Dict

import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_sts.client import STSClient

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)

# Global Variables
CLOUDFORMATION_PAGE_SIZE = 20
CLOUDFORMATION_THROTTLE_PERIOD = 0.2
MAX_THREADS = 20
ORG_PAGE_SIZE = 20  # Max page size for list_accounts
ORG_THROTTLE_PERIOD = 0.2
UNEXPECTED = "Unexpected!"
SSM_PARAMETER_PREFIX = os.environ.get("SSM_PARAMETER_PREFIX", "/sra/ec2-default-ebs-encryption")

# Initialise the helper
helper = CfnResource(json_logging=True, log_level="DEBUG", boto_level="CRITICAL")

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
    CFN_CLIENT: CloudFormationClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation")
except Exception as error:
    LOGGER.error({"Unexpected_Error": error})
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def get_all_organization_accounts() -> list:
    """Get all the active AWS Organization accounts.

    Returns:
        List of active account IDs
    """
    account_ids = []
    paginator = ORG_CLIENT.get_paginator("list_accounts")

    for page in paginator.paginate(PaginationConfig={"PageSize": ORG_PAGE_SIZE}):
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                account_ids.append(acct["Id"])
        sleep(ORG_THROTTLE_PERIOD)

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


def get_control_tower_regions() -> list:  # noqa: CCR001
    """Query 'AWSControlTowerBP-BASELINE-CLOUDWATCH' CloudFormation stack to identify customer regions.

    Returns:
        Customer regions chosen in Control Tower
    """
    paginator = CFN_CLIENT.get_paginator("list_stack_instances")
    customer_regions = set()
    aws_account = ""
    all_regions_identified = False
    for page in paginator.paginate(StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH", PaginationConfig={"PageSize": CLOUDFORMATION_PAGE_SIZE}):
        for instance in page["Summaries"]:
            if not aws_account:
                aws_account = instance["Account"]
                customer_regions.add(instance["Region"])
                continue
            if aws_account == instance["Account"]:
                customer_regions.add(instance["Region"])
                continue
            all_regions_identified = True
            break
        if all_regions_identified:
            break
        sleep(CLOUDFORMATION_THROTTLE_PERIOD)

    return list(customer_regions)


def get_enabled_regions(customer_regions: str, control_tower_regions_only: bool = False) -> list:  # noqa: CCR001
    """Query STS to identify enabled regions.

    Args:
        customer_regions: customer provided comma delimited string of regions
        control_tower_regions_only: Use the Control Tower governed regions. Defaults to False.

    Returns:
        Enabled regions
    """
    if customer_regions.strip():
        LOGGER.debug(f"CUSTOMER PROVIDED REGIONS: {str(customer_regions)}")
        region_list = [value.strip() for value in customer_regions.split(",") if value != ""]
    elif control_tower_regions_only:
        region_list = get_control_tower_regions()
    else:
        default_available_regions = [
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ca-central-1",
            "eu-central-1",
            "eu-north-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "sa-east-1",
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
        ]
        LOGGER.info({"Default_Available_Regions": default_available_regions})
        region_list = default_available_regions

    enabled_regions = []
    disabled_regions = []
    invalid_regions = []
    region_session = boto3.Session()
    for region in region_list:
        try:
            sts_client = region_session.client("sts", endpoint_url=f"https://sts.{region}.amazonaws.com", region_name=region)
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


def process_enable_ebs_encryption_by_default(
    management_account_session: boto3.Session, role_to_assume: str, role_session_name: str, account_id: str, available_regions: list
) -> None:
    """Process enable ec2 default EBS encryption.

    Args:
        management_account_session: boto3 session
        role_to_assume: IAM role to assume
        role_session_name: role session name
        account_id: account to assume role in
        available_regions: regions to process
    """
    account_session = assume_role(role_to_assume, role_session_name, account_id, management_account_session)

    for region in available_regions:
        ec2_client: EC2Client = account_session.client("ec2", region)

        response = ec2_client.get_ebs_encryption_by_default()
        if not response["EbsEncryptionByDefault"]:
            ec2_client.enable_ebs_encryption_by_default()
            LOGGER.info(f"Default EBS encryption enabled in {account_id} | {region}")
        else:
            LOGGER.info(f"Default EBS encryption is already enabled in {account_id} | {region}")


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


def set_configuration_ssm_parameters(params: dict) -> None:
    """Set Configuration SSM Parameters.

    Args:
        params: Parameters
    """
    ssm_parameter_value = {
        "CONTROL_TOWER_REGIONS_ONLY": params["CONTROL_TOWER_REGIONS_ONLY"],
        "ENABLED_REGIONS": params["ENABLED_REGIONS"],
        "ROLE_SESSION_NAME": params["ROLE_SESSION_NAME"],
        "ROLE_TO_ASSUME": params["ROLE_TO_ASSUME"],
    }

    put_ssm_parameter(SSM_CLIENT, f"{SSM_PARAMETER_PREFIX}", "", json.dumps(ssm_parameter_value))


def get_configuration_ssm_parameters() -> dict:
    """Get Configuration SSM Parameters.

    Returns:
        Parameter dictionary
    """
    ssm_parameter = json.loads(get_ssm_parameter_value(SSM_CLIENT, f"{SSM_PARAMETER_PREFIX}"))
    return {
        "CONTROL_TOWER_REGIONS_ONLY": ssm_parameter["CONTROL_TOWER_REGIONS_ONLY"],
        "ENABLED_REGIONS": ssm_parameter["ENABLED_REGIONS"],
        "ROLE_SESSION_NAME": ssm_parameter["ROLE_SESSION_NAME"],
        "ROLE_TO_ASSUME": ssm_parameter["ROLE_TO_ASSUME"],
    }


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

    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=r"(?i)^true|false$")
    parameter_pattern_validator("ENABLED_REGIONS", params.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$")
    parameter_pattern_validator("ROLE_SESSION_NAME", params.get("ROLE_SESSION_NAME"), pattern=r"^[\w=,@.-]+$")
    parameter_pattern_validator("ROLE_TO_ASSUME", params.get("ROLE_TO_ASSUME"), pattern=r"^[\w+=,.@-]{1,64}$")

    return params


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
    request_type = event["RequestType"]
    LOGGER.info(f"{request_type} Event")

    params = get_validated_parameters(event)
    set_configuration_ssm_parameters(params)
    control_tower_regions_only = (params.get("CONTROL_TOWER_REGIONS_ONLY", "true")).lower() in "true"

    if params["action"] in ("Add"):
        account_ids = get_all_organization_accounts()
        available_regions = get_enabled_regions(
            customer_regions=params.get("ENABLED_REGIONS", ""), control_tower_regions_only=control_tower_regions_only
        )
        if len(available_regions) > 0:
            thread_cnt = MAX_THREADS
            if MAX_THREADS > len(account_ids):
                thread_cnt = max(len(account_ids) - 2, 1)

            processes = []
            with ThreadPoolExecutor(max_workers=thread_cnt) as executor:
                for account_id in account_ids:
                    processes.append(
                        executor.submit(
                            process_enable_ebs_encryption_by_default,
                            MANAGEMENT_ACCOUNT_SESSION,
                            params["ROLE_TO_ASSUME"],
                            params["ROLE_SESSION_NAME"],
                            account_id,
                            available_regions,
                        )
                    )
                for future in as_completed(processes, timeout=60):
                    try:
                        future.result()
                    except Exception as error:
                        LOGGER.error(f"{error}")
                        raise ValueError(f"There was an error updating the EC2 default EBS encryption setting")
        else:
            LOGGER.info("No valid enabled regions provided.")
    else:
        delete_ssm_parameter(SSM_CLIENT, SSM_PARAMETER_PREFIX)

    return f"EC2DefaultEBSEncryption-{params['ROLE_TO_ASSUME']}-{params['ROLE_SESSION_NAME']}-{len(params.get('ENABLED_REGIONS','').strip())}"


def process_lifecycle_event(event: Dict[str, Any]) -> str:
    """Process Lifecycle Event.

    Args:
        event: event data

    Returns:
        string with account ID
    """
    params = get_configuration_ssm_parameters()
    LOGGER.info(f"Parameters: {params}")

    control_tower_regions_only = (params.get("CONTROL_TOWER_REGIONS_ONLY", "true")).lower() in "true"
    available_regions = get_enabled_regions(customer_regions=params.get("ENABLED_REGIONS", ""), control_tower_regions_only=control_tower_regions_only)
    account_id = event["detail"]["serviceEventDetails"]["createManagedAccountStatus"]["account"]["accountId"]

    process_enable_ebs_encryption_by_default(
        MANAGEMENT_ACCOUNT_SESSION, params["ROLE_TO_ASSUME"], params["ROLE_SESSION_NAME"], account_id, available_regions
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
        if "source" not in event and "RequestType" not in event:
            raise ValueError(
                f"The event did not include source = aws.controltower or RequestType. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
        elif "source" in event and event["source"] == "aws.controltower":
            process_lifecycle_event(event)
        elif "RequestType" in event:
            helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
