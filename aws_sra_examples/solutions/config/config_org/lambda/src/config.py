"""This script performs operations to enable, configure, and disable config.

Version: 1.0
'config-org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import boto3
import common
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_config.client import ConfigServiceClient
    from mypy_boto3_config.type_defs import ConfigurationRecorderTypeDef, DeliveryChannelTypeDef
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm.client import SSMClient

# Logging Settings
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Global Variables
MAX_THREADS = 20
ORG_PAGE_SIZE = 20  # Max page size for list_accounts
ORG_THROTTLE_PERIOD = 0.2
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
    CFN_CLIENT: CloudFormationClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation", config=BOTO3_CONFIG)
    SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
except Exception as error:
    LOGGER.error({"Unexpected_Error": error})
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def create_service_linked_role(account_id: str, configuration_role_name: str) -> None:
    """Create service linked role in the given account.

    Args:
        account_id (str): Account ID
        configuration_role_name (str): IAM configuration role name
    """
    LOGGER.info(f"creating service linked role for account {account_id}")
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-configure-config", account_id)
    iam_client: IAMClient = account_session.client("iam")
    common.create_service_linked_role(
        "AWSServiceRoleForConfig",
        "config.amazonaws.com",
        "A service-linked role required for AWS Config",
        iam_client,
    )


def set_config_in_org(
    account_id: str,
    region: str,
    configuration_role_name: str,
    recorder_name: str,
    role_arn: str,
    resource_types: list,
    all_supported: bool,
    include_global_resource_types: bool,
) -> None:
    """Create Config recorder.

    Args:
        account_id: Account id
        region: AWS Region
        configuration_role_name:  IAM configuration role name
        recorder_name: Name for Config recorder
        role_arn: Role arn to configure Config recorder
        resource_types: Resource types
        all_supported: All supported
        include_global_resource_types: Include global resource types
    """
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-configure-config", account_id)
    LOGGER.info(f"Checking config for {account_id} in {region}")  # update
    config_client: ConfigServiceClient = account_session.client("config", region_name=region)
    configuration_recorder: ConfigurationRecorderTypeDef = {
        "name": recorder_name,
        "roleARN": role_arn,
        "recordingGroup": {
            "allSupported": all_supported,
            "includeGlobalResourceTypes": include_global_resource_types,
            "resourceTypes": resource_types,
        },
    }
    if len(config_client.describe_configuration_recorders()["ConfigurationRecorders"]):
        response = config_client.describe_configuration_recorders()["ConfigurationRecorders"]
        if response.pop(0) == configuration_recorder:
            LOGGER.info(f"Config recorder is up to update in {account_id} in {region} region. Configurations: {configuration_recorder}")
        else:
            LOGGER.info(f"Updating config recorder in {account_id} account in {region} region")
            config_client.put_configuration_recorder(ConfigurationRecorder=configuration_recorder)
            LOGGER.info(f"Config recorder updated for {account_id} account in {region} region. Configurations: {configuration_recorder}")

    if not len(config_client.describe_configuration_recorders()["ConfigurationRecorders"]):
        LOGGER.info(f"Creating config recorder in {account_id} account in {region} region")
        config_client.put_configuration_recorder(ConfigurationRecorder=configuration_recorder)
        LOGGER.info(f"Config recorder started for {account_id} account in {region} region. Configurations: {configuration_recorder}")

    if config_client.describe_configuration_recorder_status()["ConfigurationRecordersStatus"][0]["recording"]:
        LOGGER.info(f"Config recorder is already started in {region}")
        LOGGER.info(config_client.describe_configuration_recorder_status())


def set_delivery_channel(
    account_id: str,
    region: str,
    configuration_role_name: str,
    delivery_channel: DeliveryChannelTypeDef,
) -> None:
    """Configure Delivery Channel.

    Args:
        account_id: Account ID
        region: AWS Region
        configuration_role_name: IAM configuration role name
        delivery_channel: Configuration parameters for Config delivery channel
    """
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-configure-config", account_id)
    config_client: ConfigServiceClient = account_session.client("config", region_name=region)
    try:
        LOGGER.info(f"Setting up config delivery channel for account {account_id} in {region} region")
        config_client.put_delivery_channel(DeliveryChannel=delivery_channel)
        config_client.start_configuration_recorder(
            ConfigurationRecorderName=config_client.describe_configuration_recorder_status()["ConfigurationRecordersStatus"][0]["name"]
        )
        LOGGER.info(f"Config delivery channel set for account {account_id} in {region} region. Configurations: {delivery_channel}")
    except ClientError as e:
        LOGGER.info(f"Error {repr(e)} enabling Config on account {account_id}")


def stop_config_recorder(account_id: str, region: str, configuration_role_name: str) -> None:
    """.

    Args:
        account_id (str): _description_
        region (str): _description_
        configuration_role_name (str): _description_
    """
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-delete-config", account_id)
    config_client: ConfigServiceClient = account_session.client("config", region_name=region)
    if len(config_client.describe_configuration_recorders()["ConfigurationRecorders"]):
        try:
            LOGGER.info(f"Stopping Config recorder for {account_id} account in {region} region")
            config_client.delete_configuration_recorder(
                ConfigurationRecorderName=config_client.describe_configuration_recorder_status()["ConfigurationRecordersStatus"][0]["name"]
            )
        except ClientError as e:
            LOGGER.info(f"Error {repr(e)} deleting Config on account {account_id}")
    if len(config_client.describe_delivery_channels()["DeliveryChannels"]):
        try:
            config_client.delete_delivery_channel(DeliveryChannelName=config_client.describe_delivery_channels()["DeliveryChannels"][0]["name"])
        except ClientError as e:
            LOGGER.info(f"Error {repr(e)} deleting Config delivery channel on account {account_id}")
