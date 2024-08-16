"""This script provides logic for removing Maintenance Windows with tag 'createdBy' with a value of 'SRA_Patch_Management.

Version: 1.0

'patch_mgmt' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

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
    from mypy_boto3_ssm.client import SSMClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)
boto3_config = Config(retries={"max_attempts": 10, "mode": "standard"})

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
except Exception:
    LOGGER.exception("UNEXPECTED")
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def delete_window_with_sratag(ssmclient: SSMClient, response: dict) -> bool:
    """Delete Maintenance Windows with tag 'createdBy' with a value of 'SRA_Patch_Management.

    Args:
        ssmclient (SSMClient): Boto3 Client
        response (dict): Describe Maintenance Windows response

    Returns:
        Boolean of success or failure
    """
    for window in response["WindowIdentities"]:
        response2 = ssmclient.list_tags_for_resource(ResourceType="MaintenanceWindow", ResourceId=window["WindowId"])
        # For tag in tag list then check if the tag is 'createdBy' and if it is then delete the window
        for tag in response2["TagList"]:
            if tag["Key"] == "createdBy" and tag["Value"] == "SRA_Patch_Management":
                ssmclient.delete_maintenance_window(WindowId=window["WindowId"])
                LOGGER.info(f"Deleted Maintenance Window {window['Name']} with ID {window['WindowId']}")
                break
    return True


def delete_default_host_mgmt(ssmclient: SSMClient) -> None:
    """Delete Default Host Management Configuration.

    Args:
        ssmclient (SSMClient): boto3 client
    """
    setting_id = "/ssm/managed-instance/default-ec2-instance-management-role"
    try:
        ssmclient.reset_service_setting(SettingId=setting_id)
    except ClientError as e:
        LOGGER.error(e)


def disable_patchmgmt(params: dict, boto3_config: Config) -> bool:
    """Clean up patch management created resources.

    Args:
        params (dict): The parameters of our function
        boto3_config (Config): Boto3 Configuration

    Returns:
        Boolean of success or failure
    """
    account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])
    regions = common.get_enabled_regions(
        params.get("ENABLED_REGIONS", ""),
        (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true",
    )
    for region in regions:
        for account in account_ids:
            session = common.assume_role(
                params["ROLE_NAME_TO_ASSUME"],
                "sra-disable-patch-mgmt",
                account,
            )
            LOGGER.info(f"Deleting Maintenance Windows in {account} in {region}")
            ssmclient = session.client("ssm", region_name=region, config=boto3_config)
            response = ssmclient.describe_maintenance_windows()
            delete_window_with_sratag(ssmclient, response)

            while "NextToken" in response:
                response = ssmclient.describe_maintenance_windows(NextToken=response["NextToken"])
                delete_window_with_sratag(ssmclient, response)
            LOGGER.info(f"Deleting Default Host Management Configuration in {account} in {region}")
            delete_default_host_mgmt(ssmclient)

    return True


def cleanup_patchmgmt(params: dict, boto3_config: Config) -> bool:
    """Clean up patch management created resources.

    Args:
        params (dict): The parameters of our function
        boto3_config (Config): Boto3 Configuration

    Returns:
        Boolean of success or failure
    """
    account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])
    regions = common.get_enabled_regions(
        params.get("ENABLED_REGIONS", ""),
        (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true",
    )
    for region in regions:
        for account in account_ids:
            session = common.assume_role(
                params["ROLE_NAME_TO_ASSUME"],
                "sra-patch-mgmt-cleanup",
                account,
            )
            LOGGER.info(f"Deleting Maintenance Windows in {account} in {region}")
            ssmclient = session.client("ssm", region_name=region, config=boto3_config)
            response = ssmclient.describe_maintenance_windows()
            delete_window_with_sratag(ssmclient, response)

            while "NextToken" in response:
                response = ssmclient.describe_maintenance_windows(NextToken=response["NextToken"])
                delete_window_with_sratag(ssmclient, response)

    return True
