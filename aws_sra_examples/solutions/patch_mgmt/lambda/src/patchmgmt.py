"""This script provides logic for managing Patching.

Version: 1.0

'patch_mgmt' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import logging
import os
from typing import TYPE_CHECKING

import boto3
import common
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

def delete_window_with_sratag(ssmclient: SSMClient , response: dict) -> bool:
    """Delete Maintenance Windows with tag 'createdBy' with a value of 'SRA_Patch_Management'

    Args:
        ssmclient (Client): Boto3 Client
        response (dict): Describe Maintenance Windows response
    
    Returns:
        Boolean of success or failure
    """
    for window in response["WindowIdentities"]:
        response2 = ssmclient.list_tags_for_resource(
                ResourceType="MaintenanceWindow",
                ResourceId=window["WindowId"])
        # For tag in tag list then check if the tag is 'createdBy' and if it is then delete the window
        for tag in response2["TagList"]:
            if tag["Key"] == "createdBy" and tag["Value"] == "SRA_Patch_Management":
                ssmclient.delete_maintenance_window(WindowId=window["WindowId"])
                LOGGER.info(f"Deleted Maintenance Window {window['Name']}")
                break
    return True

def cleanup_patchmgmt(params: dict, boto3_config: Config) -> bool:
    """Clean up patch management created resources.

    Args:
        params (dict): The parameters of our function
        boto3_config (Config): Boto3 Configuration

    Returns:
        Boolean of success or failure
    """
    account_ids = common.get_account_ids(
        [], params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )
    regions = common.get_enabled_regions(
        params.get("ENABLED_REGIONS", ""),
        (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true",
    )
    for region in regions:
        for account in account_ids:
            session = common.assume_role(
                params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
                "sra-patch-mgmt-cleanup",
                account,
            )
            LOGGER.info(f"Deleting Maintenance Windows in {region}")
            ssmclient = session.client("ssm", region_name=region, config=boto3_config)
            response = ssmclient.describe_maintenance_windows()
            delete_window_with_sratag(ssmclient,response)
            
            while "NextToken" in response:
                response = ssmclient.describe_maintenance_windows(
                    NextToken=response["NextToken"]
                )
                delete_window_with_sratag(ssmclient,response)

    return True
