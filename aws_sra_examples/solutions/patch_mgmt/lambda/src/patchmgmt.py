"""This script provides logic for managing Patching.

Version: 1.0

'patch_mgmt' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import common
from botocore.config import Config
import logging
import os

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)


def cleanup_patchmgmt(params: dict, BOTO3_CONFIG: Config) -> None:
    """Clean up patch management created resources

    Args:
        params (dict): The parameters of our function
        BOTO3_CONFIG (Config): Boto3 Configuration

    Returns:
        None
    """
    window_information = common.get_window_information()
    # use boto3 and assume the role to delete all the tasks inside of maintenance windows, then delete the targets, then delete the windows
    for window_task in window_information["window_tasks"]:
        session = common.assume_role(
            params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
            "sra-patch-mgmt-cleanup",
            window_task["account_id"],
        )
        LOGGER.info(f"Deleting Maintenance Window Tasks in {window_task['region']}")
        LOGGER.info(window_task)
        ssmclient = session.client("ssm", region_name=window_task["region"], config=BOTO3_CONFIG)
        response = ssmclient.deregister_task_from_maintenance_window(WindowId=window_task["windowId"], WindowTaskId=window_task["windowTaskId"])
        LOGGER.info(response)
    for window_target in window_information["window_targets"]:
        session = common.assume_role(
            params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
            "sra-patch-mgmt-cleanup",
            window_target["account_id"],
        )
        LOGGER.info(f"Deleting Maintenance Window Targets in {window_target['region']}")
        LOGGER.info(window_target)
        ssmclient = session.client("ssm", region_name=window_target["region"], config=BOTO3_CONFIG)
        response = ssmclient.deregister_target_from_maintenance_window(
            WindowId=window_target["windowId"],
            WindowTargetId=window_target["WindowTargetId"],
        )
    for previous_window_id in window_information["window_ids"]["windowIds"]:
        session = common.assume_role(
            params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
            "sra-patch-mgmt-cleanup",
            previous_window_id["account_id"],
        )
        LOGGER.info(f"Deleting Maintenance Windows in {previous_window_id['region']}")
        LOGGER.info(previous_window_id)
        ssmclient = session.client("ssm", region_name=previous_window_id["region"], config=BOTO3_CONFIG)
        response = ssmclient.delete_maintenance_window(WindowId=previous_window_id["windowId"])
