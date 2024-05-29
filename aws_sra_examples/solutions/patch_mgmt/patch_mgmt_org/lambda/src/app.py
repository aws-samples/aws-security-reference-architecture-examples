"""This script performs operations to enable, configure, and disable AWS Systems Manager Patch Manager.

Version: 1.0
'patchmgr_org' solution in the repo,
https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING, Any, Dict, TypedDict

import boto3
import common
import patchmgmt
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

# Initialize the helper. `sleep_on_delete` allows time for the CloudWatch Logs to get captured.
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

# Global variables
UNEXPECTED = "Unexpected!"
boto3_config = Config(retries={"max_attempts": 10, "mode": "standard"})


def get_account_id() -> str:
    """Get the Account ID.

    Returns:
        str: Account ID
    """
    client = boto3.client("sts")
    return client.get_caller_identity()["Account"]


class MaintInfo(TypedDict):
    """Class for Maintenance Info Typing.

    Args:
        TypedDict (_type_): Return Object
    """

    window1_ids: list
    window2_ids: list
    window3_ids: list


def create_maintenance_window(params: dict, account_id: str, regions: list) -> dict:
    """Create a maintenance window.

    Args:
        params (dict): Parameters
        account_id (str): Account ID
        regions (list): Regions to do this in

    Returns:
        dict: Maintenance Info Created
    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-mwindows",
        account_id,
    )
    window1_ids = []
    window2_ids = []
    window3_ids = []
    for region in regions:
        LOGGER.info(f"Setting up Default Host Management and Creating a Maint Window {account_id} {region}")
        ssmclient = session.client("ssm", region_name=region, config=boto3_config)
        ssmclient.update_service_setting(
            SettingId="/ssm/managed-instance/default-ec2-instance-management-role",
            SettingValue="service-role/AWSSystemsManagerDefaultEC2InstanceManagementRole",
        )
        # Window 1
        maintenance_window_name = params.get("MAINTENANCE_WINDOW1_NAME", "")
        maintenance_window_description = params.get("MAINTENANCE_WINDOW1_DESCRIPTION", "")
        maintenance_window_schedule = params.get("MAINTENANCE_WINDOW1_SCHEDULE", "")
        maintenance_window_duration = int(params.get("MAINTENANCE_WINDOW1_DURATION", 120))
        maintenance_window_cutoff = int(params.get("MAINTENANCE_WINDOW1_CUTOFF", 0))
        maintenance_window_timezone = params.get("MAINTENANCE_WINDOW1_TIMEZONE", "")

        maintenance_window = ssmclient.create_maintenance_window(
            Name=maintenance_window_name,
            Description=maintenance_window_description,
            Schedule=maintenance_window_schedule,
            Duration=maintenance_window_duration,
            Cutoff=maintenance_window_cutoff,
            ScheduleTimezone=maintenance_window_timezone,
            AllowUnassociatedTargets=False,
            Tags=[{"Key": "createdBy", "Value": "SRA_Patch_Management"}],
        )
        window1_ids.append({"region": region, "window1Id": maintenance_window["WindowId"], "account_id": account_id})
        # Window 2
        maintenance_window_name = params.get("MAINTENANCE_WINDOW2_NAME", "")
        maintenance_window_description = params.get("MAINTENANCE_WINDOW2_DESCRIPTION", "")
        maintenance_window_schedule = params.get("MAINTENANCE_WINDOW2_SCHEDULE", "")
        maintenance_window_duration = int(params.get("MAINTENANCE_WINDOW2_DURATION", 120))
        maintenance_window_cutoff = int(params.get("MAINTENANCE_WINDOW2_CUTOFF", 0))
        maintenance_window_timezone = params.get("MAINTENANCE_WINDOW2_TIMEZONE", "")

        maintenance_window = ssmclient.create_maintenance_window(
            Name=maintenance_window_name,
            Description=maintenance_window_description,
            Schedule=maintenance_window_schedule,
            Duration=maintenance_window_duration,
            Cutoff=maintenance_window_cutoff,
            ScheduleTimezone=maintenance_window_timezone,
            AllowUnassociatedTargets=False,
            Tags=[{"Key": "createdBy", "Value": "SRA_Patch_Management"}],
        )
        window2_ids.append({"region": region, "window2Id": maintenance_window["WindowId"], "account_id": account_id})
        # Window 3
        maintenance_window_name = params.get("MAINTENANCE_WINDOW3_NAME", "")
        maintenance_window_description = params.get("MAINTENANCE_WINDOW3_DESCRIPTION", "")
        maintenance_window_schedule = params.get("MAINTENANCE_WINDOW3_SCHEDULE", "")
        maintenance_window_duration = int(params.get("MAINTENANCE_WINDOW3_DURATION", 120))
        maintenance_window_cutoff = int(params.get("MAINTENANCE_WINDOW3_CUTOFF", 0))
        maintenance_window_timezone = params.get("MAINTENANCE_WINDOW3_TIMEZONE", "")

        maintenance_window = ssmclient.create_maintenance_window(
            Name=maintenance_window_name,
            Description=maintenance_window_description,
            Schedule=maintenance_window_schedule,
            Duration=maintenance_window_duration,
            Cutoff=maintenance_window_cutoff,
            ScheduleTimezone=maintenance_window_timezone,
            AllowUnassociatedTargets=False,
            Tags=[{"Key": "createdBy", "Value": "SRA_Patch_Management"}],
        )
        window3_ids.append({"region": region, "window3Id": maintenance_window["WindowId"], "account_id": account_id})

    return {"window1_ids": window1_ids, "window2_ids": window2_ids, "window3_ids": window3_ids}


def define_maintenance_window_targets(params: dict, window1_id_response: list, window2_id_response: list, window3_id_response: list, account_id: str) -> dict:
    """Define Maintenance Window Targets.

    Args:
        params (dict): Cloudformation Params
        window1_id_response (dict): Previous Window 1 IDs for the Targets
        window2_id_response (dict): Previous Window 2 IDs for the Targets
        window3_id_response (dict): Previous Window 3 IDs for the Targets
        account_id (str): Account ID for the targets to live in

    Returns:
        list[dict[str, Any]]: _description_
    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-wtarget",
        account_id,
    )
    window1_targets = []
    window2_targets = []
    window3_targets = []
    for response in window1_id_response:
        LOGGER.info(f"Maintenance Window Targets {response['region']}")
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)

        # Window 1
        target_name = params.get("TARGET1_NAME", "")
        target_description = params.get("TARGET1_DESCRIPTION", "")
        target_key_value_1 = params.get("TARGET1_VALUE_1", "")
        target_key_value_2 = params.get("TARGET1_VALUE_2", "")
        print("About to create window " + str(target_name))
        maintenance_window_targets = ssmclient.register_target_with_maintenance_window(
            Name=target_name,
            Description=target_description,
            WindowId=response["window1Id"],
            ResourceType="INSTANCE",
            Targets=[
                {
                    "Key": "tag:InstanceOS",
                    "Values": [
                        target_key_value_1,
                        target_key_value_2,
                    ],
                },
            ],
        )
        window1_targets.append(
            {
                "region": response["region"],
                "Window1TargetId": maintenance_window_targets["WindowTargetId"],
                "window1Id": response["window1Id"],
                "account_id": account_id,
            }
        )
    for response in window2_id_response:
        LOGGER.info(f"Maintenance Window Targets {response['region']}")
        # Window 2
        target_name = params.get("TARGET2_NAME", "")
        target_description = params.get("TARGET2_DESCRIPTION", "")
        target_key_value_1 = params.get("TARGET2_VALUE_1", "")

        maintenance_window_targets = ssmclient.register_target_with_maintenance_window(
            Name=target_name,
            Description=target_description,
            WindowId=response["window2Id"],
            ResourceType="INSTANCE",
            Targets=[
                {
                    "Key": "tag:InstanceOS",
                    "Values": [target_key_value_1],
                },
            ],
        )
        window2_targets.append(
            {
                "region": response["region"],
                "Window2TargetId": maintenance_window_targets["WindowTargetId"],
                "window2Id": response["window2Id"],
                "account_id": account_id,
            }
        )
    for response in window3_id_response:
        # Window 3
        target_name = params.get("TARGET3_NAME", "")
        target_description = params.get("TARGET3_DESCRIPTION", "")
        target_key_value_1 = params.get("TARGET3_VALUE_1", "")

        maintenance_window_targets = ssmclient.register_target_with_maintenance_window(
            Name=target_name,
            Description=target_description,
            WindowId=response["window3Id"],
            ResourceType="INSTANCE",
            Targets=[
                {
                    "Key": "tag:InstanceOS",
                    "Values": [target_key_value_1],
                },
            ],
        )
        window3_targets.append(
            {
                "region": response["region"],
                "Window3TargetId": maintenance_window_targets["WindowTargetId"],
                "window3Id": response["window3Id"],
                "account_id": account_id,
            }
        )
    return {"window1_targets": window1_targets, "window2_targets": window2_targets, "window3_targets": window3_targets}


def define_maintenance_window_tasks(
    params: dict,
    window_id_response: dict,
    window_target_response: dict,
    account_id: str,
) -> dict:
    """Define maintenance window targets.

    Args:
        params (dict): Parameters CFN
        window_id_response (dict): The Window IDs we made
        window_target_response (dict): The window Targets we made
        account_id (str): The Account #

    Returns:
        dict: Window Tasks Created Information
    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-wtasks",
        account_id,
    )
    window1_ids = []
    window2_ids = []
    window3_ids = []
    for response in window_id_response['window1_ids']:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        LOGGER.info(response)
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
        # Window 1
        task_name = params.get("TASK1_NAME", "")
        task_description = params.get("TASK1_DESCRIPTION", "")
        task_run_command = params.get("TASK1_RUN_COMMAND", "")
        task_operation = params.get("TASK1_OPERATION", "Scan")
        task_rebootoption = params.get("TASK1_REBOOTOPTION", "NoReboot")


        for response2 in window_target_response['window1_targets']:
            LOGGER.info(response2)
            if (
                response2["region"] == response["region"]
            ):  # must match the region up manually so we know the target that got made in that region and match it with the window
                maintenance_window_tasks = ssmclient.register_task_with_maintenance_window(
                    Name=task_name,
                    Description=task_description,
                    WindowId=response["window1Id"],
                    Targets=[
                        {
                            "Key": "WindowTargetIds",
                            "Values": [response2["Window1TargetId"]],
                        },
                    ],
                    TaskArn=task_run_command,
                    TaskType="RUN_COMMAND",
                    Priority=1,
                    ServiceRoleArn=f"arn:aws:iam::{account_id}:role/sra-patch-mgmt-automation",
                    CutoffBehavior="CONTINUE_TASK",
                    MaxConcurrency="100",
                    MaxErrors="1",
                    TaskInvocationParameters={
                        "RunCommand": {
                            "Parameters": {
                                "Operation": [task_operation],
                                "RebootOption": [task_rebootoption],
                            },
                            "DocumentVersion": "$DEFAULT",
                            "TimeoutSeconds": 3600,
                            "Comment": "Run SSMUpdate",
                            "DocumentHash": "1cbb9841b99ecbd030312fe61ad155d551eb4cf8527421fda510ec83a270a7c2",
                            "DocumentHashType": "Sha256",
                        },
                    },
                )
                window1_ids.append(
                    {
                        "region": response["region"],
                        "window1Id": response["window1Id"],
                        "windowTaskId": maintenance_window_tasks["WindowTaskId"],
                        "account_id": account_id,
                    }
                )
    for response in window_id_response['window2_ids']:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        LOGGER.info(response)
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
        # Window 2
        task_name = params.get("TASK2_NAME", "")
        task_description = params.get("TASK2_DESCRIPTION", "")
        task_run_command = params.get("TASK2_RUN_COMMAND", "")
        task_operation = params.get("TASK2_OPERATION", "Scan")
        task_rebootoption = params.get("TASK2_REBOOTOPTION", "NoReboot")

        for response2 in window_target_response['window2_targets']:
            LOGGER.info(response2)
            if (
                response2["region"] == response["region"]
            ):  # must match the region up manually so we know the target that got made in that region and match it with the window
                maintenance_window_tasks = ssmclient.register_task_with_maintenance_window(
                    Name=task_name,
                    Description=task_description,
                    WindowId=response["window2Id"],
                    Targets=[
                        {
                            "Key": "WindowTargetIds",
                            "Values": [response2["Window2TargetId"]],
                        },
                    ],
                    TaskArn=task_run_command,
                    TaskType="RUN_COMMAND",
                    Priority=1,
                    ServiceRoleArn=f"arn:aws:iam::{account_id}:role/sra-patch-mgmt-automation",
                    CutoffBehavior="CONTINUE_TASK",
                    MaxConcurrency="100",
                    MaxErrors="1",
                    TaskInvocationParameters={
                        "RunCommand": {
                            "Parameters": {
                                "Operation": [task_operation],
                                "RebootOption": [task_rebootoption],
                            },
                            "DocumentVersion": "$DEFAULT",
                            "TimeoutSeconds": 3600,
                            "Comment": "Run Windows Scan",
                            "DocumentHash": "1cbb9841b99ecbd030312fe61ad155d551eb4cf8527421fda510ec83a270a7c2",
                            "DocumentHashType": "Sha256",
                        },
                    },
                )
                window2_ids.append(
                    {
                        "region": response["region"],
                        "window2Id": response["window2Id"],
                        "windowTaskId": maintenance_window_tasks["WindowTaskId"],
                        "account_id": account_id,
                    }
                )
    for response in window_id_response['window3_ids']:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        LOGGER.info(response)
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
        # Window 1
        task_name = params.get("TASK3_NAME", "")
        task_description = params.get("TASK3_DESCRIPTION", "")
        task_run_command = params.get("TASK3_RUN_COMMAND", "")
        task_operation = params.get("TASK3_OPERATION", "Scan")
        task_rebootoption = params.get("TASK3_REBOOTOPTION", "NoReboot")

        for response2 in window_target_response['window3_targets']:
            LOGGER.info(response2)
            if (
                response2["region"] == response["region"]
            ):  # must match the region up manually so we know the target that got made in that region and match it with the window
                maintenance_window_tasks = ssmclient.register_task_with_maintenance_window(
                    Name=task_name,
                    Description=task_description,
                    WindowId=response["window3Id"],
                    Targets=[
                        {
                            "Key": "WindowTargetIds",
                            "Values": [response2["Window3TargetId"]],
                        },
                    ],
                    TaskArn=task_run_command,
                    TaskType="RUN_COMMAND",
                    Priority=1,
                    ServiceRoleArn=f"arn:aws:iam::{account_id}:role/sra-patch-mgmt-automation",
                    CutoffBehavior="CONTINUE_TASK",
                    MaxConcurrency="100",
                    MaxErrors="1",
                    TaskInvocationParameters={
                        "RunCommand": {
                            "Parameters": {
                                "Operation": [task_operation],
                                "RebootOption": [task_rebootoption],
                            },
                            "DocumentVersion": "$DEFAULT",
                            "TimeoutSeconds": 3600,
                            "Comment": "Run Linux Scan",
                            "DocumentHash": "1cbb9841b99ecbd030312fe61ad155d551eb4cf8527421fda510ec83a270a7c2",
                            "DocumentHashType": "Sha256",
                        },
                    },
                )
                window3_ids.append(
                    {
                        "region": response["region"],
                        "window3Id": response["window3Id"],
                        "windowTaskId": maintenance_window_tasks["WindowTaskId"],
                        "account_id": account_id,
                    }
                )
    return {"window1_tasks": window1_ids, "window2_tasks": window2_ids, "window3_tasks": window3_ids}


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


def get_validated_parameters(
    event: CloudFormationCustomResourceEvent,
) -> dict:  # noqa: CCR001 (cognitive complexity)
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = event["ResourceProperties"].copy()
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event["RequestType"]]

    parameter_pattern_validator(
        "CONFIGURATION_ROLE_NAME",
        params.get("CONFIGURATION_ROLE_NAME", ""),
        pattern=r"^[\w+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "CONTROL_TOWER_REGIONS_ONLY",
        params.get("CONTROL_TOWER_REGIONS_ONLY", ""),
        pattern=r"^[\w+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "DELEGATED_ADMIN_ACCOUNT_ID",
        params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
        pattern=r"^[\w+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "ROLE_NAME_TO_ASSUME",
        params.get("ROLE_NAME_TO_ASSUME", ""),
        pattern=r"^[\w+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "ENABLED_REGIONS",
        params.get("ENABLED_REGIONS", ""),
        pattern=r"^[\w\"+=,.@-]{0,64}$",
    )
    parameter_pattern_validator(
        "MANAGEMENT_ACCOUNT_ID",
        params.get("MANAGEMENT_ACCOUNT_ID", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    # Window 1
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW1_NAME",
        params.get("MAINTENANCE_WINDOW1_NAME", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW1_DESCRIPTION",
        params.get("MAINTENANCE_WINDOW1_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW1_SCHEDULE",
        params.get("MAINTENANCE_WINDOW1_SCHEDULE", ""),
        pattern=r"^[\w\s*?()+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW1_DURATION",
        params.get("MAINTENANCE_WINDOW1_DURATION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW1_CUTOFF",
        params.get("MAINTENANCE_WINDOW1_CUTOFF", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW1_TIMEZONE",
        params.get("MAINTENANCE_WINDOW1_TIMEZONE", ""),
        pattern=r"^[\w\/+=,.@-]{1,64}$",
    )
    parameter_pattern_validator("TASK1_NAME", params.get("TASK1_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$")
    parameter_pattern_validator(
        "TASK1_DESCRIPTION",
        params.get("TASK1_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TASK1_RUN_COMMAND",
        params.get("TASK1_RUN_COMMAND", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator("TARGET1_NAME", params.get("TARGET1_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$")
    parameter_pattern_validator(
        "TARGET1_DESCRIPTION",
        params.get("TARGET1_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TARGET1_VALUE_1",
        params.get("TARGET1_VALUE_1", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TARGET1_VALUE_2",
        params.get("TARGET1_VALUE_2", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    # Window 2
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW2_NAME",
        params.get("MAINTENANCE_WINDOW2_NAME", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW2_DESCRIPTION",
        params.get("MAINTENANCE_WINDOW2_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW2_SCHEDULE",
        params.get("MAINTENANCE_WINDOW2_SCHEDULE", ""),
        pattern=r"^[\w\s*?()+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW2_DURATION",
        params.get("MAINTENANCE_WINDOW2_DURATION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW2_CUTOFF",
        params.get("MAINTENANCE_WINDOW2_CUTOFF", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW2_TIMEZONE",
        params.get("MAINTENANCE_WINDOW2_TIMEZONE", ""),
        pattern=r"^[\w\/+=,.@-]{1,64}$",
    )
    parameter_pattern_validator("TASK2_NAME", params.get("TASK2_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$")
    parameter_pattern_validator(
        "TASK2_DESCRIPTION",
        params.get("TASK2_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TASK2_RUN_COMMAND",
        params.get("TASK2_RUN_COMMAND", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator("TARGET2_NAME", params.get("TARGET2_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$")
    parameter_pattern_validator(
        "TARGET2_DESCRIPTION",
        params.get("TARGET2_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TARGET2_VALUE_1",
        params.get("TARGET2_VALUE_1", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    # Window 3
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW3_NAME",
        params.get("MAINTENANCE_WINDOW3_NAME", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW3_DESCRIPTION",
        params.get("MAINTENANCE_WINDOW3_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW3_SCHEDULE",
        params.get("MAINTENANCE_WINDOW3_SCHEDULE", ""),
        pattern=r"^[\w\s*?()+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW3_DURATION",
        params.get("MAINTENANCE_WINDOW3_DURATION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW3_CUTOFF",
        params.get("MAINTENANCE_WINDOW3_CUTOFF", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW3_TIMEZONE",
        params.get("MAINTENANCE_WINDOW3_TIMEZONE", ""),
        pattern=r"^[\w\/+=,.@-]{1,64}$",
    )
    parameter_pattern_validator("TASK3_NAME", params.get("TASK3_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$")
    parameter_pattern_validator(
        "TASK3_DESCRIPTION",
        params.get("TASK3_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TASK3_RUN_COMMAND",
        params.get("TASK3_RUN_COMMAND", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator("TARGET3_NAME", params.get("TARGET3_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$")
    parameter_pattern_validator(
        "TARGET3_DESCRIPTION",
        params.get("TARGET3_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TARGET3_VALUE_1",
        params.get("TARGET3_VALUE_1", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )

    return params


def process_create_update_event(params: dict, regions: list) -> Dict:
    """Process create update events.

    Args:
        params (dict): Cloudformation Params
        regions (list): Regions to perform our work in.

    Returns:
        Dict: Dictionary of Window IDs, Targets, and Tasks
    """
    account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])  # they updated the stack and want us to remove things.
    all_window_ids = []
    all_window_targets = []
    all_window_tasks = []
    if (params.get("DISABLE_PATCHMGMT", "false")).lower() in "true" and params["action"] == "Update":
        # they updated the stack and want us to remove things.
        patchmgmt.cleanup_patchmgmt(params, boto3_config)

    else:
        for account_id in account_ids:  # across all accounts they desire
            window_ids_raw = create_maintenance_window(params, account_id, regions)
            all_window_ids.append(window_ids_raw["window1_ids"])
            all_window_ids.append(window_ids_raw["window2_ids"])
            all_window_ids.append(window_ids_raw["window3_ids"])
            window_target_response = define_maintenance_window_targets(params, window_ids_raw["window1_ids"],window_ids_raw["window2_ids"],window_ids_raw["window3_ids"], account_id)
            all_window_targets.append(window_target_response)
            all_window_tasks.append(define_maintenance_window_tasks(params, window_ids_raw, window_target_response, account_id))
    return {"window_ids": all_window_ids, "window_targets": all_window_targets, "window_tasks": all_window_tasks}


@helper.create
@helper.update
@helper.delete
def process_cloudformation_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    request_type = event["RequestType"] 
    LOGGER.info(f"{request_type} Event")
    LOGGER.debug(f"Lambda Context: {context}")

    params = get_validated_parameters(event)
    regions = common.get_enabled_regions(
        params.get("ENABLED_REGIONS", ""),
        (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true",
    )

    if params["action"] in "Add, Update":
        process_create_update_event(params, regions)
    elif params["action"] == "Remove":
        patchmgmt.cleanup_patchmgmt(params, boto3_config)

    return f"sra-patch_mgmt-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def lambda_handler(event: Dict[str, Any], context: Context) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Returns:
      Response is Handled by CR Helper

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Lambda Handler Started....")
    event_info = {"Event": event}
    LOGGER.info(event_info)
    try:
        helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
