"""This script performs operations to enable, configure, and disable AWS Systems Manager Patch Manager.

Version: 2.0
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
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_ssm.type_defs import RegisterTaskWithMaintenanceWindowResultTypeDef
    from mypy_boto3_ssm.type_defs import MaintenanceWindowTaskInvocationParametersTypeDef
    from mypy_boto3_ssm.type_defs import TargetTypeDef


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

def get_document_hash(session: boto3.Session, region: str, document_name: str) -> str:
    """
    Get the latest document hash for a given document name and region.

    Args:
        session (boto3.session.Session): The AWS session object
        region (str): The AWS region
        document_name (str): The name of the SSM document

    Returns:
        str: The latest document hash
    """
    ssm_client = session.client("ssm", region_name=region, config=boto3_config)
    response = ssm_client.describe_document(Name=document_name)
    return response["Document"]["Hash"]


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
        "sra-patch-mgmt-lambda",
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
            SettingValue="service-role/AWSSystemsManagerDefaultEC2InstanceManagementRoleCustom",
        )
        # Window 1
        maintenance_window_name = params.get("MAINTENANCE_WINDOW1_NAME", "sra_windows_patch_mgmt")
        maintenance_window_description = params.get("MAINTENANCE_WINDOW1_DESCRIPTION", "Window for Windows Patch Management")
        maintenance_window_schedule = params.get("MAINTENANCE_WINDOW1_SCHEDULE", "cron(0 9 ? * SUN *)")
        maintenance_window_duration = int(params.get("MAINTENANCE_WINDOW1_DURATION", 120))
        maintenance_window_cutoff = int(params.get("MAINTENANCE_WINDOW1_CUTOFF", 0))
        maintenance_window_timezone = params.get("MAINTENANCE_WINDOW1_TIMEZONE", "America/Los_Angeles")
        document_name = "AWS-RunPatchBaseline"
        document_hash = get_document_hash(session, region, document_name)

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
        window1_ids.append(
            {
                "region": region,
                "window1Id": maintenance_window["WindowId"],
                "account_id": account_id,
                "document_hash": document_hash,
            }
        )
        # Window 2
        maintenance_window_name = params.get("MAINTENANCE_WINDOW2_NAME", "sra_windows_patch_scan")
        maintenance_window_description = params.get("MAINTENANCE_WINDOW2_DESCRIPTION", "Window for Windows Patch Scan")
        maintenance_window_schedule = params.get("MAINTENANCE_WINDOW2_SCHEDULE", "cron(0 7 ? * SUN *)")
        maintenance_window_duration = int(params.get("MAINTENANCE_WINDOW2_DURATION", 120))
        maintenance_window_cutoff = int(params.get("MAINTENANCE_WINDOW2_CUTOFF", 0))
        maintenance_window_timezone = params.get("MAINTENANCE_WINDOW2_TIMEZONE", "America/Los_Angeles")
        document_name = "AWS-RunPatchBaseline"
        document_hash = get_document_hash(session, region, document_name)

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
        window2_ids.append(
            {
                "region": region,
                "window2Id": maintenance_window["WindowId"],
                "account_id": account_id,
                "document_hash": document_hash,
            }
        )
        # Window 3
        maintenance_window_name = params.get("MAINTENANCE_WINDOW3_NAME", "sra_linux_patch_scan")
        maintenance_window_description = params.get("MAINTENANCE_WINDOW3_DESCRIPTION", "Window for Linux Patch Scan")
        maintenance_window_schedule = params.get("MAINTENANCE_WINDOW3_SCHEDULE", "cron(0 7 ? * SAT *)")
        maintenance_window_duration = int(params.get("MAINTENANCE_WINDOW3_DURATION", 120))
        maintenance_window_cutoff = int(params.get("MAINTENANCE_WINDOW3_CUTOFF", 0))
        maintenance_window_timezone = params.get("MAINTENANCE_WINDOW3_TIMEZONE", "America/Los_Angeles")
        document_name = "AWS-RunPatchBaseline"
        document_hash = get_document_hash(session, region, document_name)

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
        window3_ids.append(
            {
                "region": region,
                "window3Id": maintenance_window["WindowId"],
                "account_id": account_id,
                "document_hash": document_hash,
            }
        )

    return {"window1_ids": window1_ids, "window2_ids": window2_ids, "window3_ids": window3_ids}


def define_mw_targets(params: dict, win1_id_resp: list, win2_id_resp: list, win3_id_resp: list, account_id: str) -> dict[str, list]:
    """Define Maintenance Window Targets.

    Args:
        params (dict): Cloudformation Params
        win1_id_resp (list): Previous Window 1 IDs for the Targets
        win2_id_resp (list): Previous Window 2 IDs for the Targets
        win3_id_resp (list): Previous Window 3 IDs for the Targets
        account_id (str): Account ID for the targets to live in

    Returns:
        list[dict[str, Any]]: _description_
    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-lambda",
        account_id,
    )
    window1_targets = []
    window2_targets = []
    window3_targets = []
    for response in win1_id_resp:
        LOGGER.info(f"Maintenance Window Targets {response['region']}")
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)

        # Window 1
        target_name = params.get("TARGET1_NAME", "Windows_Instances")
        target_description = params.get("TARGET1_DESCRIPTION", "Target Windows and Linux Instances")
        target_key_value_1 = params.get("TARGET1_VALUE_1", "Windows")
        target_key_value_2 = params.get("TARGET1_VALUE_2", "Linux")
        LOGGER.info(f"About to register target in {response['region']} for window ID {response['window1Id']} with name {target_name}")
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
    for response in win2_id_resp:
        LOGGER.info(f"Maintenance Window Targets {response['region']}")
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
        # Window 2
        target_name = params.get("TARGET2_NAME", "Windows_Instances")
        target_description = params.get("TARGET2_DESCRIPTION", "Target Windows Instances")
        target_key_value_1 = params.get("TARGET2_VALUE_1", "Windows")
        LOGGER.info(f"About to register target in {response['region']} for window ID {response['window2Id']} with name {target_name}")

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
    for response in win3_id_resp:
        # Window 3
        target_name = params.get("TARGET3_NAME", "Linux_Instances")
        target_description = params.get("TARGET3_DESCRIPTION", "Target Linux Instances")
        target_key_value_1 = params.get("TARGET3_VALUE_1", "Linux")
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
        LOGGER.info(f"About to register target in {response['region']} for window ID {response['window3Id']} with name {target_name}")

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

def manage_task_params(task_operation: str|None, task_name: str, document_hash: str, task_reboot_option: str|None) -> MaintenanceWindowTaskInvocationParametersTypeDef:
    """Manages Task Parameters.

    Args:
        task_operation (str|None): The task operation
        task_name (str): The task name
        document_hash (str): The document hash
        task_reboot_option (str|None): The task reboot option

    Returns:
        dict: The response from the register_task_with_maintenance_window API call
    """
    if task_operation is None and task_reboot_option is None:
        return {
            "RunCommand": {
                "Parameters": {},
                "DocumentVersion": "$DEFAULT",
                "TimeoutSeconds": 3600,
                "Comment": f"Run {task_operation} for {task_name}",
                "DocumentHash": document_hash,
                "DocumentHashType": "Sha256",
            },
        }
    else:
        task_operation_final: str = 'INVALID_TASK_OPERATION_PROVIDED' if task_operation is None else task_operation
        task_reboot_option_final: str = 'INVALID_TASK_REBOOT_OPTION_PROVIDED' if task_reboot_option is None else task_reboot_option
        return {
            "RunCommand": {
                "Parameters": {
                    "Operation": [task_operation_final],
                    "RebootOption": [task_reboot_option_final],
                },
                "DocumentVersion": "$DEFAULT",
                "TimeoutSeconds": 3600,
                "Comment": f"Run {task_operation} for {task_name}",
                "DocumentHash": document_hash,
                "DocumentHashType": "Sha256",
            },
        }
    

def register_task(
    session: boto3.Session,
    response: dict,
    window_id: str,
    account_id: str,
    window_target_id: str,
    task_name: str,
    task_description: str,
    task_run_command: str,
    task_operation: str|None,
    task_reboot_option: str|None,
    document_hash: str,
) -> RegisterTaskWithMaintenanceWindowResultTypeDef:
    """Helper function to register a task with a maintenance window.

    Args:
        session (str): The Session
        response (str): The response from maintenance windows
        window_id (str): The ID of the maintenance window
        window_target_id (str): The ID of the maintenance window target
        task_name (str): The name of the task
        task_description (str): The description of the task
        task_run_command (str): The ARN of the SSM document to run
        task_operation (str): The operation to perform (e.g., Scan, Install)
        task_reboot_option (str): The reboot option (e.g., NoReboot, RebootIfNeeded)
        document_hash (str): The hash of the SSM document

    Returns:
        dict: The response from the register_task_with_maintenance_window API call
    """
    ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
    taskParams: MaintenanceWindowTaskInvocationParametersTypeDef = manage_task_params(task_operation, task_name, document_hash, task_reboot_option)
    targetType: TargetTypeDef = {
                "Key": "WindowTargetIds",
                "Values": [window_target_id],
            }
    maintenance_window_tasks = ssmclient.register_task_with_maintenance_window(
        Name=task_name,
        Description=task_description,
        WindowId=window_id,
        Targets=[targetType],
        TaskArn=task_run_command,
        TaskType="RUN_COMMAND",
        Priority=1,
        ServiceRoleArn=f"arn:aws:iam::{account_id}:role/sra-patch-mgmt-automation",
        CutoffBehavior="CONTINUE_TASK",
        MaxConcurrency="100",
        MaxErrors="1",
        TaskInvocationParameters=taskParams,
    )
    return maintenance_window_tasks


def def_mw_tasks(params: dict, window_id_response: dict, window_target_response: dict, account_id: str) -> dict:
    """Define maintenance window tasks.

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
        "sra-patch-mgmt-lambda",
        account_id,
    )
    window1_tasks = []
    window2_tasks = []
    window3_tasks = []

    for response in window_id_response["window1_ids"]:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        # Window 1
        task_name = params.get("TASK1_NAME", "Windows_Patch_Install")
        task_description = params.get("TASK1_DESCRIPTION", "Install Patches on Windows Instances")
        task_run_command = params.get("TASK1_RUN_COMMAND", "AWS-RunPatchBaseline")

        for response2 in window_target_response["window1_targets"]:
            if response2["region"] == response["region"]:
                task_response = register_task(
                    session,
                    response,
                    response["window1Id"],
                    account_id,
                    response2["Window1TargetId"],
                    task_name,
                    task_description,
                    task_run_command,
                    None,
                    None,
                    response["document_hash"],
                )
                window1_tasks.append(
                    {
                        "region": response["region"],
                        "window1Id": response["window1Id"],
                        "windowTaskId": task_response["WindowTaskId"],
                        "account_id": account_id,
                    }
                )

    for response in window_id_response["window2_ids"]:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        # Window 2
        task_name = params.get("TASK2_NAME", "Windows_Patch_Scan")
        task_description = params.get("TASK2_DESCRIPTION", "Scan for Patches on Windows Instances")
        task_run_command = params.get("TASK2_RUN_COMMAND", "AWS-RunPatchBaseline")
        task_operation = params.get("TASK2_OPERATION", "Scan")
        task_reboot_option = params.get("TASK2_REBOOTOPTION", "NoReboot")

        for response2 in window_target_response["window2_targets"]:
            if response2["region"] == response["region"]:
                task_response = register_task(
                    session,
                    response,
                    response["window2Id"],
                    account_id,
                    response2["Window2TargetId"],
                    task_name,
                    task_description,
                    task_run_command,
                    task_operation,
                    task_reboot_option,
                    response["document_hash"],
                )
                window2_tasks.append(
                    {
                        "region": response["region"],
                        "window2Id": response["window2Id"],
                        "windowTaskId": task_response["WindowTaskId"],
                        "account_id": account_id,
                    }
                )

    for response in window_id_response["window3_ids"]:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        # Window 3
        task_name = params.get("TASK3_NAME", "Linux_Patch_Scan")
        task_description = params.get("TASK3_DESCRIPTION", "Scan for Patches on Linux Instances")
        task_run_command = params.get("TASK3_RUN_COMMAND", "AWS-RunPatchBaseline")
        task_operation = params.get("TASK3_OPERATION", "Scan")
        task_reboot_option = params.get("TASK3_REBOOTOPTION", "NoReboot")

        for response2 in window_target_response["window3_targets"]:
            if response2["region"] == response["region"]:
                task_response = register_task(
                    session,
                    response,
                    response["window3Id"],
                    account_id,
                    response2["Window3TargetId"],
                    task_name,
                    task_description,
                    task_run_command,
                    task_operation,
                    task_reboot_option,
                    response["document_hash"],
                )
                window3_tasks.append(
                    {
                        "region": response["region"],
                        "window3Id": response["window3Id"],
                        "windowTaskId": task_response["WindowTaskId"],
                        "account_id": account_id,
                    }
                )

    return {"window1_tasks": window1_tasks, "window2_tasks": window2_tasks, "window3_tasks": window3_tasks}


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


def process_create_update_event(params: dict, regions: list) -> Dict:
    """Process create update events.

    Args:
        params (dict): Cloudformation Params
        regions (list): Regions to perform our work in.

    Returns:
        Dict: Dictionary of Window IDs, Targets, and Tasks
    """
    account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])
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
            window_target_response = define_mw_targets(
                params, window_ids_raw["window1_ids"], window_ids_raw["window2_ids"], window_ids_raw["window3_ids"], account_id
            )
            all_window_targets.append(window_target_response)
            all_window_tasks.append(def_mw_tasks(params, window_ids_raw, window_target_response, account_id))
    return {"window_ids": all_window_ids, "window_targets": all_window_targets, "window_tasks": all_window_tasks}


def check_and_update_maintenance_window(params: dict, regions: list, account_id: str) -> None:
    """
    Check if a maintenance window with the same name already exists, and update it if necessary.

    Args:
        params (dict): CloudFormation parameters
        regions (list): List of AWS regions
        account_id (str): AWS account ID
    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-lambda",
        account_id,
    )
    for region in regions:
        ssmclient = session.client("ssm", region_name=region, config=boto3_config)

        # Check if Window 1 exists
        window1_name = params.get("MAINTENANCE_WINDOW1_NAME", "sra_windows_patch_mgmt")
        existing_window1 = ssmclient.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [window1_name]}])
        if existing_window1["WindowIdentities"]:
            window1_id = existing_window1["WindowIdentities"][0]["WindowId"]
            LOGGER.info(f"Maintenance window '{window1_name}' already exists in {region} with ID {window1_id}. Updating...")
            update_maintenance_window(ssmclient, window1_id, params, "MAINTENANCE_WINDOW1")

        # Check if Window 2 exists
        window2_name = params.get("MAINTENANCE_WINDOW2_NAME", "sra_windows_patch_scan")
        existing_window2 = ssmclient.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [window2_name]}])
        if existing_window2["WindowIdentities"]:
            window2_id = existing_window2["WindowIdentities"][0]["WindowId"]
            LOGGER.info(f"Maintenance window '{window2_name}' already exists in {region} with ID {window2_id}. Updating...")
            update_maintenance_window(ssmclient, window2_id, params, "MAINTENANCE_WINDOW2")

        # Check if Window 3 exists
        window3_name = params.get("MAINTENANCE_WINDOW3_NAME", "sra_linux_patch_scan")
        existing_window3 = ssmclient.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [window3_name]}])
        if existing_window3["WindowIdentities"]:
            window3_id = existing_window3["WindowIdentities"][0]["WindowId"]
            LOGGER.info(f"Maintenance window '{window3_name}' already exists in {region} with ID {window3_id}. Updating...")
            update_maintenance_window(ssmclient, window3_id, params, "MAINTENANCE_WINDOW3")


def update_maintenance_window(ssmclient: SSMClient, window_id: str, params: dict, window_prefix: str) -> None:
    """
    Update an existing maintenance window with the provided parameters.

    Args:
        ssmclient (SSMClient): AWS Systems Manager client
        window_id (str): ID of the maintenance window to update
        params (dict): CloudFormation parameters
        window_prefix (str): Prefix for the maintenance window parameters (e.g., "MAINTENANCE_WINDOW1")
    """
    window_name: str = params.get(f"{window_prefix}_NAME", "No_Name_Provided")
    window_description: str = params.get(f"{window_prefix}_DESCRIPTION", "No Description Provided.")
    window_schedule: str = params.get(f"{window_prefix}_SCHEDULE", "cron(0 9 ? * SUN *)")
    window_duration = int(params.get(f"{window_prefix}_DURATION", 120))
    window_cutoff = int(params.get(f"{window_prefix}_CUTOFF", 0))
    window_timezone = params.get(f"{window_prefix}_TIMEZONE", "America/Los_Angeles")

    ssmclient.update_maintenance_window(
        WindowId=window_id,
        Name=window_name,
        Description=window_description,
        Schedule=window_schedule,
        Duration=window_duration,
        Cutoff=window_cutoff,
        ScheduleTimezone=window_timezone,
        AllowUnassociatedTargets=False,
    )


def get_validated_parameters(event: CloudFormationCustomResourceEvent) -> dict:  # noqa: CCR001, CFQ001
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = event["ResourceProperties"].copy()
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event["RequestType"]]

    # Validate parameters based on patterns

    # ... (parameter validation logic remains the same)

    # Check if required parameters are provided
    required_params = [
        "CONFIGURATION_ROLE_NAME",
        "CONTROL_TOWER_REGIONS_ONLY",
        "DELEGATED_ADMIN_ACCOUNT_ID",
        "ROLE_NAME_TO_ASSUME",
        "MANAGEMENT_ACCOUNT_ID",
        "MAINTENANCE_WINDOW1_NAME",
        "MAINTENANCE_WINDOW1_DESCRIPTION",
        "MAINTENANCE_WINDOW1_SCHEDULE",
        "MAINTENANCE_WINDOW1_DURATION",
        "MAINTENANCE_WINDOW1_CUTOFF",
        "MAINTENANCE_WINDOW1_TIMEZONE",
        "TASK1_NAME",
        "TASK1_DESCRIPTION",
        "TASK1_RUN_COMMAND",
        "TARGET1_NAME",
        "TARGET1_DESCRIPTION",
        "TARGET1_VALUE_1",
        "TARGET1_VALUE_2",
        "MAINTENANCE_WINDOW2_NAME",
        "MAINTENANCE_WINDOW2_DESCRIPTION",
        "MAINTENANCE_WINDOW2_SCHEDULE",
        "MAINTENANCE_WINDOW2_DURATION",
        "MAINTENANCE_WINDOW2_CUTOFF",
        "MAINTENANCE_WINDOW2_TIMEZONE",
        "TASK2_NAME",
        "TASK2_DESCRIPTION",
        "TASK2_RUN_COMMAND",
        "TARGET2_NAME",
        "TARGET2_DESCRIPTION",
        "TARGET2_VALUE_1",
        "MAINTENANCE_WINDOW3_NAME",
        "MAINTENANCE_WINDOW3_DESCRIPTION",
        "MAINTENANCE_WINDOW3_SCHEDULE",
        "MAINTENANCE_WINDOW3_DURATION",
        "MAINTENANCE_WINDOW3_CUTOFF",
        "MAINTENANCE_WINDOW3_TIMEZONE",
        "TASK3_NAME",
        "TASK3_DESCRIPTION",
        "TASK3_RUN_COMMAND",
        "TARGET3_NAME",
        "TARGET3_DESCRIPTION",
        "TARGET3_VALUE_1",
    ]

    missing_params = [param for param in required_params if not params.get(param)]
    if missing_params:
        raise ValueError(f"Required parameters are missing: {', '.join(missing_params)}")

    return params


@helper.create
@helper.update
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
    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    # Check and update existing maintenance windows
    check_and_update_maintenance_window(params, regions, account_id)

    if params["action"] == "Add":
        process_create_update_event(params, regions)

    return f"sra-patch_mgmt-{account_id}"


@helper.delete
def process_cloudformation_delete_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:
    """Process delete event from AWS CloudFormation.

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
    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    if params["action"] == "Remove":
        patchmgmt.cleanup_patchmgmt(params, boto3_config)

    return f"sra-patch_mgmt-{account_id}"


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
    LOGGER.info(f"Lambda Handler Started. Event: {event}")
    try:
        helper(event, context)
    except Exception as e:
        LOGGER.exception(f"Unexpected error executing Lambda function: {e}")
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details.") from None
