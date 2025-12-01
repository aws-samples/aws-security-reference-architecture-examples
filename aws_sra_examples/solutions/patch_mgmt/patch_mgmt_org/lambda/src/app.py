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
from typing import TYPE_CHECKING, Any, Dict, List

import boto3
import common
import patchmgmt
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_ssm.client import SSMClient
    from mypy_boto3_ssm.type_defs import (
        MaintenanceWindowTaskInvocationParametersTypeDef,
        RegisterTaskWithMaintenanceWindowResultTypeDef,
        TargetTypeDef,
    )


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


def create_maintenance_window_1(account_id: str, session: boto3.Session, region: str, params: dict) -> dict:
    """Create windows patch maintenance window 1.

    Args:
        account_id (str): Account ID
        session (boto3.Session): Boto3 Session
        region (str): Region
        params (dict): Parameters

    Returns:
        dict: Maintenance Info Created
    """
    LOGGER.info(f"Setting up Default Host Management and Creating a Maint Window for Window 1 in region {region}")
    ssmclient = session.client("ssm", region_name=region, config=boto3_config)
    ssmclient.update_service_setting(
        SettingId="/ssm/managed-instance/default-ec2-instance-management-role",
        SettingValue="service-role/AWSSystemsManagerDefaultEC2InstanceManagementRoleCustom",
    )

    maintenance_window_name = params["MAINTENANCE_WINDOW1_NAME"]
    maintenance_window_description = params["MAINTENANCE_WINDOW1_DESCRIPTION"]
    maintenance_window_schedule = params["MAINTENANCE_WINDOW1_SCHEDULE"]
    maintenance_window_duration = int(params["MAINTENANCE_WINDOW1_DURATION"])
    maintenance_window_cutoff = int(params["MAINTENANCE_WINDOW1_CUTOFF"])
    maintenance_window_timezone = params["MAINTENANCE_WINDOW1_TIMEZONE"]
    document_name = params["TASK1_RUN_COMMAND"]
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
    return {
        "region": region,
        "window1Id": maintenance_window["WindowId"],
        "account_id": account_id,
        "document_hash": document_hash,
    }


def create_maintenance_window_2(account_id: str, session: boto3.Session, region: str, params: dict) -> dict:
    """Create windows patch scan maintenance window 2.

    Args:
        account_id (str): Account ID
        session (boto3.Session): Boto3 Session
        region (str): Region
        params (dict): Parameters

    Returns:
        dict: Maintenance Info Created
    """
    LOGGER.info(f"Setting up Default Host Management and Creating a Maint Window for Window 2 in region {region}")
    ssmclient = session.client("ssm", region_name=region, config=boto3_config)
    ssmclient.update_service_setting(
        SettingId="/ssm/managed-instance/default-ec2-instance-management-role",
        SettingValue="service-role/AWSSystemsManagerDefaultEC2InstanceManagementRoleCustom",
    )

    maintenance_window_name = params["MAINTENANCE_WINDOW2_NAME"]
    maintenance_window_description = params["MAINTENANCE_WINDOW2_DESCRIPTION"]
    maintenance_window_schedule = params["MAINTENANCE_WINDOW2_SCHEDULE"]
    maintenance_window_duration = int(params["MAINTENANCE_WINDOW2_DURATION"])
    maintenance_window_cutoff = int(params["MAINTENANCE_WINDOW2_CUTOFF"])
    maintenance_window_timezone = params["MAINTENANCE_WINDOW2_TIMEZONE"]
    document_name = params["TASK2_RUN_COMMAND"]
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
    return {
        "region": region,
        "window2Id": maintenance_window["WindowId"],
        "account_id": account_id,
        "document_hash": document_hash,
    }


def create_maintenance_window_3(account_id: str, session: boto3.Session, region: str, params: dict) -> dict:
    """Create Linux Patch Scan Window 3.

    Args:
        account_id (str): Account ID
        session (boto3.Session): Boto3 Session
        region (str): Region
        params (dict): Parameters

    Returns:
        dict: Maintenance Info Created
    """
    LOGGER.info(f"Setting up Default Host Management and Creating a Maint Window for Window 3 in region {region}")
    ssmclient = session.client("ssm", region_name=region, config=boto3_config)
    ssmclient.update_service_setting(
        SettingId="/ssm/managed-instance/default-ec2-instance-management-role",
        SettingValue="service-role/AWSSystemsManagerDefaultEC2InstanceManagementRoleCustom",
    )

    maintenance_window_name = params["MAINTENANCE_WINDOW3_NAME"]
    maintenance_window_description = params["MAINTENANCE_WINDOW3_DESCRIPTION"]
    maintenance_window_schedule = params["MAINTENANCE_WINDOW3_SCHEDULE"]
    maintenance_window_duration = int(params["MAINTENANCE_WINDOW3_DURATION"])
    maintenance_window_cutoff = int(params["MAINTENANCE_WINDOW3_CUTOFF"])
    maintenance_window_timezone = params["MAINTENANCE_WINDOW3_TIMEZONE"]
    document_name = params["TASK3_RUN_COMMAND"]
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
    return {
        "region": region,
        "window3Id": maintenance_window["WindowId"],
        "account_id": account_id,
        "document_hash": document_hash,
    }


def create_maint_window(params: dict, account_id: str, regions: list) -> dict:
    """Create all maintenance windows in all regions in an account.

    Args:
        params (dict): Parameters
        account_id (str): Account ID
        regions (list): Regions to do this in

    Returns:
        dict: Maintenance Info Created
    """
    session = common.assume_role(
        params["ROLE_NAME_TO_ASSUME"],
        "sra-patch-mgmt-lambda",
        account_id,
    )

    window1_ids = []
    window2_ids = []
    window3_ids = []

    for region in regions:
        LOGGER.info(f"Creating Maintenance Windows in {account_id} account {region} region")
        window1_ids.append(create_maintenance_window_1(account_id, session, region, params))
        window2_ids.append(create_maintenance_window_2(account_id, session, region, params))
        window3_ids.append(create_maintenance_window_3(account_id, session, region, params))

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
        params["ROLE_NAME_TO_ASSUME"],
        "sra-patch-mgmt-lambda",
        account_id,
    )
    window1_targets = []
    window2_targets = []
    window3_targets = []
    for response in win1_id_resp:
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)

        # Window 1
        target_name = params["TARGET1_NAME"]
        target_description = params["TARGET1_DESCRIPTION"]
        target_key_value_1 = params["TARGET1_VALUE_1"]
        target_key_value_2 = params["TARGET1_VALUE_2"]
        LOGGER.info(f"Registering target in {response['region']} for '{target_name}' window (ID {response['window1Id']})")
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
        target_name = params["TARGET2_NAME"]
        target_description = params["TARGET2_DESCRIPTION"]
        target_key_value_1 = params["TARGET2_VALUE_1"]
        LOGGER.info(f"Registering target in {response['region']} for '{target_name}' window (ID {response['window2Id']})")

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
        target_name = params["TARGET3_NAME"]
        target_description = params["TARGET3_DESCRIPTION"]
        target_key_value_1 = params["TARGET3_VALUE_1"]
        ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
        LOGGER.info(f"Registering target in {response['region']} for '{target_name}' window (ID {response['window3Id']})")

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


def manage_task_params(
    task_operation: str | None, task_name: str, document_hash: str, task_reboot_option: str | None
) -> MaintenanceWindowTaskInvocationParametersTypeDef:
    """Manage task parameters.

    Args:
        task_operation (str | None): The task operation
        task_name (str): The task name
        document_hash (str): The document hash
        task_reboot_option (str | None): The task reboot option

    Returns:
        MaintenanceWindowTaskInvocationParametersTypeDef: The response from the register_task_with_maintenance_window API call
    """
    if task_operation is None and task_reboot_option is None:
        no_param_response: MaintenanceWindowTaskInvocationParametersTypeDef = {
            "RunCommand": {
                "Parameters": {},
                "DocumentVersion": "$DEFAULT",
                "TimeoutSeconds": 3600,
                "Comment": f"Run {task_operation} for {task_name}",
                "DocumentHash": document_hash,
                "DocumentHashType": "Sha256",
            },
        }
        return no_param_response
    task_operation_final: str = "INVALID_TASK_OPERATION_PROVIDED" if task_operation is None else task_operation
    task_reboot_option_final: str = "INVALID_TASK_REBOOT_OPTION_PROVIDED" if task_reboot_option is None else task_reboot_option
    with_params_response: MaintenanceWindowTaskInvocationParametersTypeDef = {
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
    return with_params_response


def register_task(
    session: boto3.Session,
    response: dict,
    window_id: str,
    account_id: str,
    window_target_id: str,
    task_details: dict,
    document_hash: str,
) -> RegisterTaskWithMaintenanceWindowResultTypeDef:  # noqa: DAR203, DAR103
    """Register task with maintenance window.

    Args:
        session (boto3.Session): The Session
        response (dict): The response from maintenance windows
        window_id (str): The ID of the maintenance window
        account_id (str): The Account ID
        window_target_id (str): The ID of the maintenance window target
        task_details (dict): The task details
        document_hash (str): The hash of the SSM document

    Returns:
        RegisterTaskWithMaintenanceWindowResultTypeDef: The response from the register_task_with_maintenance_window API call
    """
    task_name = task_details["name"]
    task_description = task_details["description"]
    task_run_command = task_details["run_command"]
    task_operation = task_details["operation"]
    task_reboot_option = task_details["reboot_option"]

    ssmclient = session.client("ssm", region_name=response["region"], config=boto3_config)
    task_params: MaintenanceWindowTaskInvocationParametersTypeDef = manage_task_params(task_operation, task_name, document_hash, task_reboot_option)
    target_type: TargetTypeDef = {
        "Key": "WindowTargetIds",
        "Values": [window_target_id],
    }
    return ssmclient.register_task_with_maintenance_window(
        Name=task_name,
        Description=task_description,
        WindowId=window_id,
        Targets=[target_type],
        TaskArn=task_run_command,
        TaskType="RUN_COMMAND",
        Priority=1,
        ServiceRoleArn=f"arn:aws:iam::{account_id}:role/sra-patch-mgmt-automation",
        CutoffBehavior="CONTINUE_TASK",
        MaxConcurrency="100",
        MaxErrors="1",
        TaskInvocationParameters=task_params,
    )


def register_window_tasks(
    session: boto3.Session,
    window_id_response: dict,
    window_target_response: dict,
    account_id: str,
    window_num: int,
    task_details: Dict[str, str | None],
) -> List[Dict[str, str]]:
    """Register tasks for a specific maintenance window.

    Args:
        session (boto3.Session): The AWS session object.
        window_id_response (dict): The Window IDs we made.
        window_target_response (dict): The window Targets we made.
        account_id (str): The Account #.
        window_num (int): The window number (1, 2, or 3).
        task_details (Dict[str, str | None]): The task details.

    Returns:
        List[Dict[str, str]]: A list of window tasks created.
    """
    window_tasks: List[Dict[str, str]] = []
    window_id_key = f"window{window_num}_ids"
    window_target_key = f"window{window_num}_targets"

    for response in window_id_response[window_id_key]:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        for response2 in window_target_response[window_target_key]:
            if response2["region"] == response["region"]:
                task_response = register_task(
                    session,
                    response,
                    response[f"window{window_num}Id"],
                    account_id,
                    response2[f"Window{window_num}TargetId"],
                    task_details,
                    response["document_hash"],
                )
                window_tasks.append(
                    {
                        "region": response["region"],
                        f"window{window_num}Id": response[f"window{window_num}Id"],
                        "windowTaskId": task_response["WindowTaskId"],
                        "account_id": account_id,
                    }
                )

    return window_tasks


def def_mw_tasks(
    params: dict,
    window_id_response: dict,
    window_target_response: dict,
    account_id: str,
) -> dict:
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
        params["ROLE_NAME_TO_ASSUME"],
        "sra-patch-mgmt-lambda",
        account_id,
    )

    window1_tasks = register_window_tasks(
        session,
        window_id_response,
        window_target_response,
        account_id,
        1,
        {
            "name": params["TASK1_NAME"],
            "description": params["TASK1_DESCRIPTION"],
            "run_command": params["TASK1_RUN_COMMAND"],
            "operation": None,
            "reboot_option": None,
        },
    )

    window2_tasks = register_window_tasks(
        session,
        window_id_response,
        window_target_response,
        account_id,
        2,
        {
            "name": params["TASK2_NAME"],
            "description": params["TASK2_DESCRIPTION"],
            "run_command": params["TASK2_RUN_COMMAND"],
            "operation": params["TASK2_OPERATION"],
            "reboot_option": params["TASK2_REBOOTOPTION"],
        },
    )

    window3_tasks = register_window_tasks(
        session,
        window_id_response,
        window_target_response,
        account_id,
        3,
        {
            "name": params["TASK3_NAME"],
            "description": params["TASK3_DESCRIPTION"],
            "run_command": params["TASK3_RUN_COMMAND"],
            "operation": params["TASK3_OPERATION"],
            "reboot_option": params["TASK3_REBOOTOPTION"],
        },
    )

    return {
        "window1_tasks": window1_tasks,
        "window2_tasks": window2_tasks,
        "window3_tasks": window3_tasks,
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
    if not parameter_value:
        raise ValueError(f"'{parameter_name}' parameter is missing.")
    elif not re.match(pattern, parameter_value):
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
        LOGGER.info("Deleting Maintenance Windows and Default Host Management Configuration...")
        patchmgmt.disable_patchmgmt(params, boto3_config)

    else:
        for account_id in account_ids:
            window_ids_raw = create_maint_window(params, account_id, regions)
            all_window_ids.append(window_ids_raw["window1_ids"])
            all_window_ids.append(window_ids_raw["window2_ids"])
            all_window_ids.append(window_ids_raw["window3_ids"])
            window_target_response = define_mw_targets(
                params, window_ids_raw["window1_ids"], window_ids_raw["window2_ids"], window_ids_raw["window3_ids"], account_id
            )
            all_window_targets.append(window_target_response)
            all_window_tasks.append(def_mw_tasks(params, window_ids_raw, window_target_response, account_id))
    return {"window_ids": all_window_ids, "window_targets": all_window_targets, "window_tasks": all_window_tasks}


def process_account(account_id: str, params: dict, regions: list) -> Dict:
    """Process create event on Organizations event trigger.

    Args:
        account_id (str): AWS account id
        params (dict): Cloudformation Params
        regions (list): Regions to perform our work in.

    Returns:
        Dict: Dictionary of Window IDs, Targets, and Tasks
    """
    all_window_ids = []
    all_window_targets = []
    all_window_tasks = []

    window_ids_raw = create_maint_window(params, account_id, regions)
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
        params["ROLE_NAME_TO_ASSUME"],
        "sra-patch-mgmt-lambda",
        account_id,
    )
    for region in regions:
        ssmclient = session.client("ssm", region_name=region, config=boto3_config)

        # Check if Window 1 exists
        window1_name = params["MAINTENANCE_WINDOW1_NAME"]
        existing_window1 = ssmclient.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [window1_name]}])
        if existing_window1["WindowIdentities"]:
            window1_id = existing_window1["WindowIdentities"][0]["WindowId"]
            LOGGER.info(f"Maintenance window '{window1_name}' already exists in {account_id}/{region} with ID {window1_id}. Updating...")
            update_maintenance_window(ssmclient, window1_id, params, "MAINTENANCE_WINDOW1")
        else:
            LOGGER.info(f"Maintenance window '{window1_name}' does not exist in {account_id}/{region}. Creating...")
            process_account(account_id, params, [region])

        # Check if Window 2 exists
        window2_name = params["MAINTENANCE_WINDOW2_NAME"]
        existing_window2 = ssmclient.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [window2_name]}])
        if existing_window2["WindowIdentities"]:
            window2_id = existing_window2["WindowIdentities"][0]["WindowId"]
            LOGGER.info(f"Maintenance window '{window2_name}' already exists in {account_id}/{region} with ID {window2_id}. Updating...")
            update_maintenance_window(ssmclient, window2_id, params, "MAINTENANCE_WINDOW2")
        else:
            LOGGER.info(f"Maintenance window '{window2_name}' does not exist in {account_id}/{region}. Creating...")
            process_account(account_id, params, [region])

        # Check if Window 3 exists
        window3_name = params["MAINTENANCE_WINDOW3_NAME"]
        existing_window3 = ssmclient.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [window3_name]}])
        if existing_window3["WindowIdentities"]:
            window3_id = existing_window3["WindowIdentities"][0]["WindowId"]
            LOGGER.info(f"Maintenance window '{window3_name}' already exists in {account_id}/{region} with ID {window3_id}. Updating...")
            update_maintenance_window(ssmclient, window3_id, params, "MAINTENANCE_WINDOW3")
        else:
            LOGGER.info(f"Maintenance window '{window3_name}' does not exist in {account_id}/{region}. Creating...")
            process_account(account_id, params, [region])


def update_maintenance_window(ssmclient: SSMClient, window_id: str, params: dict, window_prefix: str) -> None:
    """
    Update an existing maintenance window with the provided parameters.

    Args:
        ssmclient (SSMClient): AWS Systems Manager client
        window_id (str): ID of the maintenance window to update
        params (dict): CloudFormation parameters
        window_prefix (str): Prefix for the maintenance window parameters (e.g., "MAINTENANCE_WINDOW1")
    """
    window_name: str = params[f"{window_prefix}_NAME"]
    window_description: str = params[f"{window_prefix}_DESCRIPTION"]
    window_schedule: str = params[f"{window_prefix}_SCHEDULE"]
    window_duration = int(params[f"{window_prefix}_DURATION"])
    window_cutoff = int(params[f"{window_prefix}_CUTOFF"])
    window_timezone = params[f"{window_prefix}_TIMEZONE"]

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


def get_validated_parameters(event: Dict[str, Any]) -> dict:  # noqa: CCR001, CFQ001
    """Validate AWS CloudFormation parameters.

    Args:
        event (Dict[str, Any]): event data

    Returns:
        dict: Validated Parameters

    """
    params = event["ResourceProperties"].copy()
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event["RequestType"]]

    # Validate parameters based on patterns
    true_false_pattern = r"(?i)^true|false$"
    text_pattern = r"^[a-zA-Z0-9-_\s]{3,128}$"
    cron_pattern = r"^(rate\(((1 (hour|minute|day))|(\d+(hours|minutes|days)))\))|(cron\(\s*(\d+)\s+(\d+)\s+(\d+)\s+\?\s+\*\s+(MON|TUE|WED|THU|FRI|SAT|SUN)*\s*\*\))$"  # noqa: E501, B950

    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY", ""), pattern=true_false_pattern)
    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), pattern=r"^\d{12}$")
    parameter_pattern_validator("ROLE_NAME_TO_ASSUME", params.get("ROLE_NAME_TO_ASSUME", ""), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", params.get("MANAGEMENT_ACCOUNT_ID", ""), pattern=r"^\d{12}$")
    parameter_pattern_validator("MAINTENANCE_WINDOW1_NAME", params.get("MAINTENANCE_WINDOW1_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW2_NAME", params.get("MAINTENANCE_WINDOW2_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW3_NAME", params.get("MAINTENANCE_WINDOW3_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW1_DESCRIPTION", params.get("MAINTENANCE_WINDOW1_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW2_DESCRIPTION", params.get("MAINTENANCE_WINDOW2_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW3_DESCRIPTION", params.get("MAINTENANCE_WINDOW3_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW1_SCHEDULE", params.get("MAINTENANCE_WINDOW1_SCHEDULE", ""), pattern=cron_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW2_SCHEDULE", params.get("MAINTENANCE_WINDOW2_SCHEDULE", ""), pattern=cron_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW3_SCHEDULE", params.get("MAINTENANCE_WINDOW3_SCHEDULE", ""), pattern=cron_pattern)
    parameter_pattern_validator("MAINTENANCE_WINDOW1_DURATION", params.get("MAINTENANCE_WINDOW1_DURATION", ""), pattern=r"^(1[0-9]|2[0-4]|[1-9])$")
    parameter_pattern_validator("MAINTENANCE_WINDOW2_DURATION", params.get("MAINTENANCE_WINDOW2_DURATION", ""), pattern=r"^(1[0-9]|2[0-4]|[1-9])$")
    parameter_pattern_validator("MAINTENANCE_WINDOW3_DURATION", params.get("MAINTENANCE_WINDOW3_DURATION", ""), pattern=r"^(1[0-9]|2[0-4]|[1-9])$")
    parameter_pattern_validator("MAINTENANCE_WINDOW1_CUTOFF", params.get("MAINTENANCE_WINDOW1_CUTOFF", ""), pattern=r"^([0-9]|1[0-9]|2[0-3])$")
    parameter_pattern_validator("MAINTENANCE_WINDOW2_CUTOFF", params.get("MAINTENANCE_WINDOW2_CUTOFF", ""), pattern=r"^([0-9]|1[0-9]|2[0-3])$")
    parameter_pattern_validator("MAINTENANCE_WINDOW3_CUTOFF", params.get("MAINTENANCE_WINDOW3_CUTOFF", ""), pattern=r"^([0-9]|1[0-9]|2[0-3])$")
    parameter_pattern_validator("MAINTENANCE_WINDOW1_TIMEZONE", params.get("MAINTENANCE_WINDOW1_TIMEZONE", ""), pattern=r"^[a-zA-Z]+(/[a-zA-Z_]+)+$")
    parameter_pattern_validator("MAINTENANCE_WINDOW2_TIMEZONE", params.get("MAINTENANCE_WINDOW2_TIMEZONE", ""), pattern=r"^[a-zA-Z]+(/[a-zA-Z_]+)+$")
    parameter_pattern_validator("MAINTENANCE_WINDOW3_TIMEZONE", params.get("MAINTENANCE_WINDOW3_TIMEZONE", ""), pattern=r"^[a-zA-Z]+(/[a-zA-Z_]+)+$")
    parameter_pattern_validator("TASK1_NAME", params.get("TASK1_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("TASK2_NAME", params.get("TASK2_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("TASK3_NAME", params.get("TASK3_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("TASK1_DESCRIPTION", params.get("TASK1_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("TASK2_DESCRIPTION", params.get("TASK2_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("TASK3_DESCRIPTION", params.get("TASK3_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("TASK1_RUN_COMMAND", params.get("TASK1_RUN_COMMAND", ""), pattern=r"^AWS-UpdateSSMAgent$")
    parameter_pattern_validator("TASK2_RUN_COMMAND", params.get("TASK2_RUN_COMMAND", ""), pattern=r"^AWS-RunPatchBaseline$")
    parameter_pattern_validator("TASK3_RUN_COMMAND", params.get("TASK3_RUN_COMMAND", ""), pattern=r"^AWS-RunPatchBaseline$")
    parameter_pattern_validator("TARGET1_NAME", params.get("TARGET1_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("TARGET2_NAME", params.get("TARGET2_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("TARGET3_NAME", params.get("TARGET3_NAME", ""), pattern=text_pattern)
    parameter_pattern_validator("TARGET1_DESCRIPTION", params.get("TARGET1_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("TARGET2_DESCRIPTION", params.get("TARGET2_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("TARGET3_DESCRIPTION", params.get("TARGET3_DESCRIPTION", ""), pattern=text_pattern)
    parameter_pattern_validator("TARGET1_VALUE_1", params.get("TARGET1_VALUE_1", ""), pattern=r"^Linux$")
    parameter_pattern_validator("TARGET1_VALUE_2", params.get("TARGET1_VALUE_2", ""), pattern=r"^Windows$")
    parameter_pattern_validator("TARGET2_VALUE_1", params.get("TARGET2_VALUE_1", ""), pattern=r"^Windows$")
    parameter_pattern_validator("TARGET3_VALUE_1", params.get("TARGET3_VALUE_1", ""), pattern=r"^Linux$")
    parameter_pattern_validator("DISABLE_PATCHMGMT", params.get("DISABLE_PATCHMGMT", ""), pattern=true_false_pattern)

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
    if request_type.isalnum():
        LOGGER.info(f"{request_type} Event")
    LOGGER.debug(f"Lambda Context: {context}")

    params = get_validated_parameters({"RequestType": event["RequestType"], "ResourceProperties": event["ResourceProperties"]})
    regions = common.get_enabled_regions(
        params.get("ENABLED_REGIONS", ""),
        (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true",
    )
    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    # Check and update existing maintenance windows
    if params["action"] == "Update":
        account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])

        if (params.get("DISABLE_PATCHMGMT", "false")).lower() in "true" and params["action"] == "Update":
            LOGGER.info("Deleting Maintenance Windows and Default Host Management Configuration...")
            patchmgmt.disable_patchmgmt(params, boto3_config)
        else:
            for account in account_ids:
                check_and_update_maintenance_window(params, regions, account)

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
    if request_type.isalnum():
        LOGGER.info(f"{request_type} Event")
    LOGGER.debug(f"Lambda Context: {context}")

    params = get_validated_parameters({"RequestType": event["RequestType"], "ResourceProperties": event["ResourceProperties"]})
    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    if params["action"] == "Remove":
        patchmgmt.cleanup_patchmgmt(params, boto3_config)

    return f"sra-patch_mgmt-{account_id}"


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    params = get_validated_parameters({"RequestType": "Update", "ResourceProperties": os.environ})

    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
    account_ids = common.get_account_ids([], params["DELEGATED_ADMIN_ACCOUNT_ID"])
    for account in account_ids:
        check_and_update_maintenance_window(params, regions, account)


def process_event_organizations(event: dict) -> None:
    """Process Event from AWS Organizations.

    Args:
        event: event data
    """
    params = get_validated_parameters({"RequestType": "Create", "ResourceProperties": os.environ})
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    if event["detail"]["eventName"] == "AcceptHandshake" and event["detail"]["responseElements"]["handshake"]["state"] == "ACCEPTED":
        for party in event["detail"]["responseElements"]["handshake"]["parties"]:
            if party["type"] == "ACCOUNT":
                aws_account_id = party["id"]
                process_account(aws_account_id, params, regions)
                break
    elif event["detail"]["eventName"] == "CreateAccountResult":
        aws_account_id = event["detail"]["serviceEventDetails"]["createAccountStatus"]["accountId"]
        process_account(aws_account_id, params, regions)
    else:
        LOGGER.info("Organization event does not match expected values.")


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        LOGGER.info("...calling helper...")
        helper(event, context)
    elif event.get("source") == "aws.organizations":
        process_event_organizations(event)
    else:
        LOGGER.info("...else...just calling process_event...")
        process_event(event)


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
    boto3_version = boto3.__version__
    LOGGER.info(f"boto3 version: {boto3_version}")
    try:
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None
