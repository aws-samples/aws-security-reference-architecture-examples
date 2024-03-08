"""
This script performs operations to enable, configure, and disable AWS Systems
Manager Patch Manager.

Version: 1.0
'patchmgr_org' solution in the repo,
https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import common
import patchmgmt
import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Dict

import boto3
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
helper = CfnResource(
    json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120
)

# Global variables
UNEXPECTED = "Unexpected!"
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


def get_account_id() -> str:
    client = boto3.client("sts")
    return client.get_caller_identity()["Account"]




from typing import TypedDict

class MaintInfo(TypedDict):
    windowIds: list

def create_maintenance_window(params:dict, account_id:str, regions:list) -> MaintInfo:
    """
    Create a maintenance window

    Args:
        maintenance_window_name: Name of Maintenance Window to be created
        maintenance_window_description: Description of Maintenance Window to be created
        maintenance_window_duration: How long to run the Maintenance Window for
        maintenance_window_cutoff: Last invocation of Maintenance Window before scheduled time ends
        maintenance_window_timezone: Timezone used to schedule Maintenance Window

    Returns:
        WindowID: Unique ID of the Maintenance Window Created

    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-mwindows",
        account_id,
    )
    windowIds = []
    for region in regions:
        LOGGER.info(
            f"Setting up Default Host Management and Creating a Maint Window {account_id} {region}"
        )
        ssmclient = session.client("ssm", region_name=region, config=BOTO3_CONFIG)
        ssmclient.update_service_setting(
            SettingId="/ssm/managed-instance/default-ec2-instance-management-role",
            SettingValue="service-role/AWSSystemsManagerDefaultEC2InstanceManagementRole",
        )
        maintenance_window_name = params.get("MAINTENANCE_WINDOW_NAME", "")
        maintenance_window_description = params.get("MAINTENANCE_WINDOW_DESCRIPTION", "")
        maintenance_window_schedule = params.get("MAINTENANCE_WINDOW_SCHEDULE", "")
        maintenance_window_duration = int(params.get("MAINTENANCE_WINDOW_DURATION", 120))
        maintenance_window_cutoff = int(params.get("MAINTENANCE_WINDOW_CUTOFF",0))
        maintenance_window_timezone = params.get("MAINTENANCE_WINDOW_TIMEZONE", "")

        maintenance_window = ssmclient.create_maintenance_window(
            Name=maintenance_window_name,
            Description=maintenance_window_description,
            Schedule=maintenance_window_schedule,
            Duration=maintenance_window_duration,
            Cutoff=maintenance_window_cutoff,
            ScheduleTimezone=maintenance_window_timezone,
            AllowUnassociatedTargets=False,
        )
        windowIds.append(
            {
                "region": region,
                "windowId": maintenance_window["WindowId"],
                "account_id": account_id,
            }
        )

    return {"windowIds": windowIds}


class WindowTargetsDictValue(TypedDict):
    region: str
    WindowTargetId: str

class WindowTargetsDict(TypedDict):
    WindowTargetId: WindowTargetsDictValue

def define_maintenance_window_targets(
    params:dict, window_id_response:list, account_id:str
) -> list[dict[str, Any]]:
    """
    Define maintenance window targets

    Args:
        target_name: Name of Target to be created
        tagrte_description: Description of Target to be created
        target_key_value: Tag Key/Value pairs to identify tagged instances in scope

    Returns:
        WindowTargetID: Unique ID of the Targets Created
    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-wtarget",
        account_id,
    )
    windowTargets = []
    for response in window_id_response:
        LOGGER.info(f"Maintenance Window Targets {response['region']}")
        ssmclient = session.client(
            "ssm", region_name=response["region"], config=BOTO3_CONFIG
        )

        # Target Args for SSM Update
        target_name = params.get("TARGET_NAME","")
        target_description = params.get("TARGET_DESCRIPTION","")
        target_key_value_1 = params.get("TARGET_VALUE_1","")
        target_key_value_2 = params.get("TARGET_VALUE_2","")


        maintenance_window_targets = ssmclient.register_target_with_maintenance_window(
            Name=target_name,
            Description=target_description,
            WindowId=response["windowId"],
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
        windowTargets.append(
            {
                "region": response["region"],
                "WindowTargetId": maintenance_window_targets["WindowTargetId"],
                "windowId": response["windowId"],
                "account_id": account_id,
            }
        )
    return windowTargets




def define_maintenance_window_tasks(
    params: dict, window_id_response:list, window_target_response:list, account_id:str
) -> list[dict[str,Any]]:
    """
    Define maintenance window tasks

    Args:
        task_name: Name of Task
        task_description: Decription of Task
        task_run_command: ARN of Run Command Document

    Returns:
        WindowTaskID: Unique ID of the Task Created
    """
    session = common.assume_role(
        params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
        "sra-patch-mgmt-wtasks",
        account_id,
    )
    windowIds = []
    for response in window_id_response:
        LOGGER.info(f"Maintenance Window Tasks in {response['region']}")
        LOGGER.info(response)
        ssmclient = session.client(
            "ssm", region_name=response["region"], config=BOTO3_CONFIG
        )
        # Task Args for SSM Update
        task_name = params.get("TASK_NAME","")
        task_description = params.get("TASK_DESCRIPTION","")
        task_run_command = params.get("TASK_RUN_COMMAND","")

        for response2 in window_target_response:
            LOGGER.info(response2)
            if (
                response2["region"] == response["region"]
            ):  # must match the region up manually so we know the target that got made in that region and match it with the window
                maintenance_window_tasks = ssmclient.register_task_with_maintenance_window(
                    Name=task_name,
                    Description=task_description,
                    WindowId=response["windowId"],
                    Targets=[
                        {
                            "Key": "WindowTargetIds",
                            "Values": [response2["WindowTargetId"]],
                        },
                    ],
                    TaskArn=task_run_command,
                    TaskType="RUN_COMMAND",
                    Priority=1,
                    ServiceRoleArn=f"arn:aws:iam::{account_id}:role/AmazonSSMAutomationRole",
                    CutoffBehavior="CONTINUE_TASK",
                    MaxConcurrency="100",
                    MaxErrors="1",
                    TaskInvocationParameters={
                        "RunCommand": {
                            "Parameters": {
                                # 'Operation': ['Scan'],
                                # 'RebootOption': ['NoReboot'],
                                # 'ServiceRoleArn': ['arn:aws:iam::425869049093:role/AmazonSSMAutomationRole'],
                            },
                            "DocumentVersion": "$DEFAULT",
                            "TimeoutSeconds": 3600,
                            "Comment": "Run SSMUpdate",
                            "DocumentHash": "1cbb9841b99ecbd030312fe61ad155d551eb4cf8527421fda510ec83a270a7c2",
                            "DocumentHashType": "Sha256",
                        },
                    },
                )
                windowIds.append(
                    {
                        "region": response["region"],
                        "windowId": response["windowId"],
                        "windowTaskId": maintenance_window_tasks["WindowTaskId"],
                        "account_id": account_id,
                    }
                )
    return windowIds


def parameter_pattern_validator(
    parameter_name: str, parameter_value: str, pattern: str
) -> None:
    """
    Validate CloudFormation Custom Resource Parameters.

    Args:
        parameter_name: CloudFormation custom resource parameter name
        parameter_value: CloudFormation custom resource parameter value
        pattern: REGEX pattern to validate against.

    Raises:
        ValueError: Parameter does not follow the allowed pattern
    """
    if not re.match(pattern, parameter_value):
        raise ValueError(
            f"'{parameter_name}' parameter with value of '{parameter_value}' does not follow the allowed pattern: {pattern}."
        )


def get_validated_parameters(
    event: CloudFormationCustomResourceEvent,
) -> dict:  # noqa: CCR001 (cognitive complexity)
    """
    Validate AWS CloudFormation parameters.

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
        "MAINTENANCE_WINDOW_NAME",
        params.get("MAINTENANCE_WINDOW_NAME", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW_DESCRIPTION",
        params.get("MAINTENANCE_WINDOW_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW_SCHEDULE",
        params.get("MAINTENANCE_WINDOW_SCHEDULE", ""),
        pattern=r"^[\w\s*?()+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW_DURATION",
        params.get("MAINTENANCE_WINDOW_DURATION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW_CUTOFF",
        params.get("MAINTENANCE_WINDOW_CUTOFF", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MAINTENANCE_WINDOW_TIMEZONE",
        params.get("MAINTENANCE_WINDOW_TIMEZONE", ""),
        pattern=r"^[\w\/+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TASK_NAME", params.get("TASK_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$"
    )
    parameter_pattern_validator(
        "TASK_DESCRIPTION",
        params.get("TASK_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TASK_RUN_COMMAND",
        params.get("TASK_RUN_COMMAND", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TARGET_NAME", params.get("TARGET_NAME", ""), pattern=r"^[\w\s+=,.@-]{1,64}$"
    )
    parameter_pattern_validator(
        "TARGET_DESCRIPTION",
        params.get("TARGET_DESCRIPTION", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TARGET_VALUE_1",
        params.get("TARGET_VALUE_1", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "TARGET_VALUE_2",
        params.get("TARGET_VALUE_2", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )
    parameter_pattern_validator(
        "MANAGEMENT_ACCOUNT_ID",
        params.get("MANAGEMENT_ACCOUNT_ID", ""),
        pattern=r"^[\w\s+=,.@-]{1,64}$",
    )

    return params


def process_create_update_event(params: dict, regions: list) -> Dict:
    """
    Process create update events.

    Args:
        params: input parameters
        regions: AWS regions
    Returns:
        window_ids: Unique IDs of the Maintenance Windows created
        window_targets: Unique IDs of the Targets Created
        window_tasks: Unique ID of the Tasks Created
    """
    account_ids = common.get_account_ids(
        [], params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )  # they updated the stack and want us to remove things. #TODO
    if (params.get("DISABLE_PATCHMGMT", "false")).lower() in "true" and params[
        "action"
    ] == "Update":
        # they updated the stack and want us to remove things.
        patchmgmt.cleanup_patchmgmt(params, BOTO3_CONFIG)

    else:
        for account_id in account_ids:  # across all accounts they desire
            window_ids = create_maintenance_window(params, account_id, regions)
            print(window_ids)

            window_target_response = define_maintenance_window_targets(
                params, window_ids["windowIds"], account_id
            )
            print(window_target_response)

            window_task_response = define_maintenance_window_tasks(
                params, window_ids["windowIds"], window_target_response, account_id
            )
            print(window_task_response)
    return {
        "window_ids": window_ids,
        "window_targets": window_target_response,
        "window_tasks": window_task_response,
    }


@helper.create
@helper.update
@helper.delete
def process_cloudformation_event(
    event: CloudFormationCustomResourceEvent, context: Context
) -> str:
    """
    Process Event from AWS CloudFormation.

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
        response = process_create_update_event(params, regions)
        common.store_window_information(response)
    elif params["action"] == "Remove":
        patchmgmt.cleanup_patchmgmt(LOGGER, params, BOTO3_CONFIG)

    return f"sra-patch_mgmt-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def lambda_handler(event: Dict[str, Any], context: Context) -> None:
    """
    Lambda Handler

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
        helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(
            f"Unexpected error executing Lambda function. Review CloudWatch logs '{context.log_group_name}' for details."
        ) from None
