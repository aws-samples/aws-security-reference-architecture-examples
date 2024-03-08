import common
from botocore.config import Config
import logging
import os
# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)


def cleanup_patchmgmt(params:dict, BOTO3_CONFIG: Config) -> None:
    windowInformation = common.get_window_information()
    # use boto3 and assume the role to delete all the tasks inside of maintenance windows, then delete the targets, then delete the windows
    for windowTask in windowInformation["window_tasks"]:
        session = common.assume_role(
            params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
            "sra-patch-mgmt-cleanup",
            windowTask["account_id"],
        )
        LOGGER.info(f"Deleting Maintenance Window Tasks in {windowTask['region']}")
        LOGGER.info(windowTask)
        ssmclient = session.client(
            "ssm", region_name=windowTask["region"], config=BOTO3_CONFIG
        )
        response = ssmclient.deregister_task_from_maintenance_window(
            WindowId=windowTask["windowId"], WindowTaskId=windowTask["windowTaskId"]
        )
        LOGGER.info(response)
    for windowTarget in windowInformation["window_targets"]:
        session = common.assume_role(
            params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
            "sra-patch-mgmt-cleanup",
            windowTarget["account_id"],
        )
        LOGGER.info(f"Deleting Maintenance Window Targets in {windowTarget['region']}")
        LOGGER.info(windowTarget)
        ssmclient = session.client(
            "ssm", region_name=windowTarget["region"], config=BOTO3_CONFIG
        )
        response = ssmclient.deregister_target_from_maintenance_window(
            WindowId=windowTarget["windowId"],
            WindowTargetId=windowTarget["WindowTargetId"],
        )
    for previouslyCreatedWindowId in windowInformation["window_ids"]["windowIds"]:
        session = common.assume_role(
            params.get("ROLE_NAME_TO_ASSUME", "sra-patch-mgmt-configuration"),
            "sra-patch-mgmt-cleanup",
            previouslyCreatedWindowId["account_id"],
        )
        LOGGER.info(
            f"Deleting Maintenance Windows in {previouslyCreatedWindowId['region']}"
        )
        LOGGER.info(previouslyCreatedWindowId)
        ssmclient = session.client(
            "ssm", region_name=previouslyCreatedWindowId["region"], config=BOTO3_CONFIG
        )
        response = ssmclient.delete_maintenance_window(
            WindowId=previouslyCreatedWindowId["windowId"]
        )
