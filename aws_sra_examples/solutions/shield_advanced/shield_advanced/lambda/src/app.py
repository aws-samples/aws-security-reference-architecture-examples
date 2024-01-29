"""This script performs operations to enable, configure, and disable shield.

Version: 1.0

'shield_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Optional

import boto3
import common
import shield
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_shield import ShieldClient


LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

UNEXPECTED: str = "Unexpected!"
SERVICE_NAME: str = "shield.amazonaws.com"

helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def process_add_update_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts

    Returns:
        Status
    """
    LOGGER.info("...process_add_update_event")

    if params["action"] == "Add":
        LOGGER.info("...Enable Shield Advanced")
        setup_shield_global(params, accounts)
        LOGGER.info("...ADD_UPDATE_COMPLETE")
        return
    if params["action"] == "Update":
        LOGGER.info("...Update Shield Advanced")
        setup_shield_global(params, accounts)
        LOGGER.info("...ADD_UPDATE_COMPLETE")

    LOGGER.info("...ADD_UPDATE_NO_EVENT")


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({"RequestType": event["RequestType"]})

    excluded_accounts: list = []
    accounts = common.get_active_organization_accounts(excluded_accounts)
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    process_add_update_event(params, regions, accounts)


def parameter_pattern_validator(parameter_name: str, parameter_value: Optional[str], pattern: str, is_optional: bool = False) -> dict:
    """Validate CloudFormation Custom Resource Properties and/or Lambda Function Environment Variables.

    Args:
        parameter_name: CloudFormation custom resource parameter name and/or Lambda function environment variable name
        parameter_value: CloudFormation custom resource parameter value and/or Lambda function environment variable value
        pattern: REGEX pattern to validate against.
        is_optional: Allow empty or missing value when True

    Raises:
        ValueError: Parameter has a value of empty string.
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern

    Returns:
        Validated Parameter
    """
    if parameter_value == "" and not is_optional:
        raise ValueError(f"({parameter_name}) parameter has a value of empty string.")
    elif not parameter_value and not is_optional:
        raise ValueError(f"({parameter_name}) parameter is missing.")
    elif not re.match(pattern, str(parameter_value)):
        raise ValueError(f"({parameter_name}) parameter with value of ({parameter_value})" + f" does not follow the allowed pattern: {pattern}.")
    return {parameter_name: parameter_value}


def get_validated_parameters(event: Dict[str, Any]) -> dict:
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]
    true_false_pattern = r"^true|false$"
    protection_group_id_pattern = r"^[a-zA-Z0-9]{0,64}$|^$"
    protection_group_resource_type_pattern = r"^(CLOUDFRONT_DISTRIBUTION|ROUTE_53_HOSTED_ZONE|ELASTIC_IP_ALLOCATION|CLASSIC_LOAD_BALANCER|APPLICATION_LOAD_BALANCER|GLOBAL_ACCELERATOR)?$|^$"
    protection_group_pattern_pattern = r"^(ALL|ARBITRARY|BY_RESOURCE_TYPE)?$|^$"
    protection_group_aggregation_pattern = r"^(SUM|MEAN|MAX)?$|^$"
    protection_group_members_pattern = r"^arn:aws:.*$|^$"
    protection_group_account_id_pattern = r"^\d{12}$|^$"
    # Required Parameters
    params.update(
        parameter_pattern_validator(
            "AWS_PARTITION",
            os.environ.get("AWS_PARTITION"),
            pattern=r"^(aws[a-zA-Z-]*)?$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "CONFIGURATION_ROLE_NAME",
            os.environ.get("CONFIGURATION_ROLE_NAME"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "SHIELD_ACCOUNTS_TO_PROTECT",
            os.environ.get("SHIELD_ACCOUNTS_TO_PROTECT"),
            pattern=r"^(ALL|(\d{12})(,\s*\d{12})*)$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "RESOURCES_TO_PROTECT",
            os.environ.get("RESOURCES_TO_PROTECT"),
            pattern=r"arn:aws:[a-z0-9-]+:([a-z0-9-]+:){0,2}[0-9]{12}:.+",
        )
    )
    params.update(
        parameter_pattern_validator(
            "CONFIGURE_DRT_TEAM_ACCESS",
            os.environ.get("CONFIGURE_DRT_TEAM_ACCESS"),
            pattern=true_false_pattern,
        )
    )
    params.update(parameter_pattern_validator("SHIELD_AUTO_RENEW", os.environ.get("SHIELD_AUTO_RENEW"), pattern=r"^(ENABLED|DISABLED){1}$"))
    params.update(
        parameter_pattern_validator(
            "SHIELD_DRT_LOG_BUCKETS", os.environ.get("SHIELD_DRT_LOG_BUCKETS"), pattern=r"^(?:[a-zA-Z0-9.\-]{3,63},\s*)*[a-zA-Z0-9.\-]{3,63}$"
        )
    )
    params.update(
        parameter_pattern_validator("SHIELD_DRT_ROLE_NAME", os.environ.get("SHIELD_DRT_ROLE_NAME"), pattern=r"^[a-zA-Z_][a-zA-Z_0-9+=,.@\-/]{0,127}$")
    )
    params.update(
        parameter_pattern_validator(
            "CONTROL_TOWER_REGIONS_ONLY",
            os.environ.get("CONTROL_TOWER_REGIONS_ONLY"),
            pattern=true_false_pattern,
        )
    )
    params.update(
        parameter_pattern_validator(
            "DELEGATED_ADMIN_ACCOUNT_ID",
            os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID"),
            pattern=r"^\d{12}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "MANAGEMENT_ACCOUNT_ID",
            os.environ.get("MANAGEMENT_ACCOUNT_ID"),
            pattern=r"^\d{12}$",
        )
    )

    params.update(
        parameter_pattern_validator(
            "SHIELD_ENABLE_PROACTIVE_ENGAGEMENT", os.environ.get("SHIELD_ENABLE_PROACTIVE_ENGAGEMENT"), pattern=true_false_pattern
        )
    )
    # Optional Parameters
    params.update(
        parameter_pattern_validator(
            "SHIELD_PROACTIVE_ENGAGEMENT_EMAIL",
            os.environ.get("SHIELD_PROACTIVE_ENGAGEMENT_EMAIL"),
            pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "SHIELD_PROACTIVE_ENGAGEMENT_PHONE_NUMBER",
            os.environ.get("SHIELD_PROACTIVE_ENGAGEMENT_PHONE_NUMBER"),
            pattern=r"^\+?[1-9]\d{1,14}$",
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "SHIELD_PROACTIVE_ENGAGEMENT_NOTES",
            os.environ.get("SHIELD_PROACTIVE_ENGAGEMENT_NOTES"),
            pattern=r"^[a-zA-Z0-9\s]+$",
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_0_ID",
            os.environ.get("PROTECTION_GROUP_0_ID"),
            pattern=protection_group_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_0_ACCOUNT_ID",
            os.environ.get("PROTECTION_GROUP_0_ACCOUNT_ID"),
            pattern=protection_group_account_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_0_AGGREGATION",
            os.environ.get("PROTECTION_GROUP_0_AGGREGATION"),
            pattern=protection_group_aggregation_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_0_PATTERN",
            os.environ.get("PROTECTION_GROUP_0_PATTERN"),
            pattern=protection_group_pattern_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_0_RESOURCE_TYPE",
            os.environ.get("PROTECTION_GROUP_0_RESOURCE_TYPE"),
            pattern=protection_group_resource_type_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_0_MEMBERS",
            os.environ.get("PROTECTION_GROUP_0_MEMBERS"),
            pattern=protection_group_members_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_1_ACCOUNT_ID",
            os.environ.get("PROTECTION_GROUP_1_ACCOUNT_ID"),
            pattern=protection_group_account_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_1_ID",
            os.environ.get("PROTECTION_GROUP_1_ID"),
            pattern=protection_group_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_1_AGGREGATION",
            os.environ.get("PROTECTION_GROUP_1_AGGREGATION"),
            pattern=protection_group_aggregation_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_1_PATTERN",
            os.environ.get("PROTECTION_GROUP_1_PATTERN"),
            pattern=protection_group_pattern_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_1_RESOURCE_TYPE",
            os.environ.get("PROTECTION_GROUP_1_RESOURCE_TYPE"),
            pattern=protection_group_resource_type_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_1_MEMBERS",
            os.environ.get("PROTECTION_GROUP_1_MEMBERS"),
            pattern=protection_group_members_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_2_ACCOUNT_ID",
            os.environ.get("PROTECTION_GROUP_0_ACCOUNT_ID"),
            pattern=protection_group_account_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_2_ID",
            os.environ.get("PROTECTION_GROUP_2_ID"),
            pattern=protection_group_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_2_AGGREGATION",
            os.environ.get("PROTECTION_GROUP_2_AGGREGATION"),
            pattern=protection_group_aggregation_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_2_PATTERN",
            os.environ.get("PROTECTION_GROUP_2_PATTERN"),
            pattern=protection_group_pattern_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_2_RESOURCE_TYPE",
            os.environ.get("PROTECTION_GROUP_2_RESOURCE_TYPE"),
            pattern=protection_group_resource_type_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_2_MEMBERS",
            os.environ.get("PROTECTION_GROUP_2_MEMBERS"),
            pattern=protection_group_members_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_3_ACCOUNT_ID",
            os.environ.get("PROTECTION_GROUP_0_ACCOUNT_ID"),
            pattern=protection_group_account_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_3_ID",
            os.environ.get("PROTECTION_GROUP_3_ID"),
            pattern=protection_group_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_3_AGGREGATION",
            os.environ.get("PROTECTION_GROUP_3_AGGREGATION"),
            pattern=protection_group_aggregation_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_3_PATTERN",
            os.environ.get("PROTECTION_GROUP_3_PATTERN"),
            pattern=protection_group_pattern_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_3_RESOURCE_TYPE",
            os.environ.get("PROTECTION_GROUP_3_RESOURCE_TYPE"),
            pattern=protection_group_resource_type_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_3_MEMBERS",
            os.environ.get("PROTECTION_GROUP_3_MEMBERS"),
            pattern=protection_group_members_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_4_ACCOUNT_ID",
            os.environ.get("PROTECTION_GROUP_0_ACCOUNT_ID"),
            pattern=protection_group_account_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_4_ID",
            os.environ.get("PROTECTION_GROUP_4_ID"),
            pattern=protection_group_id_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_4_AGGREGATION",
            os.environ.get("PROTECTION_GROUP_4_AGGREGATION"),
            pattern=protection_group_aggregation_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_4_PATTERN",
            os.environ.get("PROTECTION_GROUP_4_PATTERN"),
            pattern=protection_group_pattern_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_4_RESOURCE_TYPE",
            os.environ.get("PROTECTION_GROUP_4_RESOURCE_TYPE"),
            pattern=protection_group_resource_type_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "PROTECTION_GROUP_4_MEMBERS",
            os.environ.get("PROTECTION_GROUP_4_MEMBERS"),
            pattern=protection_group_members_pattern,
            is_optional=True,
        )
    )
    params.update(
        parameter_pattern_validator(
            "ENABLED_REGIONS",
            os.environ.get("ENABLED_REGIONS"),
            pattern=r"^$|[a-z0-9-, ]+$",
            is_optional=True,
        )
    )
    return params


def teardown_shield_service(params: dict, accounts: list) -> None:
    """Primary function to disable the shield service.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts
    """
    if params["SHIELD_ACCOUNTS_TO_PROTECT"] == "ALL":
        LOGGER.info("Protect all accounts")
    else:
        accounts = []
        for account in params["SHIELD_ACCOUNTS_TO_PROTECT"].split(","):
            accounts.append({"AccountId": account})

    LOGGER.info("Params \n")
    LOGGER.info(params)
    for account in accounts:
        LOGGER.info(f"Disable shield for {account}")
        account_id = account["AccountId"]
        shield.check_if_key_in_object(account_id, shield.RESOURCES_BY_ACCOUNT, "dict")
        account_session: boto3.Session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-configure-shield", account_id)
        teardown_shield(account_session, account_id, params)
        shield.disassociate_drt_role(account_session)
        shield.delete_drt_role(account_session, params["SHIELD_DRT_ROLE_NAME"])


def setup_shield_global(params: dict, accounts: list) -> None:
    """Enable the shield service and configure its global settings.

    Args:
        params: environment variables
        accounts: list of accounts
    """

    LOGGER.info("Params \n")
    LOGGER.info(params)
    if params["SHIELD_ACCOUNTS_TO_PROTECT"] == "ALL":
        LOGGER.info("Protect all accounts")
    else:
        LOGGER.info("")
        accounts = []
        for account in params["SHIELD_ACCOUNTS_TO_PROTECT"].split(","):
            accounts.append({"AccountId": account})
    for account in accounts:
        account_id = account["AccountId"]
        print(account_id)
        shield.check_if_key_in_object(account_id, shield.RESOURCES_BY_ACCOUNT, "dict")

        account_session: boto3.Session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-configure-shield", account_id)
        shield_client: ShieldClient = account_session.client("shield")
        # shield.create_service_linked_role(account_id, params["CONFIGURATION_ROLE_NAME"])
        shield.create_subscription(shield_client)
        role_arn = shield.create_drt_role(account_id, params["SHIELD_DRT_ROLE_NAME"], account_session)
        shield.associate_drt_role(shield_client, role_arn)
        setup_shield(account_session, account_id, params)


def teardown_shield(account_session: boto3.Session, account_id: str, params: dict) -> None:
    """removes the shield configurations but does not cancel the subscription

    Args:
        account_session: boto3 session
        account_id: AWS Account Id
        params: environment variables
    """
    buckets_processed: list = []
    resources_processed: list = []

    LOGGER.info(f"Teardown shield in for account {account_id} in ")
    shield.build_resources_by_account(account_session, params, account_id)
    shield_client = account_session.client("shield")
    shield.disable_proactive_engagement(shield_client)  #

    while len(shield.RESOURCES_BY_ACCOUNT[account_id]["buckets"]) > 0:
        bucket = shield.RESOURCES_BY_ACCOUNT[account_id]["buckets"].pop()
        if bucket not in buckets_processed:
            shield.disassociate_drt_log_bucket(shield_client, bucket)
    while len(shield.RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"]) > 0:
        resource = shield.RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"].pop()
        if resource not in resources_processed:
            # if "::" in resource or region in resource and resource:
            shield.delete_protection(shield_client, resource)
            resources_processed.append(resource)
            # else:
            #     shield.RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"].append(resource)
    shield.delete_protection_group(shield_client, params, account_id)
    shield.update_emergency_contacts(shield_client, params, True)


def setup_shield(account_session: boto3.Session, account_id: str, params: dict) -> None:
    """Setup shield service for the account.

    Args:
        account_session: boto3 session
        account_id: AWS Account Id
        params: environment variables
    """
    buckets_processed: list = []
    resources_processed: list = []

    # for region in regions:
    LOGGER.info(f"setup shield in for account {account_id} in ")
    shield.build_resources_by_account(account_session, params, account_id)
    shield_client = account_session.client("shield")
    # shield.create_subscription(shield_client)
    resources_already_protected = shield.list_protections(shield_client)
    shield.enable_proactive_engagement(shield_client, params)
    while len(shield.RESOURCES_BY_ACCOUNT[account_id]["buckets"]) > 0:
        bucket = shield.RESOURCES_BY_ACCOUNT[account_id]["buckets"].pop()
        if bucket not in buckets_processed:
            shield.associate_drt_log_bucket(shield_client, bucket)
            buckets_processed.append(bucket)
    while len(shield.RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"]) > 0:
        resource = shield.RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"].pop()
        if resource not in resources_already_protected and resource not in resources_processed:
            shield.create_protection(shield_client, resource)
            LOGGER.info(f"Create protection for {resource}")
            # shield.create_protection_group(shield_client, params, account_id)
            resources_processed.append(resource)
            # else:
            #     shield.RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"].append(resource)
    if len(resources_already_protected) > 0 or len(resources_processed) > 0:
        shield.create_protection_group(shield_client, params, account_id)


# COMMENT
@helper.create
@helper.update
@helper.delete
def process_event_cloudformation(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa U100
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)

    params = get_validated_parameters({"RequestType": event["RequestType"]})
    excluded_accounts: list = []
    accounts = common.get_active_organization_accounts(excluded_accounts)
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    if params["action"] in ["Add", "Update"]:
        LOGGER.info("calling process_add_update_event")
        process_add_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable shield from (process_event_cloudformation)")
        teardown_shield_service(params, accounts)

    return f"sra-shield-advanced-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        LOGGER.info("...calling helper...")
        helper(event, context)
        # TODO uncomment line above remove line below
        # process_event_cloudformation(event, context)
    else:
        LOGGER.info("...else...just calling process_event...")
        process_event(event)


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Lambda Handler Started....")
    boto3_version = boto3.__version__
    LOGGER.info(f"boto3 version: {boto3_version}")
    event_info = {"Event": event}
    LOGGER.info(event_info)
    try:
        orchestrator(event, context)
    except Exception as ex:
        LOGGER.exception(ex)
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None


# lambda_handler({"RequestType": "Create"}, {})
# lambda_handler({"RequestType": "Update"}, {})
# lambda_handler({"RequestType": "Delete"}, {})
"""COMMENT"""
