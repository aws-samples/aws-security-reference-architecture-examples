"""This script performs operations to enable, configure, and disable Inspector.

Version: 1.0

'detective_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Optional

import boto3
import common
import detective
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_detective import DetectiveClient
    from mypy_boto3_organizations import OrganizationsClient

LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

UNEXPECTED = "Unexpected!"
SERVICE_NAME = "detective.amazonaws.com"
SNS_PUBLISH_BATCH_MAX = 10

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

    if params["action"] in ["Add", "Update"]:
        LOGGER.info("...Configure Detective")
        setup_detective_global(params, regions, accounts)
        LOGGER.info("...ADD_UPDATE_COMPLETE")
        return

    LOGGER.info("...ADD_UPDATE_NO_EVENT")


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({"RequestType": "Update"})

    excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
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
            "CONTROL_TOWER_REGIONS_ONLY",
            os.environ.get("CONTROL_TOWER_REGIONS_ONLY"),
            pattern=true_false_pattern,
        )
    )
    params.update(
        parameter_pattern_validator(
            "DATASOURCE_PACKAGES",
            os.environ.get("DATASOURCE_PACKAGES"),
            pattern=r"(?i)^((eks_audit|asff_securityhub_finding),?){0,2}(eks_audit|asff_securityhub_finding){1}$"
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

    # Optional Parameters
    params.update(
        parameter_pattern_validator(
            "ENABLED_REGIONS",
            os.environ.get("ENABLED_REGIONS"),
            pattern=r"^$|[a-z0-9-, ]+$",
            is_optional=True,
        )
    )

    return params


def deregister_delegated_administrator(delegated_admin_account_id: str, service_principal: str = SERVICE_NAME) -> None:
    """Deregister the delegated administrator account for the provided service principal within AWS Organizations.

    Args:
        delegated_admin_account_id: Delegated Admin Account
        service_principal: Service Principal
    """
    try:
        LOGGER.info(f"Deregistering the delegated admin {delegated_admin_account_id} for {service_principal}")

        ORG_CLIENT.deregister_delegated_administrator(AccountId=delegated_admin_account_id, ServicePrincipal=service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
        LOGGER.error(
            f"AccountNotRegisteredException: Account ({delegated_admin_account_id}) is not a registered delegated administrator: {error}"
        )


def check_aws_service_access(service_principal: str = SERVICE_NAME) -> bool:
    """Check service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service principal

    Returns:
        True or False
    """
    aws_service_access_enabled = False
    LOGGER.info(f"Checking service access for {service_principal}...")
    try:
        org_svc_response = ORG_CLIENT.list_aws_service_access_for_organization()
        api_call_details = {
            "API_Call": "organizations:ListAwsServiceAccessForOrganization",
            "API_Response": org_svc_response,
        }
        LOGGER.info(api_call_details)

        for service in org_svc_response["EnabledServicePrincipals"]:
            if service["ServicePrincipal"] == service_principal:
                aws_service_access_enabled = True
                return True
    except ORG_CLIENT.exceptions.AccessDeniedException as error:
        LOGGER.error(f"AccessDeniedException: unable to check service access for {service_principal}: {error}")
    return aws_service_access_enabled


def enable_aws_service_access(service_principal: str = SERVICE_NAME) -> None:
    """Enable service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service Principal
    """
    if check_aws_service_access(service_principal) is False:
        try:
            LOGGER.info(f"Enabling service access for {service_principal}")
            ORG_CLIENT.enable_aws_service_access(ServicePrincipal=service_principal)
        except ORG_CLIENT.exceptions.AccessDeniedException as error:
            LOGGER.info(f"Failed to enable service access for {service_principal} in organizations: {error}")
    else:
        LOGGER.info(f"Organizations service access for {service_principal} is already enabled")


def disable_aws_service_access(service_principal: str = SERVICE_NAME) -> None:
    """Disable service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service Principal
    """
    try:
        LOGGER.info(f"Disabling service access for {service_principal}")

        ORG_CLIENT.disable_aws_service_access(ServicePrincipal=service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
        LOGGER.info(f"Service ({service_principal}) does not have organizations access revoked: {error}")


def disable_detective_service(params: dict) -> None:
    """Primary function to remove all components of the inspector sra feature.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts
    """
    LOGGER.info("Demove detective")

    deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

    disable_aws_service_access(SERVICE_NAME)


def build_datasource_param(datasource_packages_param: str) -> list:
    """builds list of datasource packages. Adds required value of DETECTIVE_CORE

    Args:
        datasource_packages_param: input from cfn parameter

    Returns:
        list of datasource packages
    """
    datasource_packages: list = []
    if "ASFF_SECURITYHUB_FINDING".lower() in datasource_packages_param.lower() or "EKS_AUDIT".lower() in datasource_packages_param.lower():
        datasource_packages = datasource_packages_param.split(",")
    datasource_packages.append("DETECTIVE_CORE")
    return datasource_packages


def setup_detective_global(params: dict, regions: list, accounts: list) -> None:
    """Enable the inspector service and configure its global settings.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts
    """
    enable_aws_service_access(SERVICE_NAME)
    detective.create_service_linked_role(
        params["MANAGEMENT_ACCOUNT_ID"],
        params["CONFIGURATION_ROLE_NAME"],
    )

    for account in accounts:
        detective.create_service_linked_role(
            account["AccountId"],
            params["CONFIGURATION_ROLE_NAME"],
        )

    for region in regions:
        setup_detective_in_region(
            region,
            accounts,
            build_datasource_param(params["DATASOURCE_PACKAGES"]),
            params["DELEGATED_ADMIN_ACCOUNT_ID"],
            params["CONFIGURATION_ROLE_NAME"]
        )


def setup_detective_in_region(
    region: str,
    accounts: list,
    datasource_packages: list,
    delegated_admin_account: str,
    configuration_role_name: str
) -> None:
    """Setup of the Detective solution

    Args:
        region: aws region
        accounts: list of accounts and email
        datasource_packages: datasource packages
        delegated_admin_account: delegated admin aws account number
        configuration_role_name: detective configuration role
    """

    detective.register_and_enable_delegated_admin(
        delegated_admin_account,
        region,
    )

    LOGGER.info("Waiting 10 seconds before configuring detective org auto-enable.")
    sleep(10)

    delegated_admin_session = common.assume_role(
        configuration_role_name,
        "sra-org-detective-setup",
        delegated_admin_account,
    )

    detective_delegated_admin_region_client: DetectiveClient = delegated_admin_session.client("detective", region)

    graph_arn = detective.get_graph_arn_from_list_graphs(
        detective_delegated_admin_region_client
    )

    detective.set_auto_enable_detective_in_org(
        region,
        detective_delegated_admin_region_client,
        graph_arn
    )

    detective.create_members(
        accounts,
        detective_delegated_admin_region_client,
        graph_arn
    )

    detective.update_datasource_packages(
        detective_delegated_admin_region_client,
        graph_arn, datasource_packages,
    )


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
    excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
    accounts = common.get_active_organization_accounts(excluded_accounts)
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    if params["action"] in ["Add", "Update"]:
        LOGGER.info("calling process_add_update_event")
        process_add_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable Detective from (process_event_cloudformation)")
        disable_detective_service(params)

    return f"sra-detective-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        LOGGER.info("...calling helper...")
        helper(event, context)
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
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None
