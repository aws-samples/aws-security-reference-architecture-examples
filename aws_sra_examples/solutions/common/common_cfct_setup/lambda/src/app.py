"""Custom Resource to perform the CFCT prerequisites in AWS Organizations.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Literal, Sequence, Union

import boto3
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_organizations.type_defs import TagTypeDef

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)

# Global Variables
ORGANIZATIONS_PAGE_SIZE = 20
ORGANIZATIONS_THROTTLE_PERIOD = 0.2
UNEXPECTED = "Unexpected!"

# Initialize the helper
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def get_org_details() -> dict:
    """Query AWS Organizations, and get info needed to perform the needed tasks.

    Returns:
        Info needed to perform the needed tasks and helper data for custom resource
    """
    org = ORG_CLIENT.describe_organization()["Organization"]
    root_id = ORG_CLIENT.list_roots()["Roots"][0]["Id"]
    return {"OrganizationId": org["Id"], "ManagementAccountId": org["MasterAccountId"], "RootOrganizationalUnitId": root_id}


def get_parent_id(child_id: str) -> str:
    """Identify the OU/root ID of the parent where the given child account/OU resides.

    Args:
        child_id: ID of the OU/account whose parent containers you want to list.

    Returns:
        OU/root ID of the parent of the given OU/account
    """
    response = ORG_CLIENT.list_parents(ChildId=child_id)
    LOGGER.debug({"API_Call": "organizations:ListParents", "API_Response": response})
    return response["Parents"][0]["Id"]


def move_management_account_to_ou(account_id: str, source_parent_id: str, destination_parent_id: str) -> None:
    """Moves the management account to an OU.

    Args:
        account_id: Management account ID
        source_parent_id: ID of root/ou parent where management account currently resides
        destination_parent_id: ID of root/ou parent where you want to move the management account to
    """
    ORG_CLIENT.move_account(AccountId=account_id, SourceParentId=source_parent_id, DestinationParentId=destination_parent_id)
    source = "ROOT"
    destination = "ROOT"
    if not source_parent_id.startswith("r-"):
        source = f"{get_ou_name(ou_id=source_parent_id)} OU"
    if not destination_parent_id.startswith("r-"):
        destination = f"{get_ou_name(ou_id=destination_parent_id)} OU"
    LOGGER.info(
        f"Moved Management Account ({account_id}) successfully from {source} ({source_parent_id}) to the {destination} ({destination_parent_id})."
    )


def get_children(parent_id: str, child_type: Union[Literal["ACCOUNT"], Literal["ORGANIZATIONAL_UNIT"]]) -> dict:
    """List the OUs or accounts that are contained in the parent OU/root.

    Args:
        parent_id: ID for the parent root/OU whose children you want to list.
        child_type: Filters the output to include only the specified child type. (ACCOUNT | ORGANIZATIONAL_UNIT)

    Returns:
        Mapping of OU ID/Name or Account ID/Name
    """
    children = {}
    paginator = ORG_CLIENT.get_paginator("list_children")
    for page in paginator.paginate(ParentId=parent_id, ChildType=child_type, PaginationConfig={"PageSize": ORGANIZATIONS_PAGE_SIZE}):
        for child in page["Children"]:
            if child_type == "ACCOUNT":
                child_name = ORG_CLIENT.describe_account(AccountId=child["Id"])["Account"]["Name"]
            else:
                child_name = ORG_CLIENT.describe_organizational_unit(OrganizationalUnitId=child["Id"])["OrganizationalUnit"]["Name"]
            children[child_name] = child["Id"]
        sleep(ORGANIZATIONS_THROTTLE_PERIOD)
    return children


def get_ou_name(ou_id: str) -> str:
    """Retrieves friendly name of the OU.

    Args:
        ou_id: ID of the organizational unit that you want details about.

    Returns:
        Friendly name of the OU
    """
    response = ORG_CLIENT.describe_organizational_unit(OrganizationalUnitId=ou_id)
    LOGGER.debug({"API_Call": "organizations:DescribeOrganizationalUnit", "API_Response": response})
    return response["OrganizationalUnit"]["Name"]


def create_management_account_ou(ou: str, root_id: str, tags: Sequence[TagTypeDef]) -> str:
    """Create OU where management account will be reside.

    Args:
        ou: OU where management account will reside
        root_id: Root Organizational Unit ID, where OU will reside
        tags: Tags to be applied to the OU

    Returns:
        ID of the OU created
    """
    ou_children = get_children(parent_id=root_id, child_type="ORGANIZATIONAL_UNIT")
    ou_id = ou_children.get(ou)
    if not ou_id:
        response = ORG_CLIENT.create_organizational_unit(ParentId=root_id, Name=ou, Tags=tags)
        LOGGER.debug({"API_Call": "organizations:CreateOrganizationalUnit", "API_Response": response})
        ou_id = response["OrganizationalUnit"]["Id"]
    else:
        LOGGER.info(f"{ou} OU ({ou_id}) already exists.")
    return ou_id


def process_management_account_ou(params: dict) -> dict:
    """Process the tasks needed to move the Management Account into an OU.

    Args:
        params: Parameters needed for the custom resource

    Returns:
        Info needed to create helper data for custom resource
    """
    tags: Sequence[TagTypeDef] = [{"Key": params["TAG_KEY"], "Value": params["TAG_VALUE"]}]
    org_details = get_org_details()
    parent_id = get_parent_id(org_details["ManagementAccountId"])

    if params["MANAGEMENT_ACCOUNT_OU"] == "ROOT":
        ou_id = org_details["RootOrganizationalUnitId"]
        destination = "the ROOT"
    elif params["MANAGEMENT_ACCOUNT_OU"].endswith("-Optional") and parent_id.startswith("ou-"):
        ou_name = get_ou_name(ou_id=parent_id)
        ou_id = "ALREADY_IN_OU"
        destination = f"an OU named {ou_name} ({parent_id})"
    else:
        ou_name = params["MANAGEMENT_ACCOUNT_OU"].removesuffix("-Optional")
        ou_id = create_management_account_ou(ou=ou_name, root_id=org_details["RootOrganizationalUnitId"], tags=tags)
        destination = f"the {params['MANAGEMENT_ACCOUNT_OU']} OU"

    if ou_id in [parent_id, "ALREADY_IN_OU"]:
        LOGGER.info(f"Management Account ({org_details['ManagementAccountId']}) is already in {destination}.")
    else:
        move_management_account_to_ou(account_id=org_details["ManagementAccountId"], source_parent_id=parent_id, destination_parent_id=ou_id)

    return org_details


def parameter_pattern_validator(parameter_name: str, parameter_value: Union[str, None], pattern: str) -> None:
    """Validate CloudFormation Custom Resource Parameters.

    Args:
        parameter_name: CloudFormation custom resource parameter name
        parameter_value: CloudFormation custom resource parameter value
        pattern: REGEX pattern to validate against.

    Raises:
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern
    """
    if not parameter_value:
        raise ValueError(f"'{parameter_name}' parameter is missing.")
    elif not re.match(pattern, parameter_value):
        raise ValueError(f"'{parameter_name}' parameter with value of '{parameter_value}' does not follow the allowed pattern: {pattern}.")


def get_validated_parameters(event: CloudFormationCustomResourceEvent) -> dict:
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = event["ResourceProperties"].copy()
    parameter_pattern_validator("MANAGEMENT_ACCOUNT_OU", params.get("MANAGEMENT_ACCOUNT_OU"), pattern=r"^.{1,128}$")
    parameter_pattern_validator("TAG_KEY", params["TAG_KEY"], pattern=r"^.{1,128}$")
    parameter_pattern_validator("TAG_VALUE", params["TAG_VALUE"], pattern=r"^.{1,256}$")

    return params


@helper.create
@helper.update
def create_update_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa: U100
    """Create/Update Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters(event)

    helper.Data = process_management_account_ou(params)
    return "CFCT"


@helper.delete
def delete_event(event: CloudFormationCustomResourceEvent, context: Context) -> None:  # noqa: U100
    """Delete Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    LOGGER.info("Management Account will not be moved and OU's will not be modified.")


def lambda_handler(event: CloudFormationCustomResourceEvent, context: Context) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    try:
        helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"See the details in CloudWatch Log Stream: '{context.log_group_name}'") from None
