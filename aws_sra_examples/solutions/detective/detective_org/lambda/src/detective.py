"""This script performs operations to enable, configure, and disable inspector.

Version: 1.0
'inspector2_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import math
import os
from time import sleep
from typing import TYPE_CHECKING

import boto3
import botocore
import common

if TYPE_CHECKING:
    from mypy_boto3_detective import DetectiveClient
    from mypy_boto3_detective.type_defs import (
        CreateMembersResponseTypeDef,
        ListGraphsResponseTypeDef,
        ListMembersResponseTypeDef,
        ListOrganizationAdminAccountsResponseTypeDef,
    )
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_organizations import OrganizationsClient

LOGGER = logging.getLogger("sra")


log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)


UNEXPECTED = "Unexpected!"
EMPTY_STRING = ""
DETECTIVE_THROTTLE_PERIOD = 0.2
ENABLE_RETRY_ATTEMPTS = 10
ENABLE_RETRY_SLEEP_INTERVAL = 10
MAX_RETRY = 5
SLEEP_SECONDS = 10


try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def get_graph_arn_from_list_graphs(detective_client: DetectiveClient) -> str:
    """Get detective graph arn.

    Args:
        detective_client: boto3 detective client

    Raises:
        ValueError: raise exception if a graph isn't found

    Returns:
        Detective's graph arn
    """
    response: ListGraphsResponseTypeDef = detective_client.list_graphs()
    if "GraphList" not in response or len(response["GraphList"]) < 1:
        LOGGER.error(f"No graph found when calling list_graphs. Response: {response}")
        raise ValueError("No graph found.")
    else:
        LOGGER.info(f"Graph arn found: {response['GraphList'][0]['Arn']}")
        return response["GraphList"][0]["Arn"]


def is_admin_account_enabled(detective_client: DetectiveClient, admin_account_id: str) -> bool:
    """Is admin account enabled.

    Args:
        detective_client: DetectiveClient
        admin_account_id: Admin Account ID

    Returns:
        True or False
    """
    paginator: botocore.paginate.Paginator = detective_client.get_paginator("list_organization_admin_accounts")
    for page in paginator.paginate():
        for admin_account in page["Administrators"]:
            if admin_account["AccountId"] == admin_account_id:
                return True
        sleep(DETECTIVE_THROTTLE_PERIOD)
    return False


def disable_organization_admin_account(regions: list) -> None:
    """Disable the organization admin account.

    Args:
        regions: AWS Region List
    """
    for region in regions:
        detective_client: DetectiveClient = MANAGEMENT_ACCOUNT_SESSION.client("detective", region)
        response = detective_client.disable_organization_admin_account()
        api_call_details = {"API_Call": "detective:DisableOrganizationAdminAccount", "API_Response": response}
        LOGGER.info(api_call_details)
        LOGGER.info(f"Admin Account Disabled in {region}")
        sleep(DETECTIVE_THROTTLE_PERIOD)


def check_organization_admin_enabled(detective_client: DetectiveClient) -> bool:
    """Check if the organization admin account is already enabled and matches the delegated admin from the parameter.

    Args:
        detective_client: boto3 Detective Client

    Returns:
        True or False
    """
    response: ListOrganizationAdminAccountsResponseTypeDef = detective_client.list_organization_admin_accounts()
    api_call_details: dict = {"API_Call": "detective:ListOrganizationAdminAccountsResponseTypeDef", "API_Response": response}

    LOGGER.info(api_call_details)
    if len(response["Administrators"]) == 0:
        return False
    return True


def register_and_enable_delegated_admin(admin_account_id: str, region: str) -> None:
    """Set the delegated admin account for the given region.

    Args:
        admin_account_id: Admin account ID
        region: AWS Region

    Raises:
        Exception: Generic Exception
    """
    detective_client: DetectiveClient = MANAGEMENT_ACCOUNT_SESSION.client("detective", region)
    try:
        if not check_organization_admin_enabled(detective_client):
            LOGGER.info(f"Enabling detective admin account {admin_account_id} in region {region}")
            delegated_admin_response = detective_client.enable_organization_admin_account(AccountId=admin_account_id)
            api_call_details = {"API_Call": "detective:EnableOrganizationAdminAccount", "API_Response": delegated_admin_response}
            LOGGER.info(api_call_details)
    except Exception as e:
        LOGGER.error(f"Error calling EnableOrganizationAdminAccount {e}. For account {admin_account_id}) in {region}")
        raise


def set_auto_enable_detective_in_org(
    region: str,
    detective_client: DetectiveClient,
    graph_arn: str,
) -> None:
    """Set auto enable for detective in organizations.

    Args:
        region: AWS Region
        detective_client: boto3 Detective client
        graph_arn: detective's graph arn

    Raises:
        Exception: Generic Exception
    """
    try:
        LOGGER.info(f"configuring auto-enable detective update_organization_configuration in region {region}, for graph {graph_arn}")
        update_organization_configuration_response = detective_client.update_organization_configuration(AutoEnable=True, GraphArn=graph_arn)
        api_call_details = {
            "API_Call": "Detective:UpdateOrganizationConfiguration",
            "API_Response": update_organization_configuration_response,
        }
        LOGGER.info(api_call_details)
        LOGGER.info(f"detective organization auto-enable configuration updated in {region}")
    except Exception as e:
        LOGGER.error(f"Error calling UpdateOrganizationConfiguration {e}.\n Graph arn: {graph_arn}, region {region}")
        raise


def get_unprocessed_account_details(create_members_response: CreateMembersResponseTypeDef, accounts: list) -> list:
    """Get unprocessed account details.

    Args:
        create_members_response: CreateMembersResponseTypeDef
        accounts: list

    Raises:
        ValueError: Internal Error creating member accounts

    Returns:
        remaining account list
    """
    remaining_accounts = []

    for unprocessed_account in create_members_response["UnprocessedAccounts"]:
        if "error" in unprocessed_account["Reason"]:
            LOGGER.error(f"{unprocessed_account}")
            raise ValueError(f"Internal Error creating member accounts: {unprocessed_account['Reason']}") from None
        for account_record in accounts:
            LOGGER.info(f"Unprocessed Account {unprocessed_account}")
            if account_record["AccountId"] == unprocessed_account["AccountId"] and unprocessed_account["Reason"] != "Account is already a member":
                remaining_accounts.append(account_record)
    return remaining_accounts


def get_detective_member_accounts(  # noqa S107
    detective_client: DetectiveClient, graph_arn: str, next_token: str = EMPTY_STRING, members: list = None
) -> list:
    """Get Detective's member accounts with a status of Enabled.

    Args:
        detective_client: boto3 Detective Client
        graph_arn: Detective's graph arn
        next_token: Next token for truncated API results. Defaults to ''.
        members: accounts that are members of Detective. Defaults to None.

    Returns:
        accounts that are members of Detective
    """
    response: ListMembersResponseTypeDef
    if members is None:
        members = []
    if next_token != EMPTY_STRING:
        response = detective_client.list_members(GraphArn=graph_arn, MaxResults=200, NextToken=next_token)
    else:
        response = detective_client.list_members(GraphArn=graph_arn, MaxResults=10)
    for member in response["MemberDetails"]:
        if member["Status"] == "ENABLED":
            members.append(member["AccountId"])
    if "NextToken" in response:
        get_detective_member_accounts(detective_client, graph_arn, response["NextToken"], members)

    return members


def get_members_to_add(detective_client: DetectiveClient, graph_arn: str, accounts: list) -> list:
    """Check which accounts in the organization aren't members of Detective.

    Args:
        detective_client: boto3 Detective client
        graph_arn: Detective's graph arn
        accounts: all accounts in the organization

    Returns:
        Organization accounts that are not members of Detective
    """
    LOGGER.info("get_members_to_add begin")
    members_to_add: list = []
    confirmed_members: list = get_detective_member_accounts(detective_client, graph_arn)

    for account in accounts:
        if account["AccountId"] not in confirmed_members:
            LOGGER.info(f"Account {account['AccountId']} is a member of the Organization but not a member of Detective, adding...")
            members_to_add.append({"AccountId": account["AccountId"], "EmailAddress": account["Email"]})
        else:
            LOGGER.info(f"Account {account['AccountId']} is already a member of Detective")
    LOGGER.info("get_members_to_add end")
    return members_to_add


def create_members(accounts_info: list, detective_client: DetectiveClient, graph_arn: str) -> None:  # noqa: CCR001 (cognitive complexity)
    """Create members for Detective.

    Args:
        accounts_info: [{"AccountId": "Value", "EmailAddress": "Value"]
        detective_client: boto3 detective client object
        graph_arn: Detective's graph arn

    Raises:
        ValueError: Unprocessed accounts
    """
    accounts_info = get_members_to_add(detective_client, graph_arn, accounts_info)
    number_of_create_members_calls = math.ceil(len(accounts_info) / 50)
    for api_call_number in range(0, number_of_create_members_calls):
        account_details = accounts_info[api_call_number * 50 : (api_call_number * 50) + 50]
        create_members_response: CreateMembersResponseTypeDef = detective_client.create_members(
            GraphArn=graph_arn, DisableEmailNotification=True, Accounts=account_details
        )
        api_call_details = {
            "API_Call": "Detective:CreateMembers",
            "API_Response": create_members_response,
        }
        LOGGER.info(api_call_details)

        if "UnprocessedAccounts" in create_members_response and create_members_response["UnprocessedAccounts"]:
            unprocessed = True
            retry_count = 0
            unprocessed_accounts: list = []
            LOGGER.info(f"Sleeping for {SLEEP_SECONDS} before retry")
            sleep(SLEEP_SECONDS)
            while unprocessed:
                retry_count += 1
                LOGGER.info(f"Retry number; {retry_count} for unprocessed accounts")
                LOGGER.info(f"Unprocessed Accounts: {create_members_response['UnprocessedAccounts']}")
                remaining_accounts = get_unprocessed_account_details(create_members_response, account_details)

                if remaining_accounts:
                    LOGGER.info(f"Remaining accounts found during create members {remaining_accounts}")
                    create_members_response = detective_client.create_members(
                        GraphArn=graph_arn, DisableEmailNotification=True, Accounts=remaining_accounts
                    )
                    api_call_details["API_Response"] = create_members_response
                    LOGGER.info(api_call_details)

                if retry_count >= MAX_RETRY:
                    LOGGER.info("max retry reached")
                    unprocessed = False
            if unprocessed_accounts:
                LOGGER.info(f"Unprocessed Member Accounts: {unprocessed_accounts}")
                raise ValueError("Unprocessed Member Accounts while Creating Members")


def update_datasource_packages(detective_client: DetectiveClient, graph_arn: str, packages: list) -> None:
    """Start or stop datasource packages.

    Args:
        detective_client: boto3 Detective client
        graph_arn: Detective's graph arn
        packages: packages to start  ["DETECTIVE_CORE", "EKS_AUDIT", "ASFF_SECURITYHUB_FINDING"]
    """
    LOGGER.info(f"update_datasource_packages params graph_arn {graph_arn}, packages {packages}")
    response = detective_client.update_datasource_packages(GraphArn=graph_arn, DatasourcePackages=packages)
    api_call_details = {"API_Call": "Detective:UpdateDatasourcePackages", "API_Response": response}
    LOGGER.info(api_call_details)


def create_service_linked_role(account_id: str, configuration_role_name: str) -> None:
    """Create service linked role in the given account.

    Args:
        account_id (str): Account ID
        configuration_role_name (str): IAM configuration role name
    """
    LOGGER.info(f"creating service linked role for account {account_id}")
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-detective_create-srl", account_id)
    iam_client: IAMClient = account_session.client("iam")
    common.create_service_linked_role(
        "AWSServiceRoleForDetective",
        "detective.amazonaws.com",
        "A service-linked role required for Amazon Detective to access your resources.",
        iam_client,
    )
