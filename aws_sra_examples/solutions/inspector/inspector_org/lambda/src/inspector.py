"""This script performs operations to enable, configure, and disable inspector.

Version: 1.0
'inspector2_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from time import sleep
from typing import TYPE_CHECKING, Any, Literal

import boto3
import common

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_inspector2 import Inspector2Client, ListDelegatedAdminAccountsPaginator
    from mypy_boto3_inspector2.type_defs import (
        AssociateMemberResponseTypeDef,
        AutoEnableTypeDef,
        DescribeOrganizationConfigurationResponseTypeDef,
        DisableResponseTypeDef,
        DisassociateMemberResponseTypeDef,
    )
    from mypy_boto3_organizations import OrganizationsClient

LOGGER = logging.getLogger("sra")


log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)


UNEXPECTED = "Unexpected!"
INSPECTOR_THROTTLE_PERIOD = 0.2
ENABLE_RETRY_ATTEMPTS = 10
ENABLE_RETRY_SLEEP_INTERVAL = 10

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def is_admin_account_enabled(inspector_client: Inspector2Client, admin_account_id: str) -> bool:
    """Is admin account enabled.

    Args:
        inspector_client: Inspector2Client
        admin_account_id: Admin Account ID

    Returns:
        True or False
    """
    paginator: ListDelegatedAdminAccountsPaginator = inspector_client.get_paginator("list_delegated_admin_accounts")
    for page in paginator.paginate():
        for admin_account in page["delegatedAdminAccounts"]:
            if admin_account["accountId"] == admin_account_id and admin_account["status"] == "ENABLED":
                return True
        sleep(INSPECTOR_THROTTLE_PERIOD)
    return False


def disable_organization_admin_account(regions: list) -> None:
    """Disable the organization admin account.

    Args:
        regions: AWS Region List
    """
    for region in regions:
        inspector_client: Inspector2Client = MANAGEMENT_ACCOUNT_SESSION.client("inspector2", region)
        paginator: ListDelegatedAdminAccountsPaginator = inspector_client.get_paginator("list_delegated_admin_accounts")
        for page in paginator.paginate():
            for admin_account in page["delegatedAdminAccounts"]:
                if admin_account["status"] == "ENABLED":
                    response = inspector_client.disable_delegated_admin_account(delegatedAdminAccountId=admin_account["accountId"])
                    api_call_details = {"API_Call": "inspector2:DisableDelegatedAdminAccount", "API_Response": response}
                    LOGGER.info(api_call_details)
                    LOGGER.info(f"Admin Account {admin_account['accountId']} Disabled in {region}")
            sleep(INSPECTOR_THROTTLE_PERIOD)


def disable_inspector_in_associated_member_accounts(
    delegated_admin_account_id: str, configuration_role_name: str, regions: list, scan_components: list
) -> None:
    """Disable inspector in the associated member accounts.

    Args:
        delegated_admin_account_id: Delegate admin account ID
        configuration_role_name: Inspector configuration Role Name
        regions: AWS Region List
        scan_components: List of scan components
    """
    LOGGER.info(f"disable_inspector_in_associated_member_accounts: scan_components - ({scan_components})")
    account_session = common.assume_role(configuration_role_name, "sra-disable-inspector", delegated_admin_account_id)
    LOGGER.info(f"creating session to disassociate members role name: {configuration_role_name} account id {delegated_admin_account_id}")
    org_response = ORG_CLIENT.list_accounts()
    for region in regions:
        inspector2_delegated_admin_client: Inspector2Client = account_session.client("inspector2", region)
        for acct in org_response["Accounts"]:
            if lookup_associated_accounts(inspector2_delegated_admin_client, acct["Id"]) is True:
                LOGGER.info(acct["Id"] + ", " + acct["Name"] + ", MEMBER")
                disable_inspector2_response = disable_inspector2(inspector2_delegated_admin_client, acct["Id"], scan_components)
                LOGGER.info(disable_inspector2_response)
                disassociate_member_return = disassociate_member(inspector2_delegated_admin_client, acct["Id"])
                LOGGER.info(disassociate_member_return)
            else:
                LOGGER.info(acct["Id"] + ", " + acct["Name"] + ", DISASSOCIATED")


def lookup_associated_accounts(inspector2_client: Inspector2Client, account_id: str) -> bool:
    """Determine if the account is an associated member of the delegated admin inspector configuration.

    Args:
        inspector2_client: Inspector2 client
        account_id: Account ID

    Returns:
        bool: relationship status enabled true/false

    Raises:
        Exception: raises exception as e
    """
    try:
        response = inspector2_client.get_member(accountId=account_id)
    except inspector2_client.exceptions.ResourceNotFoundException:
        return False
    except Exception as e:
        LOGGER.error(f"Failed to get inspector members. {e}")
        raise
    if response["member"]["accountId"] == account_id:
        LOGGER.info(f"{account_id} relationship status: {response['member']['relationshipStatus']}")
        if response["member"]["relationshipStatus"] != "ENABLED":
            associate_account(inspector2_client, account_id)
        return True
    return False


def disassociate_member(inspector2_delegated_admin_client: Inspector2Client, account_id: str) -> DisassociateMemberResponseTypeDef:
    """Disassociate a member account from the delegated admin inspector configuration.

    Args:
        inspector2_delegated_admin_client: Inspector2 client for delegated admin account
        account_id: Account ID

    Returns:
        DisassociateMemberResponseTypeDef: inspector2 API response
    """
    associate_response: DisassociateMemberResponseTypeDef = inspector2_delegated_admin_client.disassociate_member(accountId=account_id)
    return associate_response


def enable_inspector2(inspector2_client: Inspector2Client, account_id: str, region: str, scan_components: list) -> None:
    """Enable inspector in the given account in the given region.

    Args:
        inspector2_client: Inspector2 client
        account_id: Account ID
        region: Region
        scan_components: list of scan components
    """
    LOGGER.info(f"enable_inspector2: scan_components - ({scan_components})")
    for attempt_iteration in range(1, ENABLE_RETRY_ATTEMPTS):
        if get_inspector_status(inspector2_client, account_id, scan_components) != "enabled":
            LOGGER.info(f"Attempt {attempt_iteration} - enabling inspector in the ({account_id}) account in {region}...")
            try:
                enable_inspector_response: Any = inspector2_client.enable(
                    accountIds=[
                        account_id,
                    ],
                    resourceTypes=scan_components,
                )
                api_call_details = {"API_Call": "inspector:Enable", "API_Response": enable_inspector_response}
                LOGGER.info(api_call_details)
            except inspector2_client.exceptions.ConflictException:
                LOGGER.info(f"inspector already enabled in {account_id} {region}")
        else:
            LOGGER.info(f"Inspector is enabled in the {account_id} account in {region}")
            break
        sleep(ENABLE_RETRY_SLEEP_INTERVAL)


def set_inspector_delegated_admin_in_mgmt(admin_account_id: str, region: str) -> None:
    """Set the delegated admin account for the given region.

    Args:
        admin_account_id: Admin account ID
        region: AWS Region

    Raises:
        Exception: inspector2_client.exceptions.ConflictException or e Error
    """
    inspector2_client: Inspector2Client = MANAGEMENT_ACCOUNT_SESSION.client("inspector2", region)
    if not is_admin_account_enabled(inspector2_client, admin_account_id):
        try:
            delegated_admin_response = inspector2_client.enable_delegated_admin_account(delegatedAdminAccountId=admin_account_id)
            api_call_details = {"API_Call": "inspector:EnableDelegatedAdminAccount", "API_Response": delegated_admin_response}
            LOGGER.info(api_call_details)
            LOGGER.info(f"Delegated admin ({admin_account_id}) enabled in {region}")
        except inspector2_client.exceptions.ConflictException:
            LOGGER.info(f"Delegated admin already enabled in {region}")
        except Exception as e:
            LOGGER.error(f"Failed to enable delegated admin. {e}")
            raise


def disable_inspector2(inspector2_client: Inspector2Client, account_id: str, scan_components: list) -> DisableResponseTypeDef:
    """Disable inspector for the given account.

    Args:
        inspector2_client: Inspector2 client
        account_id: Account ID
        scan_components: list of scan components

    Returns:
        DisableResponseTypeDef: inspector2 client api response
    """
    LOGGER.info(f"disable_inspector2: scan_components - ({scan_components})")
    disable_inspector_response = inspector2_client.disable(
        accountIds=[
            account_id,
        ],
        resourceTypes=scan_components,
    )
    return disable_inspector_response  # noqa: R504


def check_inspector_org_auto_enabled(inspector2_delegated_admin_client: Inspector2Client) -> int:
    """Describe autoEnable configuration settings for the organization to ensure it is configured properly.

    Args:
        inspector2_delegated_admin_client: Inspector2 client for delegated admin account

    Returns:
        int: sum of autoEnabled components
    """
    describe_org_conf_response: DescribeOrganizationConfigurationResponseTypeDef = (
        inspector2_delegated_admin_client.describe_organization_configuration()
    )
    org_config_ec2_auto_enabled = 0
    org_config_ecr_auto_enabled = 0
    org_config_lambda_auto_enabled = 0
    org_config_lambda_code_auto_enabled = 0
    if "ec2" in describe_org_conf_response["autoEnable"] and describe_org_conf_response["autoEnable"]["ec2"] is True:
        org_config_ec2_auto_enabled = 1
        LOGGER.info("Organization inspector scanning for ec2 is already configured to be auto-enabled")
    if "ecr" in describe_org_conf_response["autoEnable"] and describe_org_conf_response["autoEnable"]["ecr"] is True:
        org_config_ecr_auto_enabled = 1
        LOGGER.info("Organization inspector scanning for ecr is already configured to be auto-enabled")
    if "lambda" in describe_org_conf_response["autoEnable"] and describe_org_conf_response["autoEnable"]["lambda"] is True:
        org_config_lambda_auto_enabled = 1
        LOGGER.info("Organization inspector scanning for lambda is already configured to be auto-enabled")
    if "lambdaCode" in describe_org_conf_response["autoEnable"] and describe_org_conf_response["autoEnable"]["lambdaCode"] is True:
        org_config_lambda_code_auto_enabled = 1
        LOGGER.info("Organization inspector scanning for lambda code is already configured to be auto-enabled")
    return org_config_ec2_auto_enabled + org_config_ecr_auto_enabled + org_config_lambda_auto_enabled + org_config_lambda_code_auto_enabled


def disable_auto_scanning_in_org(delegated_admin_account_id: str, configuration_role_name: str, regions: list) -> None:
    """Disable auto-enable setting in org for ec2, ec2, lambda and lambdaCode.

    Args:
        regions: AWS Region List
        delegated_admin_account_id: Delegated Admin Account ID
        configuration_role_name: Configuration Role Name
    """
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(f"open session {configuration_role_name} and account id {delegated_admin_account_id} to disable auto-enablement of inspector in org")
    for region in regions:
        inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)
        if check_inspector_org_auto_enabled(inspector_delegated_admin_region_client) > 0:
            LOGGER.info(f"disabling inspector scanning auto-enable in region {region}")
            update_organization_configuration_response = inspector_delegated_admin_region_client.update_organization_configuration(
                autoEnable={"ec2": False, "ecr": False, "lambda": False, "lambdaCode": False}
            )
            api_call_details = {"API_Call": "inspector:UpdateOrganizationConfiguration", "API_Response": update_organization_configuration_response}
            LOGGER.info(api_call_details)
            LOGGER.info(f"inspector organization configuration updated (disabled scanning) in {region}")


def get_inspector_status(inspector2_client: Inspector2Client, account_id: str, scan_components: list) -> str:
    """Fetch the enablement status of inspector in an AWS account.

    Args:
        inspector2_client: Inspector2 client
        account_id: Account ID
        scan_components: list of scan components

    Returns:
        Inspector status (enabled/disabled)
    """
    LOGGER.info(f"get_inspector_status: scan_components - ({scan_components})")
    LOGGER.info(f"Checking inspector service status for {account_id} account...")
    enabled_components = 0
    inspector_status_response = inspector2_client.batch_get_account_status(accountIds=[account_id])
    api_call_details = {"API_Call": "inspector:BatchGetAccountStatus", "API_Response": inspector_status_response}
    LOGGER.info(api_call_details)
    for status in inspector_status_response["accounts"]:
        if status["state"]["status"] == "ENABLED":
            LOGGER.info(f"Status: {status['state']['status']}")
            for scan_component in scan_components:
                LOGGER.info(f"{scan_component} status: {status['resourceState'][common.snake_to_camel(scan_component)]['status']}")  # type: ignore
                if status["resourceState"][common.snake_to_camel(scan_component)]["status"] != "ENABLED":  # type: ignore
                    LOGGER.info(f"{scan_component} scan component is disabled...")
                else:
                    LOGGER.info(f"{scan_component} scan component is enabled...")
                    enabled_components = enabled_components + 1
        else:
            inspector_status = "disabled"
            return inspector_status
    if 0 < enabled_components < len(scan_components):
        inspector_status = "partial"
    elif enabled_components == len(scan_components):
        inspector_status = "enabled"
    else:
        inspector_status = "disabled"
    return inspector_status


def check_scan_component_enablement_for_accounts(
    all_accounts: list, delegated_admin_account_id: str, disabled_components: list, configuration_role_name: str, region: str
) -> None:
    """Check for scan components that should be disabled in the active configuration.

    Args:
        all_accounts: list of all accounts
        delegated_admin_account_id: delegated admin account Id
        disabled_components: list of scan components that should be disabled
        region: AWS region
        configuration_role_name: configuration role name
    """
    LOGGER.info(f"check_scan_component_enablement_for_accounts: disabled components - ({disabled_components})")
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(f"creating delegated admin session with ({configuration_role_name}) and account ({delegated_admin_account_id}) to disable inspector")
    inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)

    for account in all_accounts:
        check_for_updates_to_scan_components(inspector_delegated_admin_region_client, account, disabled_components)


def check_for_updates_to_scan_components(inspector2_client: Inspector2Client, account_id: str, disabled_components: list) -> None:
    """Fetch the enablement status of inspector in an AWS account.

    Args:
        inspector2_client: Inspector2 client
        account_id: Account ID
        disabled_components: list of scan components that should be disabled
    """
    LOGGER.info(f"check_for_updates_to_scan_components: disabled components - ({disabled_components}) - in account ({account_id})")
    LOGGER.info(f"Checking inspector service status for {account_id} account...")
    disablement: bool = False
    inspector_status_response = inspector2_client.batch_get_account_status(accountIds=[account_id])
    api_call_details = {"API_Call": "inspector:BatchGetAccountStatus", "API_Response": inspector_status_response}
    LOGGER.info(api_call_details)
    for status in inspector_status_response["accounts"]:
        if status["state"]["status"] == "ENABLED":
            LOGGER.info(f"Status: {status['state']['status']}")
            for scan_component in disabled_components:
                LOGGER.info(f"{scan_component} status: {status['resourceState'][scan_component]['status']}")  # type: ignore
                if status["resourceState"][scan_component]["status"] != "ENABLED":  # type: ignore
                    LOGGER.info(f"{scan_component} scan component is disabled...")
                else:
                    LOGGER.info(f"{scan_component} scan component is enabled (disablement required)...")
                    disablement = True
    if disablement is True:
        LOGGER.info("Disabling some scan components...")
        disable_inspector2(
            inspector2_client, account_id, [common.camel_to_snake_upper(disabled_component) for disabled_component in disabled_components]
        )


def enable_inspector2_in_mgmt_and_delegated_admin(
    region: str, configuration_role_name: str, mgmt_account_id: str, delegated_admin_account_id: str, scan_components: list
) -> None:
    """Enable inspector in management and delegated admin accounts.

    Args:
        region: AWS Region
        delegated_admin_account_id: Delegated Admin Account ID
        mgmt_account_id: Management Account ID
        configuration_role_name: Configuration Role Name
        scan_components: list of scan components
    """
    LOGGER.info(f"enable_inspector2_in_mgmt_and_delegated_admin: scan_components - ({scan_components})")
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(f"creating delegated admin session with ({configuration_role_name}) and account ({delegated_admin_account_id}) to enable inspector")
    inspector_management_region_client: Inspector2Client = MANAGEMENT_ACCOUNT_SESSION.client("inspector2", region)
    LOGGER.info(f"client region: {inspector_management_region_client.meta.region_name}")
    LOGGER.info(f"enabling inspector in the management account ({mgmt_account_id}) in {region}...")
    enable_inspector2(inspector_management_region_client, mgmt_account_id, region, scan_components)
    inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)
    LOGGER.info(f"enabling inspector in the delegated admin account ({delegated_admin_account_id}) in {region}...")
    enable_inspector2(inspector_delegated_admin_region_client, delegated_admin_account_id, region, scan_components)


def enable_inspector2_in_member_accounts(
    region: str, configuration_role_name: str, delegated_admin_account_id: str, scan_components: list, accounts: list
) -> None:
    """Enable inspector in member accounts.

    Args:
        region: AWS Region
        configuration_role_name: Configuration Role Name
        scan_components: list of scan components
        accounts: list of AWS member accounts
        delegated_admin_account_id: delegated admin account id
    """
    LOGGER.info(f"enable_inspector2_in_member_accounts: scan_components - ({scan_components})")
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(f"creating delegated admin session with ({configuration_role_name}) and account ({delegated_admin_account_id}) to enable inspector")
    inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)
    for account in accounts:
        LOGGER.info(f"enabling inspector in the member account ({account['AccountId']}) in {region}...")
        enable_inspector2(inspector_delegated_admin_region_client, account["AccountId"], region, scan_components)


def set_ecr_scan_duration(
    region: str, configuration_role_name: str, delegated_admin_account_id: str, ecr_scan_duration: Literal["DAYS_180", "DAYS_30", "LIFETIME"]
) -> None:
    """Set the ECR scan duration in the delegated administrator account.

    Args:
        configuration_role_name: configuration role name
        delegated_admin_account_id: delegated admin account id
        ecr_scan_duration: ecr scan duration
        region: AWS region

    Returns:
        dict: API response
    """
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(
        f"creating delegated admin session with ({configuration_role_name}) in account ({delegated_admin_account_id}) to set ecr scan duration"
    )
    inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)
    LOGGER.info(f"Setting ECR scan duration in delegated admin account to {ecr_scan_duration} in {region}")
    LOGGER.info(f"delegated admin client region: {inspector_delegated_admin_region_client.meta.region_name}")
    LOGGER.info(f"Region: {delegated_admin_session.region_name}")
    sts_client = delegated_admin_session.client("sts", region_name=region)
    LOGGER.info(f"caller identity: {sts_client.get_caller_identity()}")
    configuration_response: dict = inspector_delegated_admin_region_client.update_configuration(
        ecrConfiguration={"rescanDuration": ecr_scan_duration}
    )
    api_call_details = {"API_Call": "inspector:UpdateConfiguration", "API_Response": configuration_response}
    LOGGER.info(api_call_details)
    return


def set_ec2_scan_mode(
    region: str, configuration_role_name: str, delegated_admin_account_id: str, ec2_scan_mode: Literal["EC2_SSM_AGENT_BASED", "EC2_HYBRID"]
) -> None:
    """Set the EC2 scan mode in the delegated administrator account.

    Args:
        configuration_role_name: configuration role name
        delegated_admin_account_id: delegated admin account id
        ec2_scan_mode: ec2 scan mode
        region: AWS region

    Returns:
        dict: API response
    """
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(
        f"creating delegated admin session with ({configuration_role_name}) in account ({delegated_admin_account_id}) to set ec2 scan mode"
    )
    inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)
    LOGGER.info(f"Setting EC2 scan mode in delegated admin account to {ec2_scan_mode} in {region}")
    LOGGER.info(f"delegated admin client region: {inspector_delegated_admin_region_client.meta.region_name}")
    LOGGER.info(f"Region: {delegated_admin_session.region_name}")
    sts_client = delegated_admin_session.client("sts", region_name=region)
    LOGGER.info(f"caller identity: {sts_client.get_caller_identity()}")
    configuration_response: dict = inspector_delegated_admin_region_client.update_configuration(
        ec2Configuration={"scanMode": ec2_scan_mode}
    )
    api_call_details = {"API_Call": "inspector:UpdateConfiguration", "API_Response": configuration_response}
    LOGGER.info(api_call_details)
    return


def disable_inspector2_in_mgmt_and_delegated_admin(
    regions: list, configuration_role_name: str, mgmt_account_id: str, delegated_admin_account_id: str, scan_components: list
) -> None:
    """Disable inspector in management and delegated admin accounts.

    Args:
        regions: AWS Region List
        delegated_admin_account_id: Delegated Admin Account ID
        mgmt_account_id: Management Account ID
        configuration_role_name: Configuration Role Name
        scan_components: List of scan components
    """
    LOGGER.info(f"disable_inspector2_in_mgmt_and_delegated_admin: scan_components - ({scan_components})")
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(f"creating delegated admin session with ({configuration_role_name}) and account ({delegated_admin_account_id}) to disable inspector")
    for region in regions:
        inspector_management_region_client: Inspector2Client = MANAGEMENT_ACCOUNT_SESSION.client("inspector2", region)
        if get_inspector_status(inspector_management_region_client, mgmt_account_id, scan_components) != "disabled":
            LOGGER.info(f"disabling inspector in the management account in {region}...")
            disable_inspector2_response = disable_inspector2(inspector_management_region_client, mgmt_account_id, scan_components)
            LOGGER.info(disable_inspector2_response)
        else:
            LOGGER.info(f"inspector is already disabled in the management account in {region}")
        inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)
        if get_inspector_status(inspector_delegated_admin_region_client, delegated_admin_account_id, scan_components) != "disabled":
            LOGGER.info(f"disabling inspector in the delegated admin account in {region}...")
            disable_inspector2_response = disable_inspector2(inspector_delegated_admin_region_client, delegated_admin_account_id, scan_components)
            LOGGER.info(disable_inspector2_response)
        else:
            LOGGER.info(f"inspector is already disabled in the delegated admin account in {region}")


def set_auto_enable_inspector_in_org(
    region: str, configuration_role_name: str, delegated_admin_account_id: str, scan_component_dict: AutoEnableTypeDef
) -> None:
    """Set auto enablement for inspector in organizations.

    Args:
        region: AWS Region
        delegated_admin_account_id: Delegated Admin Account ID
        configuration_role_name: Configuration Role Name
        scan_component_dict: dictionary of scan components with true/false enable value
    """
    enabled_component_count: int = 0
    for scan_component in scan_component_dict:
        if scan_component_dict[scan_component] is True:  # type: ignore
            enabled_component_count = enabled_component_count + 1

    LOGGER.info(f"set_auto_enable_inspector_in_org: scan_component_dict - ({scan_component_dict})")
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(f"open session {configuration_role_name} and account id {delegated_admin_account_id} to set auto-enablement of inspector in org")
    inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)

    if check_inspector_org_auto_enabled(inspector_delegated_admin_region_client) != enabled_component_count:
        LOGGER.info(f"configuring auto-enable inspector via update_organization_configuration in region {region}")
        update_organization_configuration_response = inspector_delegated_admin_region_client.update_organization_configuration(
            autoEnable=scan_component_dict
        )
        api_call_details = {
            "API_Call": "inspector:UpdateOrganizationConfiguration",
            "API_Response": update_organization_configuration_response,
        }
        LOGGER.info(api_call_details)
        LOGGER.info(f"inspector organization auto-enable configuration updated in {region}")
    else:
        LOGGER.info(f"inspector organization already auto-enabled properly in {region}")


def associate_account(inspector2_client: Inspector2Client, account_id: str) -> AssociateMemberResponseTypeDef:
    """Associate member accounts (which also enables inspector) to the delegated admin account.

    Args:
        inspector2_client (Inspector2Client): inspector SDK client
        account_id (str): account ID

    Returns:
        AssociateMemberResponseTypeDef: API call response
    """
    associate_response = inspector2_client.associate_member(accountId=account_id)
    api_call_details = {
        "API_Call": "inspector2:AssociateMember",
        "API_Response": associate_response,
    }
    LOGGER.info(api_call_details)

    return associate_response


def associate_inspector_member_accounts(configuration_role_name: str, delegated_admin_account_id: str, accounts: list, region: str) -> None:
    """Associate accounts with the inspector delegated admin within the given region by calling associate_account function.

    Args:
        configuration_role_name (str): IAM configuration role name
        delegated_admin_account_id (str): Delegated account ID
        accounts (list): list of accounts
        region (str): region name
    """
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-inspector", delegated_admin_account_id)
    LOGGER.info(f"open session {configuration_role_name} and account id {delegated_admin_account_id} to set auto-enablement of inspector in org")
    inspector_delegated_admin_region_client: Inspector2Client = delegated_admin_session.client("inspector2", region)

    for account in accounts:
        if lookup_associated_accounts(inspector_delegated_admin_region_client, account["AccountId"]) is True:
            LOGGER.info(f"Account ({account['AccountId']}) is a member")
        else:
            LOGGER.info(f"Account ({account['AccountId']}) is NOT a member yet")
            LOGGER.info(associate_account(inspector_delegated_admin_region_client, account["AccountId"]))


def create_service_linked_role(account_id: str, configuration_role_name: str) -> None:
    """Create service linked role in the given account.

    Args:
        account_id (str): Account ID
        configuration_role_name (str): IAM configuration role name
    """
    LOGGER.info(f"creating service linked role for account {account_id}")
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-configure-inspector", account_id)
    iam_client: IAMClient = account_session.client("iam")
    common.create_service_linked_role(
        "AWSServiceRoleForAmazonInspector2",
        "inspector2.amazonaws.com",
        "A service-linked role required for AWS Inspector to access your resources.",
        iam_client,
    )
