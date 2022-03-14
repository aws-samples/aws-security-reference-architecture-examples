"""This script performs operations to enable, configure, and disable SecurityHub.

Version: 1.0

'securityhub_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from time import sleep
from typing import TYPE_CHECKING

import boto3
import common
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_securityhub import SecurityHubClient
    from mypy_boto3_securityhub.type_defs import CreateMembersResponseTypeDef, ListOrganizationAdminAccountsResponseTypeDef

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)

# Global variables
UNEXPECTED = "Unexpected!"
MAX_RETRY = 5

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def enable_admin_account(admin_account_id: str, response: ListOrganizationAdminAccountsResponseTypeDef) -> bool:
    """Enable admin account.

    Args:
        admin_account_id: Admin Account ID
        response: ListOrganizationAdminAccountsResponseTypeDef

    Returns:
        True or False
    """
    if not response["AdminAccounts"]:
        return True

    is_admin_account = [admin_account for admin_account in response["AdminAccounts"] if admin_account["AccountId"] == admin_account_id]
    if not is_admin_account:
        return True
    return False


def process_organization_admin_account(admin_account_id: str, regions: list) -> None:
    """Process the delegated admin account for each region.

    Args:
        admin_account_id: Admin account ID
        regions: AWS Region List

    Raises:
        ClientError: boto3 ClientError
    """
    for region in regions:
        securityhub_client: SecurityHubClient = MANAGEMENT_ACCOUNT_SESSION.client("securityhub", region)
        response: ListOrganizationAdminAccountsResponseTypeDef = securityhub_client.list_organization_admin_accounts()

        if enable_admin_account(admin_account_id, response):
            try:
                securityhub_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
            except ClientError as error:
                if error.response["Error"]["Code"] != "InvalidInputException":
                    raise
                sleep(10)
                securityhub_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
            LOGGER.info(f"Delegated admin '{admin_account_id}' enabled in {region}")


def disable_organization_admin_account(regions: list) -> None:
    """Disable the organization admin account.

    Args:
        regions: AWS Region List
    """
    for region in regions:
        securityhub_client: SecurityHubClient = MANAGEMENT_ACCOUNT_SESSION.client("securityhub", region)
        response = securityhub_client.list_organization_admin_accounts()
        for admin_account in response["AdminAccounts"]:
            if admin_account["Status"] == "ENABLED":
                securityhub_client.disable_organization_admin_account(AdminAccountId=admin_account["AccountId"])
                LOGGER.info(f"Admin Account {admin_account['AccountId']} Disabled in {region}")


def disable_securityhub(account_id: str, configuration_role_name: str, regions: list) -> None:
    """Disable Security Hub.

    Args:
        account_id: Account ID
        configuration_role_name: Configuration Role Name
        regions: AWS Region List
    """
    account_session = common.assume_role(configuration_role_name, "sra-disable-security-hub", account_id)

    for region in regions:
        securityhub_client: SecurityHubClient = account_session.client("securityhub", region)
        member_account_ids: list = get_associated_members(securityhub_client)

        if member_account_ids:
            securityhub_client.disassociate_members(AccountIds=member_account_ids)
            LOGGER.info(f"Member accounts disassociated in {region}")

            securityhub_client.delete_members(AccountIds=member_account_ids)
            LOGGER.info(f"Member accounts deleted in {region}")

        try:
            securityhub_client.disable_security_hub()
            LOGGER.info(f"SecurityHub disabled in {region}")
        except securityhub_client.exceptions.ResourceNotFoundException:
            LOGGER.debug(f"SecurityHub is not enabled in {region}")


def get_associated_members(securityhub_client: SecurityHubClient) -> list:
    """Get SecurityHub members.

    Args:
        securityhub_client: SecurityHub Client

    Returns:
        account_ids

    Raises:
        ClientError: botocore Client Error
    """
    account_ids = []
    paginator = securityhub_client.get_paginator("list_members")

    try:
        for page in paginator.paginate(OnlyAssociated=False):
            for member in page["Members"]:
                account_ids.append(member["AccountId"])
    except securityhub_client.exceptions.InternalException:
        LOGGER.debug("No associated members")
    except ClientError as error:
        if error.response["Error"]["Code"] != "BadRequestException":
            raise
        else:
            LOGGER.debug("SecurityHub is not enabled")

    return account_ids


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
        if "error" in unprocessed_account["ProcessingResult"]:
            LOGGER.error(f"{unprocessed_account}")
            raise ValueError(f"Internal Error creating member accounts: {unprocessed_account['ProcessingResult']}") from None
        for account_record in accounts:
            if account_record["AccountId"] == unprocessed_account["AccountId"]:
                remaining_accounts.append(account_record)
    return remaining_accounts


def create_members(security_hub_client: SecurityHubClient, accounts: list) -> None:
    """Create members.

    Args:
        security_hub_client: SecurityHubClient
        accounts: list of account details [{"AccountId": "", "Email": ""}]

    Raises:
        ValueError: Internal Error creating member accounts
        ValueError: Unprocessed Member Accounts
    """
    create_members_response: CreateMembersResponseTypeDef = security_hub_client.create_members(AccountDetails=accounts)
    if "UnprocessedAccounts" in create_members_response and create_members_response["UnprocessedAccounts"]:
        unprocessed = True
        retry_count = 0
        unprocessed_accounts = []
        while unprocessed:
            retry_count += 1
            LOGGER.debug(f"Unprocessed Accounts: {create_members_response['UnprocessedAccounts']}")
            remaining_accounts = get_unprocessed_account_details(create_members_response, accounts)
            unprocessed = False
            if remaining_accounts:
                create_members_response = security_hub_client.create_members(AccountDetails=remaining_accounts)
                if "UnprocessedAccounts" in create_members_response and create_members_response["UnprocessedAccounts"]:
                    unprocessed_accounts = create_members_response["UnprocessedAccounts"]
                    if retry_count != MAX_RETRY:
                        unprocessed = True

        if unprocessed_accounts:
            LOGGER.error(f"Unprocessed Member Accounts: {unprocessed_accounts}")
            raise ValueError("Unprocessed Member Accounts")

    LOGGER.info(f"Member accounts created: {len(accounts)}")


def enable_securityhub(
    delegated_admin_account_id: str,
    configuration_role_name: str,
    accounts: list,
    regions: list,
    standards_user_input: dict,
    aws_partition: str,
    region_linking_mode: str,
    home_region: str,
) -> None:
    """Enable SecurityHub.

    Args:
        delegated_admin_account_id: Delegated Admin Account
        configuration_role_name: Configuration Role Name
        accounts: Existing member account list
        regions: AWS Region List
        standards_user_input: Standards
        aws_partition: AWS Partition
        region_linking_mode: Region Linking Mode
        home_region: Home Region
    """
    process_organization_admin_account(delegated_admin_account_id, regions)
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-security-hub", delegated_admin_account_id)
    securityhub_management_client: SecurityHubClient = MANAGEMENT_ACCOUNT_SESSION.client("securityhub")

    for region in regions:
        try:
            securityhub_management_client.enable_security_hub(EnableDefaultStandards=False)
            LOGGER.info(f"Management account SecurityHub enabled in {region}")
        except securityhub_management_client.exceptions.ResourceConflictException:
            LOGGER.info(f"Management account SecurityHub already enabled in {region}")

        securityhub_delegated_admin_region_client: SecurityHubClient = delegated_admin_session.client("securityhub", region)
        try:
            securityhub_delegated_admin_region_client.enable_security_hub(EnableDefaultStandards=False)
            LOGGER.info(f"SecurityHub enabled in {region}")
        except securityhub_delegated_admin_region_client.exceptions.ResourceConflictException:
            LOGGER.info(f"SecurityHub already enabled in {region}")

        securityhub_delegated_admin_region_client.update_organization_configuration(AutoEnable=True)
        LOGGER.info(f"SecurityHub organization configuration updated in {region}")

        securityhub_delegated_admin_region_client.update_security_hub_configuration(AutoEnableControls=True)
        LOGGER.info(f"SecurityHub configuration updated in {region}")

        create_members(securityhub_delegated_admin_region_client, accounts)

        standard_dict: dict = get_standard_dictionary(
            delegated_admin_account_id,
            region,
            aws_partition,
            standards_user_input["SecurityBestPracticesVersion"],
            standards_user_input["CISVersion"],
            standards_user_input["PCIVersion"],
        )
        process_standards(securityhub_delegated_admin_region_client, standard_dict, standards_user_input["StandardsToEnable"])

    securityhub_delegated_admin_client: SecurityHubClient = delegated_admin_session.client("securityhub")
    create_finding_aggregator(securityhub_delegated_admin_client, region_linking_mode, regions, home_region)


def configure_member_account(account_id: str, configuration_role_name: str, regions: list, standards_user_input: dict, aws_partition: str) -> None:
    """Configure Member Account.

    Args:
        account_id: Account ID
        configuration_role_name: Configuration Role Name
        regions: AWS Region List
        standards_user_input: Standards user input dictionary
        aws_partition: AWS Partition
    """
    LOGGER.info(f"Configuring account {account_id}")

    account_session = common.assume_role(configuration_role_name, "sra-configure-security-hub", account_id)

    for region in regions:
        securityhub_client: SecurityHubClient = account_session.client("securityhub", region)
        standard_dict: dict = get_standard_dictionary(
            account_id,
            region,
            aws_partition,
            standards_user_input["SecurityBestPracticesVersion"],
            standards_user_input["CISVersion"],
            standards_user_input["PCIVersion"],
        )
        process_standards(securityhub_client, standard_dict, standards_user_input["StandardsToEnable"])


def process_standards(
    securityhub_client: SecurityHubClient,
    standard_dict: dict,
    standards_to_enable: dict,
) -> None:
    """Process Standards.

    Args:
        securityhub_client: SecurityHubClient
        standard_dict: Standard Dictionary
        standards_to_enable: Dictionary of standards to enable
    """
    standard_dict = get_current_enabled_standards(securityhub_client, standard_dict)
    for key, value in standard_dict.items():
        process_standard(securityhub_client, standards_to_enable, value, key)


def get_standard_dictionary(account_id: str, region: str, aws_partition: str, sbp_version: str, cis_version: str, pci_version: str) -> dict:
    """Get Standard ARNs.

    Args:
        account_id: Account ID
        region: AWS Region
        aws_partition: AWS Partition
        sbp_version: AWS Security Best Practices Standard Version
        cis_version: CIS Standard Version
        pci_version: PCI Standard Version

    Returns:
        Standard ARN Dictionary
    """
    return {
        "cis": {
            "name": "CIS AWS Foundations Benchmark Security Standard",
            "enabled": False,
            "standard_arn": f"arn:{aws_partition}:securityhub:::ruleset/cis-aws-foundations-benchmark/v/{cis_version}",
            "subscription_arn": f"arn:{aws_partition}:securityhub:{region}:{account_id}:subscription/cis-aws-foundations-benchmark/v/{cis_version}",
        },
        "pci": {
            "name": "Payment Card Industry Data Security Standard (PCI DSS)",
            "enabled": False,
            "standard_arn": f"arn:{aws_partition}:securityhub:{region}::standards/pci-dss/v/{pci_version}",
            "subscription_arn": f"arn:{aws_partition}:securityhub:{region}:{account_id}:subscription/pci-dss/v/{pci_version}",
        },
        "sbp": {
            "name": "AWS Foundational Security Best Practices Standard",
            "enabled": False,
            "standard_arn": f"arn:{aws_partition}:securityhub:{region}::standards/aws-foundational-security-best-practices/v/{sbp_version}",
            "subscription_arn": (
                f"arn:{aws_partition}:securityhub:{region}:{account_id}:subscription/aws-foundational-security-best-practices/v/{sbp_version}"
            ),
        },
    }


def get_current_enabled_standards(securityhub_client: SecurityHubClient, standard_dict: dict) -> dict:
    """Get current enabled standards.

    Args:
        securityhub_client: SecurityHubClient
        standard_dict: Standard Dictionary

    Returns:
        Standard Dictionary
    """
    enabled_standards_response = securityhub_client.get_enabled_standards()
    LOGGER.debug(f"Enabled Standards: {enabled_standards_response}")

    for item in enabled_standards_response["StandardsSubscriptions"]:
        if standard_dict["sbp"]["standard_arn"] in item["StandardsArn"]:
            standard_dict["sbp"]["enabled"] = True
        if standard_dict["cis"]["standard_arn"] in item["StandardsArn"]:
            standard_dict["cis"]["enabled"] = True
        if standard_dict["pci"]["standard_arn"] in item["StandardsArn"]:
            standard_dict["pci"]["enabled"] = True

    return standard_dict


def process_standard(securityhub_client: SecurityHubClient, standards_to_enable: dict, standard_data: dict, standard_key: str) -> bool:
    """Process standard.

    Args:
        securityhub_client: SecurityHubClient
        standards_to_enable: Dictionary of standards to enable
        standard_data: Standard data
        standard_key: Standard short name

    Returns:
        True or False
    """
    try:
        if standards_to_enable[standard_key]:  # Enable Standard
            if not standard_data["enabled"]:
                securityhub_client.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": standard_data["standard_arn"]}])
                LOGGER.info(f"Enabled {standard_data['name']}")
                return True
            LOGGER.info(f"{standard_data['name']} is already enabled")
        else:  # Disable Standard
            if standard_data["enabled"]:
                securityhub_client.batch_disable_standards(StandardsSubscriptionArns=[standard_data["subscription_arn"]])
                LOGGER.info(f"Disabled {standard_data['name']} in Account")
                return True
            LOGGER.info(f"{standard_data['name']} is already disabled")
    except securityhub_client.exceptions.InvalidInputException:
        LOGGER.error("Retry after the standard is no longer in pending state.")
    return True


def create_finding_aggregator(securityhub_client: SecurityHubClient, region_linking_mode: str, regions: list, home_region: str) -> None:
    """Create Finding Aggregator.

    Args:
        securityhub_client: Security Hub Client
        region_linking_mode: Region Linking Mode
        regions: AWS Region List
        home_region: Home Region
    """
    regions_minus_home_region = regions.copy()
    regions_minus_home_region.remove(home_region)

    finding_aggregator_arns: list = []
    paginator = securityhub_client.get_paginator("list_finding_aggregators")

    try:
        for page in paginator.paginate():
            for finding_aggregator in page["FindingAggregators"]:
                finding_aggregator_arns.append(finding_aggregator["FindingAggregatorArn"])
    except securityhub_client.exceptions.InternalException:
        LOGGER.debug("No existing finding aggregator")

    if finding_aggregator_arns:
        LOGGER.info("...Updating finding aggregator")
        update_finding_aggregator(securityhub_client, region_linking_mode, regions_minus_home_region, finding_aggregator_arns)
    else:
        LOGGER.info("...Creating finding aggregator")
        securityhub_client.create_finding_aggregator(RegionLinkingMode=region_linking_mode, Regions=regions_minus_home_region)


def update_finding_aggregator(securityhub_client: SecurityHubClient, region_linking_mode: str, regions: list, finding_aggregator_arns: list) -> None:
    """Update Finding Aggregator.

    Args:
        securityhub_client: Security Hub Client
        region_linking_mode: Region Linking Mode
        regions: AWS Region List
        finding_aggregator_arns: Finding Aggregator Arns
    """
    for finding_aggregator_arn in finding_aggregator_arns:
        response = securityhub_client.get_finding_aggregator(FindingAggregatorArn=finding_aggregator_arn)
        if response["RegionLinkingMode"] != region_linking_mode or not compare_lists(regions, response["Regions"]):
            LOGGER.info(f"Update finding aggregator: {finding_aggregator_arn}")
            if region_linking_mode != "ALL_REGIONS":
                securityhub_client.update_finding_aggregator(
                    FindingAggregatorArn=finding_aggregator_arn, RegionLinkingMode=region_linking_mode, Regions=regions
                )
            else:
                securityhub_client.update_finding_aggregator(FindingAggregatorArn=finding_aggregator_arn, RegionLinkingMode=region_linking_mode)


def compare_lists(list1: list, list2: list) -> bool:
    """Compare lists.

    Args:
        list1: List 1
        list2: List 2

    Returns:
        True or False
    """
    if len(list1) != len(list2):
        return False

    if set(list1) == set(list2):
        return True

    return False
