"""This script performs operations to enable, configure, and disable SecurityHub.

Version: 1.1

'securityhub_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from time import sleep
from typing import TYPE_CHECKING, Any

import boto3
import common
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_securityhub import GetEnabledStandardsPaginator, ListMembersPaginator, ListOrganizationAdminAccountsPaginator, SecurityHubClient
    from mypy_boto3_securityhub.type_defs import CreateMembersResponseTypeDef, DeleteMembersResponseTypeDef

# Setup Default Logger
LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)

# Global variables
UNEXPECTED = "Unexpected!"
MAX_RETRY = 5
SECURITY_HUB_THROTTLE_PERIOD = 0.2

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def is_admin_account_enabled(securityhub_client: SecurityHubClient, admin_account_id: str) -> bool:
    """Is admin account enabled.

    Args:
        securityhub_client: SecurityHubClient
        admin_account_id: Admin Account ID

    Returns:
        True or False
    """
    paginator: ListOrganizationAdminAccountsPaginator = securityhub_client.get_paginator("list_organization_admin_accounts")
    for page in paginator.paginate():
        for admin_account in page["AdminAccounts"]:
            if admin_account["AccountId"] == admin_account_id and admin_account["Status"] == "ENABLED":
                return True
        sleep(SECURITY_HUB_THROTTLE_PERIOD)
    return False


def process_organization_admin_account(admin_account_id: str, regions: list) -> None:  # noqa: CCR001
    """Process the delegated admin account for each region.

    Args:
        admin_account_id: Admin account ID
        regions: AWS Region List

    Raises:
        ClientError: boto3 ClientError
    """
    for region in regions:
        securityhub_client: SecurityHubClient = MANAGEMENT_ACCOUNT_SESSION.client("securityhub", region)

        if not is_admin_account_enabled(securityhub_client, admin_account_id):
            for _ in range(10):
                try:
                    securityhub_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
                    LOGGER.info(f"Delegated admin '{admin_account_id}' enabled in {region}")
                    break
                except securityhub_client.exceptions.ResourceConflictException:
                    LOGGER.info(f"Delegated admin already enabled in {region}")
                except ClientError as error:
                    if error.response["Error"]["Code"] != "InvalidInputException":
                        raise
                    LOGGER.info(
                        f"Waiting 10 seconds before retrying the enable organization delegated admin '{admin_account_id}' enabled in {region}"
                    )
                    sleep(10)


def disable_organization_admin_account(regions: list) -> None:
    """Disable the organization admin account.

    Args:
        regions: AWS Region List
    """
    for region in regions:
        securityhub_client: SecurityHubClient = MANAGEMENT_ACCOUNT_SESSION.client("securityhub", region)
        paginator: ListOrganizationAdminAccountsPaginator = securityhub_client.get_paginator("list_organization_admin_accounts")
        for page in paginator.paginate():
            for admin_account in page["AdminAccounts"]:
                if admin_account["Status"] == "ENABLED":
                    response = securityhub_client.disable_organization_admin_account(AdminAccountId=admin_account["AccountId"])
                    api_call_details = {"API_Call": "securityhub:DisableOrganizationAdminAccount", "API_Response": response}
                    LOGGER.info(api_call_details)
                    LOGGER.info(f"Admin Account {admin_account['AccountId']} Disabled in {region}")
            sleep(SECURITY_HUB_THROTTLE_PERIOD)


def disable_securityhub(account_id: str, configuration_role_name: str, regions: list) -> None:  # noqa: CCR001
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
            disassociate_members_response = securityhub_client.disassociate_members(AccountIds=member_account_ids)
            api_call_details = {"API_Call": "securityhub:DisassociateMembers", "API_Response": disassociate_members_response}
            LOGGER.info(api_call_details)
            LOGGER.info(f"Member accounts disassociated in {region}")

            delete_members_response: DeleteMembersResponseTypeDef = securityhub_client.delete_members(AccountIds=member_account_ids)
            api_call_details = {"API_Call": "securityhub:DeleteMembers", "API_Response": delete_members_response}
            LOGGER.info(api_call_details)
            LOGGER.info(f"Member accounts deleted in {region}")

        try:
            disable_security_hub_response = securityhub_client.disable_security_hub()
            api_call_details = {"API_Call": "securityhub:DisableSecurityHub", "API_Response": disable_security_hub_response}
            LOGGER.info(api_call_details)
            LOGGER.info(f"SecurityHub disabled in {region}")
        except securityhub_client.exceptions.ResourceNotFoundException:
            LOGGER.info(f"SecurityHub is not enabled in {region}")


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
    paginator: ListMembersPaginator = securityhub_client.get_paginator("list_members")

    try:
        for page in paginator.paginate(OnlyAssociated=False):
            for member in page["Members"]:
                account_ids.append(member["AccountId"])
        sleep(SECURITY_HUB_THROTTLE_PERIOD)
    except securityhub_client.exceptions.InternalException:
        LOGGER.info("No associated members")
    except ClientError as error:
        if error.response["Error"]["Code"] != "BadRequestException":
            raise
        else:
            LOGGER.info("SecurityHub is not enabled")

    return account_ids


def get_unprocessed_account_details(create_members_response: CreateMembersResponseTypeDef, accounts: list) -> list:
    """Get unprocessed account details.

    Args:
        create_members_response: CreateMembersResponseTypeDef
        accounts: list

    Returns:
        remaining account list
    """
    remaining_accounts = []

    for unprocessed_account in create_members_response["UnprocessedAccounts"]:
        for account_record in accounts:
            if account_record["AccountId"] == unprocessed_account["AccountId"]:
                remaining_accounts.append(account_record)
    return remaining_accounts


def create_members(security_hub_client: SecurityHubClient, accounts: list) -> None:  # noqa: CCR001 # NOSONAR
    """Create members.

    Args:
        security_hub_client: SecurityHubClient
        accounts: list of account details [{"AccountId": "", "Email": ""}]
    """
    response: CreateMembersResponseTypeDef = security_hub_client.create_members(AccountDetails=accounts)
    api_call_details = {"API_Call": "securityhub:CreateMembers", "API_Response": response}
    LOGGER.info(api_call_details)
    if "UnprocessedAccounts" in response and response["UnprocessedAccounts"]:
        unprocessed = True
        retry_count = 0
        unprocessed_accounts = []
        while unprocessed:
            retry_count += 1
            LOGGER.info(f"Unprocessed Accounts: {response['UnprocessedAccounts']}")
            remaining_accounts = get_unprocessed_account_details(response, accounts)
            unprocessed = False
            if remaining_accounts:
                response = security_hub_client.create_members(AccountDetails=remaining_accounts)
                api_call_details = {"API_Call": "securityhub:CreateMembers", "API_Response": response}
                LOGGER.info(api_call_details)
                if "UnprocessedAccounts" in response and response["UnprocessedAccounts"]:
                    unprocessed_accounts = response["UnprocessedAccounts"]
                    if retry_count != MAX_RETRY:
                        unprocessed = True
                        LOGGER.info("Waiting 10 seconds before retrying create members with unprocessed accounts.")
                        sleep(10)

        if unprocessed_accounts:
            LOGGER.info(f"Unable to add the following accounts as members. {unprocessed_accounts}")

    LOGGER.info(f"Member accounts created: {len(accounts)}")


def enable_account_securityhub(account_id: str, regions: list, configuration_role_name: str, aws_partition: str, standards_user_input: dict) -> None:
    """Enable account SecurityHub.

    Args:
        account_id: Account ID
        regions: AWS Region List
        configuration_role_name: Configuration Role Name
        aws_partition: AWS Partition
        standards_user_input: Dictionary of standards
    """
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-configure-security-hub", account_id)
    iam_client: IAMClient = account_session.client("iam")
    common.create_service_linked_role(
        "AWSServiceRoleForSecurityHub",
        "securityhub.amazonaws.com",
        "A service-linked role required for AWS Security Hub to access your resources.",
        iam_client,
    )

    for region in regions:
        standard_dict: dict = get_standard_dictionary(
            account_id,
            region,
            aws_partition,
            standards_user_input["SecurityBestPracticesVersion"],
            standards_user_input["CISVersion"],
            standards_user_input["PCIVersion"],
        )
        securityhub_client: SecurityHubClient = account_session.client("securityhub", region)

        try:
            enable_security_hub_response: Any = securityhub_client.enable_security_hub(EnableDefaultStandards=False)
            api_call_details = {"API_Call": "securityhub:EnableSecurityHub", "API_Response": enable_security_hub_response}
            LOGGER.info(api_call_details)
            LOGGER.info(f"SecurityHub enabled in {account_id} {region}")
        except securityhub_client.exceptions.ResourceConflictException:
            LOGGER.info(f"SecurityHub already enabled in {account_id} {region}")

        process_standards(securityhub_client, standard_dict, standards_user_input["StandardsToEnable"])


def configure_delegated_admin_securityhub(
    accounts: list, regions: list, delegated_admin_account_id: str, configuration_role_name: str, region_linking_mode: str, home_region: str
) -> None:
    """Configure delegated admin security hub.

    Args:
        accounts: list of account details [{"AccountId": "", "Email": ""}]
        regions: AWS Region List
        delegated_admin_account_id: Delegated Admin Account ID
        configuration_role_name: Configuration Role Name
        region_linking_mode: Region Linking Mode
        home_region: Home Region
    """
    process_organization_admin_account(delegated_admin_account_id, regions)
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-security-hub", delegated_admin_account_id)

    for region in regions:
        securityhub_delegated_admin_region_client: SecurityHubClient = delegated_admin_session.client("securityhub", region)
        update_organization_configuration_response = securityhub_delegated_admin_region_client.update_organization_configuration(AutoEnable=True)
        api_call_details = {"API_Call": "securityhub:UpdateOrganizationConfiguration", "API_Response": update_organization_configuration_response}
        LOGGER.info(api_call_details)
        LOGGER.info(f"SecurityHub organization configuration updated in {region}")

        update_security_hub_configuration_response = securityhub_delegated_admin_region_client.update_security_hub_configuration(
            AutoEnableControls=True
        )
        api_call_details = {"API_Call": "securityhub:UpdateSecurityHubConfiguration", "API_Response": update_security_hub_configuration_response}
        LOGGER.info(api_call_details)
        LOGGER.info(f"SecurityHub configuration updated in {region}")

        create_members(securityhub_delegated_admin_region_client, accounts)

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


def get_enabled_standards(securityhub_client: SecurityHubClient) -> list:
    """Get Enabled Standards.

    Args:
        securityhub_client: SecurityHubClient

    Returns:
        standards subscriptions list
    """
    standards_subscriptions = []
    try:
        paginator: GetEnabledStandardsPaginator = securityhub_client.get_paginator("get_enabled_standards")

        for page in paginator.paginate():
            for standards_subscription in page["StandardsSubscriptions"]:
                standards_subscriptions.append(standards_subscription)
    except securityhub_client.exceptions.InvalidAccessException:
        LOGGER.info("Security Hub is not enabled.")
    return standards_subscriptions


def all_standards_in_status(standards_subscriptions: list, standards_status: str) -> bool:
    """All standards in status.

    Args:
        standards_subscriptions: list of standards subscriptions
        standards_status: standards status 'PENDING'|'READY'|'FAILED'|'DELETING'|'INCOMPLETE'

    Returns:
        True or False
    """
    for standards_subscription in standards_subscriptions:  # noqa: SIM111
        if standards_subscription.get("StandardsStatus") != standards_status:
            return False
    return True


def get_current_enabled_standards(securityhub_client: SecurityHubClient, standard_dict: dict) -> dict:  # noqa: CCR001 (cognitive complexity)
    """Get current enabled standards.

    Args:
        securityhub_client: SecurityHubClient
        standard_dict: Standard Dictionary

    Returns:
        Standard Dictionary
    """
    standards_subscriptions = get_enabled_standards(securityhub_client)
    if all_standards_in_status(standards_subscriptions, "READY"):
        for item in standards_subscriptions:
            if standard_dict["sbp"]["standard_arn"] == item["StandardsArn"]:
                standard_dict["sbp"]["enabled"] = True
            if standard_dict["cis"]["standard_arn"] == item["StandardsArn"]:
                standard_dict["cis"]["enabled"] = True
            if standard_dict["pci"]["standard_arn"] == item["StandardsArn"]:
                standard_dict["pci"]["enabled"] = True

    return standard_dict


def all_standards_ready(securityhub_client: SecurityHubClient) -> bool:
    """All Standards Ready.

    Args:
        securityhub_client: SecurityHubClient

    Returns:
        True or False
    """
    for i in range(10):
        standards_subscriptions = get_enabled_standards(securityhub_client)
        if all_standards_in_status(standards_subscriptions, "READY"):
            return True
        LOGGER.info(f"Waiting 20 seconds before checking if standards are in READY status. {i} of 10")
        sleep(20)
    return False


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
    for standard, status in standard_dict.items():
        process_standard(securityhub_client, standards_to_enable, status, standard)


def process_standard(securityhub_client: SecurityHubClient, standards_to_enable: dict, standard_definition: dict, standard_short_name: str) -> bool:
    """Process standard.

    Args:
        securityhub_client: SecurityHubClient
        standards_to_enable: Dictionary of standards to enable
        standard_definition: Specific Standard Information like subscription and standard ARNs
        standard_short_name: Standard short name

    Returns:
        True or False
    """
    if all_standards_ready(securityhub_client):
        try:
            if standards_to_enable[standard_short_name]:
                if not standard_definition["enabled"]:
                    response = securityhub_client.batch_enable_standards(
                        StandardsSubscriptionRequests=[{"StandardsArn": standard_definition["standard_arn"]}]
                    )
                    api_call_details = {"API_Call": "securityhub:BatchEnableStandards", "API_Response": response}
                    LOGGER.info(api_call_details)
                    LOGGER.info(f"Enabled {standard_definition['name']}")
                else:
                    LOGGER.info(f"{standard_definition['name']} is already enabled")
            else:  # Disable Standard
                if standard_definition["enabled"]:
                    LOGGER.info(f"Disabling {standard_definition['name']} in Account")
                    response = securityhub_client.batch_disable_standards(StandardsSubscriptionArns=[standard_definition["subscription_arn"]])
                    api_call_details = {"API_Call": "securityhub:BatchDisableStandards", "API_Response": response}
                    LOGGER.info(api_call_details)
                    LOGGER.info(f"Disabled {standard_definition['name']} in Account")
                else:
                    LOGGER.info(f"{standard_definition['name']} is already disabled")
        except securityhub_client.exceptions.InvalidInputException:
            LOGGER.error("Retry after the standard is no longer in pending state.")
    return True


def create_finding_aggregator(securityhub_client: SecurityHubClient, region_linking_mode: str, regions: list, home_region: str) -> bool:
    """Create Finding Aggregator.

    Args:
        securityhub_client: Security Hub Client
        region_linking_mode: Region Linking Mode
        regions: AWS Region List
        home_region: Home Region

    Returns:
        True
    """
    regions_minus_home_region = regions.copy()
    regions_minus_home_region.remove(home_region)
    if not regions_minus_home_region:
        LOGGER.info("Region aggregator not created due to only one governed region.")
        return True

    finding_aggregator_arns: list = []
    paginator = securityhub_client.get_paginator("list_finding_aggregators")

    try:
        for page in paginator.paginate():
            for finding_aggregator in page["FindingAggregators"]:
                finding_aggregator_arns.append(finding_aggregator["FindingAggregatorArn"])
    except securityhub_client.exceptions.InternalException:
        LOGGER.info("No existing finding aggregator")

    if finding_aggregator_arns:
        LOGGER.info("...Updating finding aggregator")
        update_finding_aggregator(securityhub_client, region_linking_mode, regions_minus_home_region, finding_aggregator_arns)
    else:
        LOGGER.info("...Creating finding aggregator")
        response = securityhub_client.create_finding_aggregator(RegionLinkingMode=region_linking_mode, Regions=regions_minus_home_region)
        api_call_details = {"API_Call": "securityhub:CreateFindingAggregator", "API_Response": response}
        LOGGER.info(api_call_details)
    return True


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
        api_call_details = {"API_Call": "securityhub:GetFindingAggregator", "API_Response": response}
        LOGGER.info(api_call_details)

        if response["RegionLinkingMode"] != region_linking_mode or not compare_lists(regions, response["Regions"]):
            LOGGER.info(f"Update finding aggregator: {finding_aggregator_arn}")
            if region_linking_mode != "ALL_REGIONS":
                securityhub_client.update_finding_aggregator(
                    FindingAggregatorArn=finding_aggregator_arn, RegionLinkingMode=region_linking_mode, Regions=regions
                )
                api_call_details = {"API_Call": "securityhub:UpdateFindingAggregator", "API_Response": response}
                LOGGER.info(api_call_details)
            else:
                securityhub_client.update_finding_aggregator(FindingAggregatorArn=finding_aggregator_arn, RegionLinkingMode=region_linking_mode)
                api_call_details = {"API_Call": "securityhub:UpdateFindingAggregator", "API_Response": response}
                LOGGER.info(api_call_details)


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
