"""This script deletes GuardDuty detectors within member accounts.

Version: 1.1

'guardduty_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
from time import sleep
from typing import TYPE_CHECKING, Any, Dict

import boto3
import common
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_guardduty import GuardDutyClient
    from mypy_boto3_guardduty.type_defs import CreateMembersResponseTypeDef, ListOrganizationAdminAccountsResponseTypeDef
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_sns import SNSClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")

# Global variables
SERVICE_NAME = "guardduty.amazonaws.com"
PRINCIPAL_NAME = "malware-protection.guardduty.amazonaws.com"
SLEEP_SECONDS = 10
UNEXPECTED = "Unexpected!"
MAX_RETRY = 5
BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
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

    is_admin_account = [admin_account for admin_account in response["AdminAccounts"] if admin_account["AdminAccountId"] == admin_account_id]
    if not is_admin_account:
        return True
    return False


def process_organization_admin_account(admin_account_id: str, available_regions: list) -> None:
    """Enable delegated admin account for each region.

    Args:
        admin_account_id: Admin account ID
        available_regions: Available region list

    Raises:
        ClientError: boto3 ClientError
    """
    # Loop through the regions and enable GuardDuty
    for region in available_regions:
        guardduty_client: GuardDutyClient = MANAGEMENT_ACCOUNT_SESSION.client("guardduty", region, config=BOTO3_CONFIG)
        response = guardduty_client.list_organization_admin_accounts()

        if enable_admin_account(admin_account_id, response):
            try:
                guardduty_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
            except ClientError as error:
                if error.response["Error"]["Code"] != "InvalidInputException":
                    raise
                sleep(10)
                guardduty_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
            LOGGER.info(f"Delegated admin '{admin_account_id}' enabled in {region}")


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
        if "error" in unprocessed_account["Result"]:
            LOGGER.error(f"{unprocessed_account}")
            raise ValueError(f"Internal Error creating member accounts: {unprocessed_account['Result']}") from None
        for account_record in accounts:
            if account_record["AccountId"] == unprocessed_account["AccountId"]:
                remaining_accounts.append(account_record)
    return remaining_accounts


def create_members(guardduty_client: GuardDutyClient, detector_id: str, accounts: list) -> None:  # noqa: CCR001 (cognitive complexity)
    """Create GuardDuty members with existing accounts. Retry 2 times.

    Args:
        guardduty_client: GuardDutyClient
        detector_id: GD detector ID
        accounts: List of accounts

    Raises:
        ValueError: Unprocessed member accounts.
    """
    LOGGER.info("Creating members")
    create_members_response = guardduty_client.create_members(DetectorId=detector_id, AccountDetails=accounts)

    if "UnprocessedAccounts" in create_members_response and create_members_response["UnprocessedAccounts"]:
        unprocessed = True
        retry_count = 0
        unprocessed_accounts = []
        while unprocessed:
            retry_count += 1
            LOGGER.info(f"Unprocessed Accounts: {create_members_response['UnprocessedAccounts']}")
            remaining_accounts = get_unprocessed_account_details(create_members_response, accounts)

            unprocessed = False
            if remaining_accounts:
                create_members_response = guardduty_client.create_members(DetectorId=detector_id, AccountDetails=remaining_accounts)
                if "UnprocessedAccounts" in create_members_response and create_members_response["UnprocessedAccounts"]:
                    unprocessed_accounts = create_members_response["UnprocessedAccounts"]
                    if retry_count != MAX_RETRY:
                        unprocessed = True

        if unprocessed_accounts:
            LOGGER.info(f"Unprocessed Member Accounts: {unprocessed_accounts}")
            raise ValueError("Unprocessed Member Accounts")


def update_member_detectors(  # noqa: CCR001 (cognitive complexity)
    guardduty_client: GuardDutyClient,
    detector_id: str,
    account_ids: list,
    auto_enable_s3_logs: bool,
    enable_eks_audit_logs: bool,
    auto_enable_malware_protection: bool,
    enable_rds_login_events: bool,
    enable_eks_runtime_monitoring: bool,
    enable_eks_addon_management: bool,
    enable_lambda_network_logs: bool
) -> None:
    """Update member detectors.

    Args:
        guardduty_client: GuardDuty client
        detector_id: GuardDuty detector id
        account_ids: member account list
        auto_enable_s3_logs: Auto enable S3 Logs
        enable_eks_audit_logs: Auto enable Kubernetes Audit Logs
        auto_enable_malware_protection: Auto enable Malware Protection
        enable_rds_login_events: Auto enable RDS login activity monitoring
        enable_eks_runtime_monitoring: Auto enable EKS runtime monitoring
        enable_eks_addon_management: Auto enable EKS add-on
        enable_lambda_network_logs: Auto enable Lambda network logs

    Raises:
        ValueError: Unprocessed member accounts
    """
    configuration_params: Dict[str, Any] = {"DetectorId": detector_id, "AccountIds": account_ids}
    if "Features" not in configuration_params:
        configuration_params["Features"] = []
        if auto_enable_s3_logs:
            configuration_params["Features"].append({"Name": "S3_DATA_EVENTS", "Status": "ENABLED"})
        else:
            configuration_params["Features"].append({"Name": "S3_DATA_EVENTS", "Status": "DISABLED"})
        if enable_eks_audit_logs:
            configuration_params["Features"].append({"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"})
        else:
            configuration_params["Features"].append({"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"})
        if auto_enable_malware_protection:
            configuration_params["Features"].append({"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"})
        else:
            configuration_params["Features"].append({"Name": "EBS_MALWARE_PROTECTION", "Status": "DISABLED"})
        if enable_rds_login_events:
            configuration_params["Features"].append({"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"})
        else:
            configuration_params["Features"].append({"Name": "RDS_LOGIN_EVENTS", "Status": "DISABLED"})
        if enable_eks_runtime_monitoring and enable_eks_addon_management:
            configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "ENABLED"}]})
        elif enable_eks_runtime_monitoring and not enable_eks_addon_management:
            configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}]})
        else:
            configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "Status": "DISABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}]})
        if enable_lambda_network_logs:
            configuration_params["Features"].append({"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"})
        else:
            configuration_params["Features"].append({"Name": "LAMBDA_NETWORK_LOGS", "Status": "DISABLED"})
        LOGGER.info(f"Configuration parameters are: {configuration_params}")

    update_member_response = guardduty_client.update_member_detectors(**configuration_params)

    if "UnprocessedAccounts" in update_member_response and update_member_response["UnprocessedAccounts"]:
        unprocessed = True
        retry_count = 0
        unprocessed_accounts = []
        while unprocessed:
            sleep(SLEEP_SECONDS)
            retry_count += 1
            remaining_accounts = []

            for unprocessed_account in update_member_response["UnprocessedAccounts"]:
                if unprocessed_account["AccountId"] in account_ids:
                    remaining_accounts.append(unprocessed_account["AccountId"])

            if remaining_accounts:
                configuration_params["AccountIds"] = remaining_accounts
                update_member_response = guardduty_client.update_member_detectors(**configuration_params)
                if "UnprocessedAccounts" in update_member_response and update_member_response["UnprocessedAccounts"]:
                    unprocessed_accounts = update_member_response["UnprocessedAccounts"]
                    if retry_count == 5:
                        unprocessed = False
                else:
                    unprocessed = False

        if unprocessed_accounts:
            LOGGER.info(f"Update Member Detectors Unprocessed Member Accounts: {unprocessed_accounts}")
            raise ValueError("Unprocessed Member Accounts")


def update_guardduty_configuration(  # noqa: CCR001 (cognitive complexity)
    guardduty_client: GuardDutyClient,
    auto_enable_s3_logs: bool,
    enable_eks_audit_logs: bool,
    auto_enable_malware_protection: bool,
    enable_rds_login_events: bool,
    enable_eks_runtime_monitoring: bool,
    enable_eks_addon_management: bool,
    enable_lambda_network_logs: bool,
    detector_id: str,
    finding_publishing_frequency: str,
    account_ids: list
) -> None:
    """Update GuardDuty configuration to auto enable new accounts and S3 log protection.

    Args:
        guardduty_client: GuardDuty Client
        auto_enable_s3_logs: Auto enable S3 Logs
        enable_eks_audit_logs: Auto enable Kubernetes Audit Logs
        auto_enable_malware_protection: Auto enable Malware Protection
        enable_rds_login_events: Auto enable RDS login activity monitoring
        enable_eks_runtime_monitoring: Auto enable EKS runtime monitoring
        enable_eks_addon_management: Auto enable EKS add-on
        enable_lambda_network_logs: Auto enable Lambda network logs
        detector_id: GuardDuty detector ID
        finding_publishing_frequency: Finding publishing frequency
        account_ids: List of member account ids
    """
    org_configuration_params: Dict[str, Any] = {"DetectorId": detector_id, "AutoEnable": True}
    admin_configuration_params: Dict[str, Any] = {"DetectorId": detector_id, "FindingPublishingFrequency": finding_publishing_frequency}

    if "Features" not in org_configuration_params:
        org_configuration_params["Features"] = []
        if auto_enable_s3_logs:
            org_configuration_params["Features"].append({"Name": "S3_DATA_EVENTS", "AutoEnable": "NEW"})
        else:
            org_configuration_params["Features"].append({"Name": "S3_DATA_EVENTS", "AutoEnable": "NONE"})
        if enable_eks_audit_logs:
            org_configuration_params["Features"].append({"Name": "EKS_AUDIT_LOGS", "AutoEnable": "NEW"})
        else:
            org_configuration_params["Features"].append({"Name": "EKS_AUDIT_LOGS", "AutoEnable": "NONE"})
        if auto_enable_malware_protection:
            org_configuration_params["Features"].append({"Name": "EBS_MALWARE_PROTECTION", "AutoEnable": "NEW"})
        else:
            org_configuration_params["Features"].append({"Name": "EBS_MALWARE_PROTECTION", "AutoEnable": "NONE"})
        if enable_rds_login_events:
            org_configuration_params["Features"].append({"Name": "RDS_LOGIN_EVENTS", "AutoEnable": "NEW"})
        else:
            org_configuration_params["Features"].append({"Name": "RDS_LOGIN_EVENTS", "AutoEnable": "NONE"})
        if enable_eks_runtime_monitoring and enable_eks_addon_management:
            org_configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "AutoEnable": "NEW",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "AutoEnable": "NEW"}]})
        elif enable_eks_runtime_monitoring and not enable_eks_addon_management:
            org_configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "AutoEnable": "NEW",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "AutoEnable": "NONE"}]})
        else:
            org_configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "AutoEnable": "NONE",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "AutoEnable": "NONE"}]})
        if enable_lambda_network_logs:
            org_configuration_params["Features"].append({"Name": "LAMBDA_NETWORK_LOGS", "AutoEnable": "NEW"})
        else:
            org_configuration_params["Features"].append({"Name": "LAMBDA_NETWORK_LOGS", "AutoEnable": "NONE"})

    if "Features" not in admin_configuration_params:
        admin_configuration_params["Features"] = []
        if auto_enable_s3_logs:
            admin_configuration_params["Features"].append({"Name": "S3_DATA_EVENTS", "Status": "ENABLED"})
        else:
            admin_configuration_params["Features"].append({"Name": "S3_DATA_EVENTS", "Status": "DISABLED"})
        if enable_eks_audit_logs:
            admin_configuration_params["Features"].append({"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"})
        else:
            admin_configuration_params["Features"].append({"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"})
        if auto_enable_malware_protection:
            admin_configuration_params["Features"].append({"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"})
        else:
            admin_configuration_params["Features"].append({"Name": "EBS_MALWARE_PROTECTION", "Status": "DISABLED"})
        if enable_rds_login_events:
            admin_configuration_params["Features"].append({"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"})
        else:
            admin_configuration_params["Features"].append({"Name": "RDS_LOGIN_EVENTS", "Status": "DISABLED"})
        if enable_eks_runtime_monitoring and enable_eks_addon_management:
            admin_configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "ENABLED"}]})
        elif enable_eks_runtime_monitoring and not enable_eks_addon_management:
            admin_configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}]})
        else:
            admin_configuration_params["Features"].append({
                "Name": "EKS_RUNTIME_MONITORING",
                "Status": "DISABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}]})
        if enable_lambda_network_logs:
            admin_configuration_params["Features"].append({"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"})
        else:
            admin_configuration_params["Features"].append({"Name": "LAMBDA_NETWORK_LOGS", "Status": "DISABLED"})

        guardduty_client.update_organization_configuration(**org_configuration_params)
        guardduty_client.update_detector(**admin_configuration_params)
        update_member_detectors(guardduty_client,
                                detector_id, account_ids,
                                auto_enable_s3_logs,
                                enable_eks_audit_logs,
                                auto_enable_malware_protection,
                                enable_rds_login_events,
                                enable_eks_runtime_monitoring,
                                enable_eks_addon_management,
                                enable_lambda_network_logs
                                )


def configure_guardduty(
    session: boto3.Session,
    delegated_account_id: str,
    auto_enable_s3_logs: bool,
    enable_eks_audit_logs: bool,
    auto_enable_malware_protection: bool,
    enable_rds_login_events: bool,
    enable_eks_runtime_monitoring: bool,
    enable_eks_addon_management: bool,
    enable_lambda_network_logs: bool,
    region_list: list,
    finding_publishing_frequency: str,
    kms_key_arn: str,
    publishing_destination_arn: str,
) -> None:
    """Configure GuardDuty with provided parameters.

    Args:
        session: boto3 session
        delegated_account_id: Delegated Admin Account ID
        auto_enable_s3_logs: Auto enable S3 Logs
        enable_eks_audit_logs: Auto enable Kubernetes Audit Logs
        auto_enable_malware_protection: Auto enable Malware Protection
        enable_rds_login_events: Auto enable RDS login activity monitoring
        enable_eks_runtime_monitoring: Auto enable EKS runtime monitoring
        enable_eks_addon_management: Auto enable EKS add-on
        enable_lambda_network_logs: Auto enable Lambda network logs
        region_list: AWS Regions
        finding_publishing_frequency: Finding publishing frequency
        kms_key_arn: KMS Key ARN
        publishing_destination_arn: Publishing Destination ARN (S3 Bucket)
    """
    accounts = common.get_all_organization_accounts([delegated_account_id])
    account_ids = common.get_account_ids(accounts)

    # Loop through the regions and enable GuardDuty
    for region in region_list:
        regional_guardduty: GuardDutyClient = session.client("guardduty", region_name=region, config=BOTO3_CONFIG)
        detectors = regional_guardduty.list_detectors()

        if detectors["DetectorIds"]:
            detector_id = detectors["DetectorIds"][0]
            LOGGER.info(f"DetectorID: {detector_id} Region: {region}")

            # Update Publish Destination
            destinations = regional_guardduty.list_publishing_destinations(DetectorId=detector_id)

            if "Destinations" in destinations and len(destinations["Destinations"]) == 1:
                destination_id = destinations["Destinations"][0]["DestinationId"]

                regional_guardduty.update_publishing_destination(
                    DetectorId=detector_id,
                    DestinationId=destination_id,
                    DestinationProperties={
                        "DestinationArn": publishing_destination_arn,
                        "KmsKeyArn": kms_key_arn,
                    },
                )
            else:
                # Create Publish Destination
                regional_guardduty.create_publishing_destination(
                    DetectorId=detector_id,
                    DestinationType="S3",
                    DestinationProperties={
                        "DestinationArn": publishing_destination_arn,
                        "KmsKeyArn": kms_key_arn,
                    },
                )

            # Create members for existing Organization accounts
            LOGGER.info(f"Members created for existing accounts: {accounts} in {region}")
            create_members(regional_guardduty, detector_id, accounts)

            LOGGER.info(f"Waiting {SLEEP_SECONDS} seconds before updating the configuration.")
            sleep(SLEEP_SECONDS)
            update_guardduty_configuration(regional_guardduty,
                                           auto_enable_s3_logs,
                                           enable_eks_audit_logs,
                                           auto_enable_malware_protection,
                                           enable_rds_login_events,
                                           enable_eks_runtime_monitoring,
                                           enable_eks_addon_management,
                                           enable_lambda_network_logs,
                                           detector_id,
                                           finding_publishing_frequency,
                                           account_ids)


def check_for_detectors(session: boto3.Session, regions: list) -> bool:  # noqa: CCR001 (cognitive complexity)
    """Check to see if the GuardDuty detectors exist for all regions before configuring.

    Args:
        session: boto3 session
        regions: AWS regions

    Returns:
        True or False
    """
    region_detectors: Dict[str, list] = {}

    for region in regions:
        try:
            region_detectors[region] = []
            guardduty_client: GuardDutyClient = session.client("guardduty", region, config=BOTO3_CONFIG)
            paginator = guardduty_client.get_paginator("list_detectors")

            for page in paginator.paginate():
                region_detectors[region].extend(page["DetectorIds"])
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                LOGGER.info(f"Detector not found in {region}")

    return all(value for _, value in region_detectors.items())


def process_delete_event(params: dict, regions: list, account_ids: list, include_members: bool = False) -> None:
    """Delete GuardDuty solution resources.

    Args:
        params: parameters
        regions: AWS regions
        account_ids: AWS account IDs
        include_members: Include Members
    """
    delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "DeleteGuardDuty", params["DELEGATED_ADMIN_ACCOUNT_ID"])
    # Loop through the regions and disable GuardDuty in the delegated admin account
    for region in regions:
        management_guardduty_client: GuardDutyClient = MANAGEMENT_ACCOUNT_SESSION.client("guardduty", region_name=region, config=BOTO3_CONFIG)
        disable_organization_admin_account(management_guardduty_client, region)

        # Delete Detectors in the Delegated Admin Account
        delegated_admin_guardduty_client: GuardDutyClient = delegated_admin_session.client("guardduty", region_name=region, config=BOTO3_CONFIG)
        delete_detectors(delegated_admin_guardduty_client, region, True)

    deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

    if include_members:
        management_sns_client: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns", config=BOTO3_CONFIG)
        for account_id in account_ids:
            sns_message = {
                "AccountId": account_id,
                "Regions": regions,
                "DeleteDetectorRoleName": params["DELETE_DETECTOR_ROLE_NAME"],
                "Action": "delete-member",
            }
            LOGGER.info(f"Publishing message to cleanup GuardDuty in {account_id}")
            LOGGER.info(f"{json.dumps(sns_message)}")
            management_sns_client.publish(TopicArn=params["SNS_TOPIC_ARN"], Message=json.dumps(sns_message))


def disable_aws_service_access(service_principal: str = PRINCIPAL_NAME) -> None:
    """Disable service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service Principal
    """
    try:
        LOGGER.info(f"Disabling service access for {service_principal}")

        ORG_CLIENT.disable_aws_service_access(ServicePrincipal=service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
        LOGGER.info(f"Service ({service_principal}) does not have organizations access revoked: {error}")


def cleanup_member_account(account_id: str, delete_detector_role_name: str, regions: list) -> dict:
    """Cleanup member account.

    Args:
        account_id: Account ID
        delete_detector_role_name: Delete Detector Role Name
        regions: AWS Regions

    Returns:
        Account ID
    """
    session = common.assume_role(delete_detector_role_name, "sra-delete-guardduty", account_id)

    for region in regions:
        LOGGER.info(f"Deleting GuardDuty detector in {account_id} {region}")
        guardduty_client: GuardDutyClient = session.client("guardduty", region_name=region, config=BOTO3_CONFIG)
        delete_detectors(guardduty_client, region, False)

    return {"AccountId": account_id}


def delete_detectors(guardduty_client: GuardDutyClient, region: str, is_delegated_admin: bool = False) -> None:
    """Delete GuardDuty Detectors.

    Args:
        guardduty_client: GuardDuty Client
        region: AWS Region
        is_delegated_admin: True or False
    """
    disable_aws_service_access(PRINCIPAL_NAME)
    detectors = guardduty_client.list_detectors()

    if detectors["DetectorIds"]:
        for detector_id in detectors["DetectorIds"]:
            if is_delegated_admin:
                account_ids = get_associated_members(guardduty_client, detector_id)
                LOGGER.info(f"Account IDs: {account_ids}")

                if account_ids:
                    guardduty_client.disassociate_members(DetectorId=detector_id, AccountIds=account_ids)
                    LOGGER.info(f"GuardDuty accounts disassociated in {region}")

                    guardduty_client.delete_members(DetectorId=detector_id, AccountIds=account_ids)
                    LOGGER.info(f"GuardDuty members deleted in {region}")

            guardduty_client.delete_detector(DetectorId=detector_id)


def get_associated_members(guardduty_client: GuardDutyClient, detector_id: str) -> list:
    """Get associated GuardDuty members.

    Args:
        guardduty_client: GuardDuty Client
        detector_id: GuardDuty Detector ID

    Returns:
        account_ids
    """
    account_ids = []
    paginator = guardduty_client.get_paginator("list_members")

    for page in paginator.paginate(DetectorId=detector_id, OnlyAssociated="false", PaginationConfig={"PageSize": 20}):
        for member in page["Members"]:
            account_ids.append(member["AccountId"])

    return account_ids


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
        LOGGER.debug(f"Account is not a registered delegated administrator: {error}")


def disable_organization_admin_account(guardduty_client: GuardDutyClient, region: str) -> None:
    """Disable the organization admin account.

    Args:
        guardduty_client: GuardDutyClient
        region: AWS Region
    """
    response = guardduty_client.list_organization_admin_accounts()
    if "AdminAccounts" in response and response["AdminAccounts"]:
        for admin_account in response["AdminAccounts"]:
            if admin_account["AdminStatus"] == "ENABLED":
                guardduty_client.disable_organization_admin_account(AdminAccountId=admin_account["AdminAccountId"])
                LOGGER.info(f"GuardDuty Admin Account {admin_account['AdminAccountId']} Disabled in {region}")
    else:
        LOGGER.info(f"No GuardDuty Admin Accounts in {region}")
