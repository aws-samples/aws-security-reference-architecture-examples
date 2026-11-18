"""This script deletes GuardDuty detectors within member accounts.

Version: 1.1

'guardduty_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
from functools import partial
from time import sleep
from typing import TYPE_CHECKING, Any, Callable, Dict

import boto3
import common
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_guardduty import GuardDutyClient
    from mypy_boto3_guardduty.type_defs import (
        CreateMembersResponseTypeDef,
        ListOrganizationAdminAccountsResponseTypeDef,
        UpdateMemberDetectorsResponseTypeDef,
    )
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
CHECK_ACCT_MEMBER_RETRIES = 10

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
    if not is_admin_account:  # noqa: SIM103
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


def check_members(guardduty_client: GuardDutyClient, detector_id: str, accounts: list) -> list:
    """Check all accounts in the organization are member accounts.

    Args:
        guardduty_client: boto3 guardduty client
        detector_id: detectorId of the delegated admin account
        accounts: list of accounts in the organization

    Returns:
        any account in the organization that isn't a member
    """
    LOGGER.info("check_members begin")
    retries = 0
    missing_members: list = []
    confirmed_members: list = []
    while retries < CHECK_ACCT_MEMBER_RETRIES:
        confirmed_members = []
        missing_members = []
        member_paginator = guardduty_client.get_paginator("list_members")
        page_iterator = member_paginator.paginate(DetectorId=detector_id)
        for page in page_iterator:
            for member in page["Members"]:
                confirmed_members.append(member["AccountId"])
        for account in accounts:
            if account["AccountId"] not in confirmed_members:
                missing_members.append(account)
        if len(missing_members) > 0:
            LOGGER.info(f"missing {len(missing_members)} members: {common.get_account_ids(missing_members)}")
            retries += 1
            LOGGER.info(f"sleep for {SLEEP_SECONDS} retry number {retries}")
            sleep(SLEEP_SECONDS)
        else:
            LOGGER.info("All accounts in the organization are members")
            break
    LOGGER.info("check_members end")
    return missing_members


def call_create_members(guardduty_client: GuardDutyClient, detector_id: str, accounts: list) -> Any:
    """Create GuardDuty members for a batch of accounts.

    Args:
        guardduty_client: GuardDuty client
        detector_id: GuardDuty detector id
        accounts: Accounts to create as members

    Returns:
        ``create_members`` API response
    """
    return guardduty_client.create_members(DetectorId=detector_id, AccountDetails=accounts)


def create_members(guardduty_client: GuardDutyClient, detector_id: str, accounts: list) -> None:
    """Create GuardDuty members with existing accounts, retrying unprocessed ones.

    Args:
        guardduty_client: GuardDutyClient
        detector_id: GD detector ID
        accounts: List of accounts
    """
    LOGGER.info("Creating members")

    for batch_start in range(0, len(accounts), 50):
        account_details = accounts[batch_start : batch_start + 50]
        LOGGER.info(f"Calling create_members with detector_id: {detector_id}, account_details length: {len(account_details)}")
        create_members_response = guardduty_client.create_members(DetectorId=detector_id, AccountDetails=account_details)
        process_unprocessed_accounts(
            call=partial(call_create_members, guardduty_client, detector_id),
            remaining=get_unprocessed_account_details(create_members_response, account_details),
            extract=partial(get_unprocessed_account_details, accounts=account_details),
            failure_message="Unprocessed Member Accounts while Creating Members",
        )


def set_features_list(gd_features: dict) -> list:
    """Set a list of GuardDuty features with status configurations.

    Args:
        gd_features: GuardDuty features

    Returns:
        list of GuardDuty features with status configurations
    """
    features_config: list = []
    name = ""
    status = ""

    for feature_name in gd_features:
        feature_to_set = {"Name": name, "Status": status}
        if gd_features[feature_name] is True:  # noqa: SIM108
            status = "ENABLED"
        else:
            status = "DISABLED"
        if feature_name == "RUNTIME_MONITORING":
            runtime_monitoring_config = {"Name": feature_name, "Status": status, "AdditionalConfiguration": []}
            features_config.append(runtime_monitoring_config)
        elif feature_name == "ECS_FARGATE_AGENT_MANAGEMENT" or feature_name == "EKS_ADDON_MANAGEMENT" or feature_name == "EC2_AGENT_MANAGEMENT":
            feature_to_set["Name"] = feature_name
            feature_to_set["Status"] = status
            runtime_monitoring_config["AdditionalConfiguration"].append(feature_to_set)
        else:
            feature_to_set["Name"] = feature_name
            feature_to_set["Status"] = status
            features_config.append(feature_to_set)

    return features_config


def set_configuration_params(
    detector_id: str,
    account_ids: list,
    gd_features: dict,
) -> Dict[str, Any]:
    """Set GuardDuty configuration parameters.

    Args:
        detector_id: GuardDuty detector ID
        account_ids: List of account IDs
        gd_features: GuardDuty features

    Returns:
        configuration_params: Configuration parameters
    """
    LOGGER.info("Updating Member Detectors")
    config = set_features_list(gd_features)
    configuration_params: Dict[str, Any] = {"DetectorId": detector_id, "AccountIds": account_ids, "Features": config}
    LOGGER.info("Setting feature configuration parameters once...")

    return configuration_params


def get_remaining_accounts(update_member_response: UpdateMemberDetectorsResponseTypeDef, account_ids: list) -> list:
    """Get remaining accounts.

    Args:
        update_member_response: UpdateMemberDetectorsResponseTypeDef
        account_ids: Member account list

    Returns:
        List of remaining accounts
    """
    remaining_accounts: list = []
    for unprocessed_account in update_member_response["UnprocessedAccounts"]:
        if unprocessed_account["AccountId"] in account_ids:
            remaining_accounts.append(unprocessed_account["AccountId"])
    return remaining_accounts


def process_unprocessed_accounts(
    call: Callable[[list], Any],
    remaining: list,
    extract: Callable[[Any], list],
    failure_message: str,
) -> None:
    """Retry a batch until GuardDuty reports no unprocessed accounts.

    Args:
        call: Issues the API request for the accounts that still need a retry
        remaining: Accounts the first response left unprocessed
        extract: Pulls the unprocessed accounts out of an API response
        failure_message: Error message used when retries are exhausted

    Raises:
        ValueError: Accounts are still unprocessed after ``MAX_RETRY`` retries
    """
    retries = 0
    while remaining and retries < MAX_RETRY:
        retries += 1
        LOGGER.info(f"Retrying {len(remaining)} unprocessed accounts; retry number {retries}")
        LOGGER.info(f"Sleeping for {SLEEP_SECONDS} before retry")
        sleep(SLEEP_SECONDS)
        remaining = extract(call(remaining))
    if remaining:
        LOGGER.info(f"Unprocessed accounts after {MAX_RETRY} retries: {remaining}")
        raise ValueError(failure_message)


def call_update_member_detectors(guardduty_client: GuardDutyClient, detector_id: str, features: list, account_ids: list) -> Any:
    """Update member detectors for a batch of accounts.

    Args:
        guardduty_client: GuardDuty client
        detector_id: GuardDuty detector id
        features: GuardDuty protection plans configuration
        account_ids: Accounts to update

    Returns:
        ``update_member_detectors`` API response
    """
    return guardduty_client.update_member_detectors(DetectorId=detector_id, AccountIds=account_ids, Features=features)


def update_member_detectors(
    guardduty_client: GuardDutyClient,
    detector_id: str,
    account_ids: list,
    gd_features: dict,
) -> None:
    """Update member detectors.

    Args:
        guardduty_client: GuardDuty client
        detector_id: GuardDuty detector id
        account_ids: Member account list
        gd_features: GuardDuty protection plans configuration

    """
    configuration_params = set_configuration_params(detector_id, account_ids, gd_features)
    features = configuration_params["Features"]
    LOGGER.info("Iterating through api calls for each group of accounts...")
    for batch_start in range(0, len(account_ids), 50):
        batch = account_ids[batch_start : batch_start + 50]

        LOGGER.info(f"Calling update_member_detectors with params {configuration_params}")
        update_member_response = guardduty_client.update_member_detectors(DetectorId=detector_id, AccountIds=batch, Features=features)
        process_unprocessed_accounts(
            call=partial(call_update_member_detectors, guardduty_client, detector_id, features),
            remaining=get_remaining_accounts(update_member_response, batch),
            extract=partial(get_remaining_accounts, account_ids=batch),
            failure_message="Unprocessed Member Accounts while Updating Member Detectors",
        )


def set_org_configuration_params(detector_id: str, gd_features: dict) -> dict:
    """Set organization configuration parameters for GuardDuty.

    Args:
        detector_id: GuardDuty detector ID
        gd_features: GuardDuty features

    Returns:
        dict: GuardDuty organization configuration parameters
    """
    features_config: list = []
    org_configuration_params: Dict[str, Any] = {
        "DetectorId": detector_id,
        "AutoEnable": True,
        "Features": features_config,
    }
    name = ""
    auto_enable_type = ""

    for feature_name in gd_features:
        org_feature_to_set = {"Name": name, "AutoEnable": auto_enable_type}
        if gd_features[feature_name] is True:  # noqa: SIM108
            auto_enable_type = "ALL"
        else:
            auto_enable_type = "NONE"
        if feature_name == "RUNTIME_MONITORING":
            runtime_monitoring_config = {"Name": feature_name, "AutoEnable": auto_enable_type, "AdditionalConfiguration": []}
            features_config.append(runtime_monitoring_config)
        elif feature_name == "ECS_FARGATE_AGENT_MANAGEMENT" or feature_name == "EKS_ADDON_MANAGEMENT" or feature_name == "EC2_AGENT_MANAGEMENT":
            org_feature_to_set["Name"] = feature_name
            org_feature_to_set["AutoEnable"] = auto_enable_type
            runtime_monitoring_config["AdditionalConfiguration"].append(org_feature_to_set)
        else:
            org_feature_to_set["Name"] = feature_name
            org_feature_to_set["AutoEnable"] = auto_enable_type
            features_config.append(org_feature_to_set)
        LOGGER.info({"RETURNED ORG CONFIG PARAMS": org_configuration_params})
    return org_configuration_params


def set_admin_configuration_params(
    detector_id: str,
    finding_publishing_frequency: str,
    gd_features: dict,
) -> dict:
    """Set delegated administrator configuration parameters for GuardDuty.

    Args:
        detector_id: The GuardDuty detector ID
        finding_publishing_frequency: The frequency at which findings are published
        gd_features: The GuardDuty features

    Returns:
        dict: The admin configuration parameters for GuardDuty
    """
    config = set_features_list(gd_features)
    admin_configuration_params: Dict[str, Any] = {
        "DetectorId": detector_id,
        "FindingPublishingFrequency": finding_publishing_frequency,
        "Features": config,
    }
    return admin_configuration_params


def update_guardduty_configuration(
    guardduty_client: GuardDutyClient,
    gd_features: dict,
    detector_id: str,
    finding_publishing_frequency: str,
) -> None:
    """Update GuardDuty configuration to auto enable GuardDuty and selected features in new accounts.

    Args:
        guardduty_client: GuardDuty Client
        gd_features: GuardDuty protection plans configuration
        detector_id: GuardDuty detector ID
        finding_publishing_frequency: Finding publishing frequency
    """
    org_configuration_params = set_org_configuration_params(detector_id, gd_features)
    admin_configuration_params = set_admin_configuration_params(detector_id, finding_publishing_frequency, gd_features)

    guardduty_client.update_organization_configuration(**org_configuration_params)
    guardduty_client.update_detector(**admin_configuration_params)


def configure_guardduty(  # noqa: CFQ002, CFQ001
    session: boto3.Session,
    delegated_account_id: str,
    gd_features: dict,
    region_list: list,
    finding_publishing_frequency: str,
    kms_key_arn: str,
    publishing_destination_arn: str,
) -> None:
    """Configure GuardDuty with provided parameters.

    Args:
        session: boto3 session
        delegated_account_id: Delegated Admin Account ID
        gd_features: GuardDuty protection plans configuration
        region_list: AWS Regions
        finding_publishing_frequency: Finding publishing frequency
        kms_key_arn: KMS Key ARN
        publishing_destination_arn: Publishing Destination ARN (S3 Bucket)

    Raises:
        ValueError: "Check members failure"
    """
    accounts = common.get_all_organization_accounts([delegated_account_id])
    account_ids = common.get_account_ids(accounts)

    # Loop through the regions and enable GuardDuty
    for region in region_list:
        LOGGER.info(f"Configuring GuardDuty in {region}")
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

            # Set GuardDuty Organization configuration to auto-enable selected features
            update_guardduty_configuration(
                regional_guardduty,
                gd_features,
                detector_id,
                finding_publishing_frequency,
            )

            # Create members for existing Organization accounts
            create_members(regional_guardduty, detector_id, accounts)
            LOGGER.info(f"Creating members for existing accounts: {account_ids} in {region}")

    # Verify members created for existing Organization accounts
    for region in region_list:
        detectors = regional_guardduty.list_detectors()
        if detectors["DetectorIds"]:
            detector_id = detectors["DetectorIds"][0]
            LOGGER.info(f"Checking for missing members. DetectorID: {detector_id} Region: {region}")
        missing_members: list = check_members(regional_guardduty, detector_id, accounts)
        if len(missing_members) > 0:
            LOGGER.info(f"Check members failure: {common.get_account_ids(missing_members)}")
            raise ValueError("Check members failure")
        update_member_detectors(
            regional_guardduty,
            detector_id,
            account_ids,
            gd_features,
        )


def check_for_detectors(session: boto3.Session, regions: list) -> bool:
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
                LOGGER.info(f"Detectors: {region_detectors}")
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


def disable_aws_service_access(service_principal: str) -> None:
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
