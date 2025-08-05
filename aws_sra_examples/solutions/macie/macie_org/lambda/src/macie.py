"""This script provides logic for managing Macie.

Version: 1.2

'macie_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
from time import sleep
from typing import TYPE_CHECKING, Literal, Union

import boto3
import common
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_macie2 import Macie2Client
    from mypy_boto3_macie2.type_defs import CreateClassificationJobRequestRequestTypeDef, ListOrganizationAdminAccountsResponseTypeDef
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_sns import SNSClient

# Setup Default Logger
LOGGER = logging.getLogger("sra")

# Global variables
SERVICE_NAME = "macie.amazonaws.com"
SLEEP_SECONDS = 30
UNEXPECTED = "Unexpected!"
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
    if not response["adminAccounts"]:
        return True

    is_admin_account = [admin_account for admin_account in response["adminAccounts"] if admin_account["accountId"] == admin_account_id]
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
    management_account_session = boto3.Session()
    for region in regions:
        macie2_client: Macie2Client = management_account_session.client("macie2", region, config=BOTO3_CONFIG)
        response: ListOrganizationAdminAccountsResponseTypeDef = macie2_client.list_organization_admin_accounts()

        if enable_admin_account(admin_account_id, response):
            try:
                macie2_client.enable_organization_admin_account(adminAccountId=admin_account_id)
            except ClientError as error:
                if error.response["Error"]["Code"] != "ValidationException":
                    raise
                sleep(10)
                macie2_client.enable_organization_admin_account(adminAccountId=admin_account_id)
            LOGGER.info(f"Delegated admin '{admin_account_id}' enabled in {region}")


def create_members(macie2_client: Macie2Client, accounts: list) -> None:
    """Create members with existing accounts.

    Args:
        macie2_client: Macie2Client
        accounts: Existing AWS accounts
    """
    LOGGER.info("...Creating members")
    for account in accounts:
        try:
            create_member_response = macie2_client.create_member(account={"accountId": account["AccountId"], "email": account["Email"]})
            api_call_details = {"API_Call": "macie2:CreateMember", "API_Response": create_member_response}
            LOGGER.info(api_call_details)
            sleep(1)  # Sleeping 1 second to avoid max API call error
        except ClientError as error:
            LOGGER.info(f"Error creating member {account['AccountId']} - {error}")
            LOGGER.info("...Waiting 10 seconds to try adding member again.")
            sleep(10)  # Wait for delegated admin to get configured
            create_member_response = macie2_client.create_member(account={"accountId": account["AccountId"], "email": account["Email"]})
            api_call_details = {"API_Call": "macie2:CreateMember", "API_Response": create_member_response}
            LOGGER.info(api_call_details)


def configure_macie(
    session: boto3.Session,
    delegated_account_id: str,
    regions: list,
    s3_bucket_name: str,
    kms_key_arn: str,
    finding_publishing_frequency: Union[Literal["FIFTEEN_MINUTES"], Literal["ONE_HOUR"], Literal["SIX_HOURS"]],
) -> None:
    """Configure Macie with provided parameters.

    Args:
        session: boto3 Session
        delegated_account_id: Delegated Admin Account
        regions: AWS Region List
        s3_bucket_name: S3 Bucket Name
        kms_key_arn: KMS Key ARN
        finding_publishing_frequency: Finding Publishing Frequency
    """
    accounts = common.get_all_organization_accounts([delegated_account_id])

    LOGGER.info(f"...Waiting {SLEEP_SECONDS} seconds for the delegated admin to get configured.")
    sleep(SLEEP_SECONDS)  # Wait for delegated admin to get configured

    # Loop through the regions and enable Macie
    for region in regions:
        regional_client: Macie2Client = session.client("macie2", region_name=region, config=BOTO3_CONFIG)
        regional_client.update_macie_session(findingPublishingFrequency=finding_publishing_frequency, status="ENABLED")
        regional_client.put_classification_export_configuration(
            configuration={"s3Destination": {"bucketName": s3_bucket_name, "kmsKeyArn": kms_key_arn}}
        )

        # Create members for existing Organization accounts
        LOGGER.info(f"Existing Accounts: {accounts}")
        create_members(regional_client, accounts)

        # Update Organization configuration to automatically enable new accounts
        regional_client.update_organization_configuration(autoEnable=True)


def enable_macie(
    account_id: str,
    configuration_role_name: str,
    regions: list,
    finding_publishing_frequency: Union[Literal["FIFTEEN_MINUTES"], Literal["ONE_HOUR"], Literal["SIX_HOURS"]],
) -> None:
    """Enable Macie with provided parameters.

    Args:
        account_id: Account ID
        configuration_role_name: Configuration Role Name (Optional)
        regions: AWS Region List
        finding_publishing_frequency: Finding Publishing Frequency
    """
    account_session: boto3.Session = boto3.Session()

    if configuration_role_name:
        account_session = common.assume_role(configuration_role_name, "sra-enable-macie", account_id)

    # Loop through the regions and enable Macie
    for region in regions:
        regional_client: Macie2Client = account_session.client("macie2", region_name=region, config=BOTO3_CONFIG)
        try:
            enable_macie_response = regional_client.enable_macie(findingPublishingFrequency=finding_publishing_frequency, status="ENABLED")
            api_call_details = {"API_Call": "macie2:EnableMacie", "API_Response": enable_macie_response}
            LOGGER.info(api_call_details)
            sleep(0.2)  # Sleeping .2 second to avoid max API call error
        except regional_client.exceptions.ConflictException:
            LOGGER.info(f"Macie already enabled in {region}.")


def create_macie_job(configuration_role_name: str, admin_account_id: str, regions: list, job_name: str, tag_key: str) -> None:
    """Create Macie job.

    Args:
        configuration_role_name: Configuration Role Name
        admin_account_id: Delegated administrator account id
        regions: AWS Region List
        job_name: Macie job name
        tag_key: Macie job tag key for bucket criteria
    """
    kwargs: CreateClassificationJobRequestRequestTypeDef = {  # type: ignore[typeddict-item]  # noqa: ECE001
        "description": "SRA Macie job (Daily)",
        "jobType": "SCHEDULED",
        "initialRun": True,
        "name": job_name,
        "managedDataIdentifierSelector": "ALL",
        "s3JobDefinition": {
            "bucketCriteria": {"excludes": {"and": [{"tagCriterion": {"comparator": "EQ", "tagValues": [{"key": tag_key, "value": "True"}]}}]}}
        },
        "samplingPercentage": 100,
        "scheduleFrequency": {"dailySchedule": {}},
        "tags": {"sra-solution": "sra-macie-org"},
    }
    account_session: boto3.Session = boto3.Session()

    if configuration_role_name:
        account_session = common.assume_role(configuration_role_name, "sra-enable-macie", admin_account_id)
    for region in regions:
        regional_client: Macie2Client = account_session.client("macie2", region_name=region, config=BOTO3_CONFIG)
        try:
            response = regional_client.create_classification_job(**kwargs)
            LOGGER.debug({"API_Call": "macie2:CreateClassificationJob", "API_Response": response})
            LOGGER.info(f"Created Macie classification job '{job_name}' in {region}")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ResourceInUseException":
                LOGGER.info(f"Macie classification job '{job_name}' already exists in {region}")


def process_delete_event(params: dict, regions: list, account_ids: list, include_members: bool = False) -> None:
    """Delete Macie solution resources.

    Args:
        params: parameters
        regions: AWS regions
        account_ids: AWS account IDs
        include_members: True or False
    """
    delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-macie-org", params["DELEGATED_ADMIN_ACCOUNT_ID"])
    # Loop through the regions and disable Macie in the delegated admin account
    for region in regions:
        management_macie2_client: Macie2Client = MANAGEMENT_ACCOUNT_SESSION.client("macie2", region_name=region, config=BOTO3_CONFIG)
        disable_organization_admin_account(management_macie2_client, region)

        # Disable Macie in the Delegated Admin Account
        delegated_admin_macie2_client: Macie2Client = delegated_admin_session.client("macie2", region_name=region, config=BOTO3_CONFIG)
        disable_macie(delegated_admin_macie2_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], region, True)

    deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

    if include_members:
        management_sns_client: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns", config=BOTO3_CONFIG)
        for account_id in account_ids:
            sns_message = {
                "AccountId": account_id,
                "Regions": regions,
                "DisableMacieRoleName": params["DISABLE_MACIE_ROLE_NAME"],
                "Action": "disable",
            }
            LOGGER.info(f"Publishing message to disable Macie in {account_id}")
            LOGGER.info(f"{json.dumps(sns_message)}")
            management_sns_client.publish(TopicArn=params["SNS_TOPIC_ARN"], Message=json.dumps(sns_message))


def disable_macie(macie2_client: Macie2Client, account_id: str, region: str, is_delegated_admin: bool) -> None:
    """Disable Macie.

    Args:
        macie2_client: Macie2Client
        account_id: Account ID
        region: AWS Region
        is_delegated_admin: Is Delegated Admin Account
    """
    if is_delegated_admin:
        account_ids = get_associated_members(macie2_client)
        LOGGER.info(f"Account IDs: {account_ids}")

        if account_ids:
            for account_id in account_ids:
                macie2_client.disassociate_member(id=account_id)
                LOGGER.info(f"Macie disassociated in {account_id} and {region}")

                macie2_client.delete_member(id=account_id)
                LOGGER.info(f"Macie members deleted in {account_id} and {region}")

    try:
        LOGGER.info(f"Disabling Macie in {account_id} {region}")
        macie2_client.disable_macie()
    except macie2_client.exceptions.AccessDeniedException:
        LOGGER.debug(f"Macie is not enabled within {account_id} {region}")


def disable_member_account(account_id: str, disable_macie_role_name: str, regions: list) -> dict:
    """Disable member account.

    Args:
        account_id: Account ID
        disable_macie_role_name: Disable Macie Role Name
        regions: AWS Regions

    Returns:
        Account ID
    """
    session = common.assume_role(disable_macie_role_name, "sra-macie-org-disable", account_id)

    for region in regions:
        LOGGER.info(f"Disabling Macie in {account_id} {region}")
        macie2_client: Macie2Client = session.client("macie2", region_name=region, config=BOTO3_CONFIG)
        disable_macie(macie2_client, account_id, region, False)

    return {"AccountId": account_id}


def get_associated_members(macie2_client: Macie2Client) -> list:
    """Get associated Macie members.

    Args:
        macie2_client: Macie2Client

    Returns:
        account_ids
    """
    account_ids = []
    try:
        paginator = macie2_client.get_paginator("list_members")

        for page in paginator.paginate(onlyAssociated="false"):
            for member in page["members"]:
                account_ids.append(member["accountId"])
    except macie2_client.exceptions.AccessDeniedException:
        LOGGER.debug("Macie is not enabled.")

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


def disable_organization_admin_account(macie2_client: Macie2Client, region: str) -> None:
    """Disable the organization admin account.

    Args:
        macie2_client: Macie2Client
        region: AWS Region
    """
    response = macie2_client.list_organization_admin_accounts()
    if "adminAccounts" in response and response["adminAccounts"]:
        for admin_account in response["adminAccounts"]:
            if admin_account["status"] == "ENABLED":
                macie2_client.disable_organization_admin_account(adminAccountId=admin_account["accountId"])
                LOGGER.info(f"Macie Admin Account {admin_account['accountId']} Disabled in {region}")
    else:
        LOGGER.info(f"No Macie Admin Accounts in {region}")
