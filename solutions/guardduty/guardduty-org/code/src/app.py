########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
import boto3
import botocore
import time
from botocore.exceptions import ClientError
from crhelper import CfnResource
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time as now

# Setup Default Logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

"""
The purpose of this script is to configure GuardDuty within the delegated 
administrator account in all provided regions to add existing accounts, enable new accounts 
automatically, and publish findings to an S3 bucket.
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="INFO", boto_level="CRITICAL")

CLOUDFORMATION_PARAMETERS = ["AUTO_ENABLE_S3_LOGS", "AWS_PARTITION", "CONFIGURATION_ROLE_NAME",
                             "DELEGATED_ADMIN_ACCOUNT_ID", "DELETE_DETECTOR_ROLE_NAME", "ENABLED_REGIONS",
                             "FINDING_PUBLISHING_FREQUENCY", "KMS_KEY_ARN", "PUBLISHING_DESTINATION_BUCKET_ARN"]
SERVICE_ROLE_NAME = "AWSServiceRoleForAmazonGuardDuty"
SERVICE_NAME = "guardduty.amazonaws.com"
PAGE_SIZE = 20  # Max page size for list_accounts
MAX_RUN_COUNT = 18  # 3 minute wait = 18 x 10 seconds
SLEEP_SECONDS = 10
MAX_THREADS = 10
STS_CLIENT = boto3.client('sts')

try:
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

except Exception as e:
    logger.error(f"{e}")
    helper.init_failure(e)


def get_service_client(aws_service: str, aws_region: str, session=None):
    """
    Get boto3 client for an AWS service
    :param aws_service:
    :param aws_region:
    :param session:
    :return: service client
    """
    if aws_region:
        if session:
            service_client = session.client(aws_service, region_name=aws_region)
        else:
            service_client = boto3.client(aws_service, aws_region)
    else:
        if session:
            service_client = session.client(aws_service)
        else:
            service_client = boto3.client(aws_service)
    return service_client


def is_region_available(region):
    """
    Check if the region is available
    :param region:
    :return:
    """
    regional_sts = boto3.client('sts', region_name=region)
    try:
        regional_sts.get_caller_identity()
        return True
    except ClientError as error:
        if "InvalidClientTokenId" in str(error):
            logger.info(f"Region: {region} is not available")
            return False
        else:
            logger.error(f"{error}")


def get_available_service_regions(user_regions: str, aws_service: str) -> list:
    """
    Get the available regions for the AWS service
    :param: user_regions
    :param: aws_service
    :return: available region list
    """
    available_regions = []
    try:
        if user_regions.strip():
            logger.info(f"USER REGIONS: {str(user_regions)}")
            service_regions = [value.strip() for value in user_regions.split(",") if value != '']
        else:
            service_regions = boto3.session.Session().get_available_regions(
                aws_service
            )
        logger.info(f"SERVICE REGIONS: {service_regions}")
    except ClientError as ce:
        logger.error(f"get_available_service_regions error: {ce}")
        raise ValueError("Error getting service regions")

    for region in service_regions:
        if is_region_available(region):
            available_regions.append(region)

    logger.info(f"AVAILABLE REGIONS: {available_regions}")
    return available_regions


def get_all_organization_accounts(exclude_account_id: str):
    """
    Gets a list of active AWS Accounts in the AWS Organization
    :param exclude_account_id
    :return: accounts dict and account_id lists
    """
    accounts = []  # used for create_members
    account_ids = []  # used for disassociate_members

    try:
        organizations = boto3.client("organizations")
        paginator = organizations.get_paginator("list_accounts")

        for page in paginator.paginate(PaginationConfig={"PageSize": PAGE_SIZE}):
            for acct in page["Accounts"]:
                if exclude_account_id and acct["Id"] not in exclude_account_id:
                    if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                        account_record = {"AccountId": acct["Id"], "Email": acct["Email"]}
                        accounts.append(account_record)
                        account_ids.append(acct["Id"])
    except Exception as exc:
        logger.error(f"get_all_organization_accounts error: {exc}")
        raise ValueError("Error error getting accounts")

    return accounts, account_ids


def assume_role(aws_account_number: str, aws_partition: str, role_name: str, session_name: str):
    """
    Assumes the provided role in the provided account and returns a session
    :param aws_account_number: AWS Account Number
    :param aws_partition: AWS partition
    :param role_name: Role name to assume in target account
    :param session_name: Session name
    :return: session for the account and role name
    """
    try:
        response = STS_CLIENT.assume_role(
            RoleArn=f"arn:{aws_partition}:iam::{aws_account_number}:role/{role_name}",
            RoleSessionName=session_name,
        )
        # Storing STS credentials
        session = boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )
        logger.debug(f"Assumed session for {aws_account_number}")

        return session
    except Exception as exc:
        logger.error(f"Unexpected error: {exc}")
        raise ValueError("Error assuming role")


def gd_create_members(guardduty_client, detector_id: str, accounts: list):
    """
    Create GuardDuty members with existing accounts. Retry 2 times.
    :param guardduty_client:
    :param detector_id:
    :param accounts:
    :return:
    """
    try:
        logger.info("Creating members")
        create_members_response = guardduty_client.create_members(DetectorId=detector_id, AccountDetails=accounts)

        if "UnprocessedAccounts" in create_members_response and create_members_response["UnprocessedAccounts"]:
            unprocessed = True
            retry_count = 0
            unprocessed_accounts = []
            while unprocessed:
                retry_count += 1
                logger.info(f"Unprocessed Accounts: {create_members_response['UnprocessedAccounts']}")
                remaining_accounts = []

                for unprocessed_account in create_members_response["UnprocessedAccounts"]:
                    account_id = unprocessed_account["AccountId"]
                    account_info = [account_record for account_record in accounts if
                                    account_record["AccountId"] == account_id]
                    remaining_accounts.append(account_info[0])

                if remaining_accounts:
                    create_members_response = guardduty_client.create_members(DetectorId=detector_id,
                                                                              AccountDetails=remaining_accounts)
                    if "UnprocessedAccounts" in create_members_response \
                            and create_members_response["UnprocessedAccounts"]:
                        unprocessed_accounts = create_members_response["UnprocessedAccounts"]
                        if retry_count == 2:
                            unprocessed = False
                    else:
                        unprocessed = False

            if unprocessed_accounts:
                logger.info(f"Unprocessed Member Accounts: {unprocessed_accounts}")
                raise ValueError(f"Unprocessed Member Accounts")
    except Exception as exc:
        logger.error(f"{exc}")
        raise ValueError(f"Error Creating Member Accounts")


def update_member_detectors(guardduty_client, detector_id: str, account_ids: list):
    """
    update member detectors
    :param guardduty_client: GuardDuty client
    :param detector_id: GuardDuty detector id
    :param account_ids: member account list
    :return: None
    """
    try:
        configuration_params = {
            "DetectorId": detector_id,
            "AccountIds": account_ids,
            "DataSources": {"S3Logs": {"Enable": True}}
        }
        update_member_response = guardduty_client.update_member_detectors(**configuration_params)

        if "UnprocessedAccounts" in update_member_response and update_member_response["UnprocessedAccounts"]:
            unprocessed = True
            retry_count = 0
            unprocessed_accounts = []
            while unprocessed:
                time.sleep(SLEEP_SECONDS)
                retry_count += 1
                remaining_accounts = []

                for unprocessed_account in update_member_response["UnprocessedAccounts"]:
                    if unprocessed_account["AccountId"] in account_ids:
                        remaining_accounts.append(unprocessed_account["AccountId"])

                if remaining_accounts:
                    configuration_params["AccountIds"] = remaining_accounts
                    update_member_response = guardduty_client.update_member_detectors(**configuration_params)
                    if "UnprocessedAccounts" in update_member_response \
                            and update_member_response["UnprocessedAccounts"]:
                        unprocessed_accounts = update_member_response["UnprocessedAccounts"]
                        if retry_count == 2:
                            unprocessed = False
                    else:
                        unprocessed = False

            if unprocessed_accounts:
                logger.info(f"Update Member Detectors Unprocessed Member Accounts: {unprocessed_accounts}")
                raise ValueError(f"Unprocessed Member Accounts")
    except Exception as error:
        logger.error(f"update member detectors error: {error}")
        raise ValueError("Error updating member detectors")


def update_guardduty_configuration(guardduty_client, auto_enable_s3_logs: bool, detector_id: str,
                                   finding_publishing_frequency: str, account_ids: list):
    """
    Update GuardDuty configuration to auto enable new accounts and S3 log protection
    :param guardduty_client: GuardDuty Client
    :param auto_enable_s3_logs:
    :param detector_id: GuardDuty detector ID
    :param finding_publishing_frequency:
    :param account_ids: List of member account ids
    :return: None
    """
    try:
        org_configuration_params = {"DetectorId": detector_id, "AutoEnable": True}
        admin_configuration_params = {
            "DetectorId": detector_id,
            "FindingPublishingFrequency": finding_publishing_frequency
        }

        if auto_enable_s3_logs:
            org_configuration_params["DataSources"] = {"S3Logs": {"AutoEnable": True}}
            admin_configuration_params["DataSources"] = {"S3Logs": {"Enable": True}}

        guardduty_client.update_organization_configuration(**org_configuration_params)
        guardduty_client.update_detector(**admin_configuration_params)
        update_member_detectors(guardduty_client, detector_id, account_ids)
    except ClientError as error:
        logger.error(f"update_guardduty_configuration {error}")
        raise ValueError(f"Error updating GuardDuty configuration")


def configure_guardduty(session, delegated_account_id: str, auto_enable_s3_logs: bool, available_regions: list,
                        finding_publishing_frequency: str, kms_key_arn: str, publishing_destination_arn: str):
    """
    Configure GuardDuty with provided parameters
    :param session:
    :param delegated_account_id:
    :param auto_enable_s3_logs:
    :param available_regions:
    :param finding_publishing_frequency:
    :param kms_key_arn:
    :param publishing_destination_arn:
    :return: None
    """
    accounts, account_ids = get_all_organization_accounts(delegated_account_id)

    # Loop through the regions and enable GuardDuty
    for region in available_regions:
        try:
            regional_guardduty = get_service_client("guardduty", region, session)
            detectors = regional_guardduty.list_detectors()

            if detectors["DetectorIds"]:
                detector_id = detectors["DetectorIds"][0]
                logger.info(f"DetectorID: {detector_id} Region: {region}")

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
                logger.info(f"Members created for existing accounts: {accounts} in {region}")
                gd_create_members(regional_guardduty, detector_id, accounts)
                logger.info(f"Waiting {SLEEP_SECONDS} seconds")
                time.sleep(SLEEP_SECONDS)
                update_guardduty_configuration(regional_guardduty, auto_enable_s3_logs, detector_id,
                                               finding_publishing_frequency, account_ids)
        except Exception as exc:
            logger.error(f"configure_guardduty Exception: {exc}")
            raise ValueError(f"Configure GuardDuty Exception. Review logs for details.")


def create_service_linked_role(role_name: str, service_name: str):
    """
    Creates the service linked role if it does not exist
    :param role_name: Service Linked Role Name
    :param service_name: AWS Service Name
    :return: None
    """
    iam = boto3.client("iam")
    try:
        iam.get_role(RoleName=role_name)
        service_role_exists = True
    except iam.exceptions.NoSuchEntityException:
        service_role_exists = False
        logger.info(f"{role_name} does not exist")
    except Exception as exc:
        logger.error(f"IAM Get Role Exception: {exc}")
        raise ValueError(f"IAM API Exception. Review logs for details.")

    if not service_role_exists:
        try:
            iam.create_service_linked_role(AWSServiceName=service_name)
        except Exception as exc:
            logger.error(f"IAM Create Service Linked Role Exception: {exc}")
            raise ValueError(f"IAM API Exception. Review logs for details.")


def check_for_detectors(session, available_regions: list) -> bool:
    """
    Check to see if the GuardDuty detectors exist before configuring
    :param session:
    :param available_regions:
    :return: True or False
    """
    detectors_exist = False

    for region in available_regions:
        try:
            guardduty = get_service_client("guardduty", region, session)
            paginator = guardduty.get_paginator("list_detectors")

            for page in paginator.paginate():
                if "DetectorIds" in page and page["DetectorIds"]:
                    detectors_exist = True
                else:
                    detectors_exist = False
                    logger.info(f"Detector Does Not Exist in {region}")
        except botocore.exceptions.ClientError as ce:
            if "AccessDeniedException" in str(ce):
                logger.debug(f"Detector not found in {region}")
                detectors_exist = False
                break
            else:
                logger.info(f"Unexpected Client Exception for {region}: {ce}")
        except Exception as exc:
            logger.error(f"GuardDuty Exception {region}: {exc}")
            raise ValueError(f"GuardDuty API Exception: {exc}")

    return detectors_exist


def get_associated_members(guardduty, detector_id):
    """
    Get associated GuardDuty members
    :param guardduty: GuardDuty Client
    :param detector_id: GuardDuty Detector ID
    :return: account_ids
    """
    account_ids = []

    try:
        paginator = guardduty.get_paginator("list_members")

        for page in paginator.paginate(DetectorId=detector_id, OnlyAssociated="false",
                                       PaginationConfig={"PageSize": 20}):
            for member in page["Members"]:
                account_ids.append(member["AccountId"])
    except ClientError as ce:
        logger.error(f"get_associated_members error: {str(ce)}")
        raise ValueError("Error getting associated members")

    return account_ids


def enable_organization_admin_account(admin_account_id: str, available_regions: list):
    """
    Enable delegated admin account for each region
    :param admin_account_id:
    :param available_regions:
    :return: None
    """
    # Loop through the regions and enable GuardDuty
    for region in available_regions:
        try:
            guardduty = get_service_client("guardduty", region)
            response = guardduty.list_organization_admin_accounts()

            if not response["AdminAccounts"]:
                enable_admin_account = True
                logger.info(f"GuardDuty delegated admin {admin_account_id} enabled in {region}")
            else:
                admin_account = [admin_account for admin_account in response["AdminAccounts"]
                                 if admin_account["AdminAccountId"] == admin_account_id]
                if admin_account:
                    enable_admin_account = False
                    logger.info(f"GuardDuty delegated admin {admin_account_id} already enabled in {region}")
                else:
                    enable_admin_account = True

            if enable_admin_account:
                guardduty.enable_organization_admin_account(AdminAccountId=admin_account_id)

        except Exception as error:
            logger.error(f"GuardDuty Exception {region}: {error}")
            raise ValueError(f"GuardDuty API Exception. Review logs for details.")


def disable_organization_admin_account(regional_guardduty, region: str):
    """
    Disable the organization admin account
    :param regional_guardduty:
    :param region:
    :return:
    """
    try:
        response = regional_guardduty.list_organization_admin_accounts()
        if "AdminAccounts" in response and response["AdminAccounts"]:
            for admin_account in response["AdminAccounts"]:
                admin_account_id = admin_account["AdminAccountId"]
                if admin_account["AdminStatus"] == "ENABLED":
                    regional_guardduty.disable_organization_admin_account(AdminAccountId=admin_account_id)
                    logger.info(f"GuardDuty Admin Account {admin_account_id} Disabled in {region}")
        else:
            logger.info(f"No GuardDuty Admin Accounts in {region}")
    except ClientError as error:
        logger.error(f"disable_organization_admin_account ClientError: {error}")
        raise ValueError(f"Error disabling admin account in {region}")


def check_parameters(event: dict):
    """
    Check event for required parameters in the ResourceProperties
    :param event:
    :return:
    """
    try:
        if "StackId" not in event or "ResourceProperties" not in event:
            raise ValueError("Invalid CloudFormation request, missing StackId or ResourceProperties.")

        # Check CloudFormation parameters
        for parameter in CLOUDFORMATION_PARAMETERS:
            if parameter not in event.get("ResourceProperties", ""):
                raise ValueError("Invalid CloudFormation request, missing one or more ResourceProperties.")

        logger.debug(f"Stack ID : {event.get('StackId')}")
        logger.debug(f"Stack Name : {event.get('StackId').split('/')[1]}")
    except Exception as error:
        logger.error(f"Exception checking parameters {error}")
        raise ValueError("Error checking parameters")


@helper.create
@helper.update
def create(event, context):
    """
    CloudFormation Create Event.
    :param event: event data
    :param context: runtime information
    :return: GuardDutyResourceId
    """
    request_type = event["RequestType"]
    logger.info(f"{request_type} Event")

    try:
        check_parameters(event)
        params = event.get("ResourceProperties")

        # Required to enable GuardDuty in the Org Management account from the delegated admin
        create_service_linked_role(SERVICE_ROLE_NAME, SERVICE_NAME)

        available_regions = get_available_service_regions(params.get("ENABLED_REGIONS", ""), "guardduty")

        enable_organization_admin_account(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), available_regions)
        session = assume_role(
            params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
            params.get("AWS_PARTITION", "aws"),
            params.get("CONFIGURATION_ROLE_NAME", ""),
            "CreateGuardDuty"
        )
        detectors_exist = False
        run_count = 0

        while not detectors_exist and run_count < MAX_RUN_COUNT:
            run_count += 1
            detectors_exist = check_for_detectors(session, available_regions)
            logger.info(f"All Detectors Exist: {detectors_exist} Count: {run_count}")
            if not detectors_exist:
                time.sleep(SLEEP_SECONDS)

        if detectors_exist:
            auto_enable_s3_logs = (params.get("AUTO_ENABLE_S3_LOGS", "false")).lower() in "true"

            configure_guardduty(
                session,
                params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
                auto_enable_s3_logs,
                available_regions,
                params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES"),
                params.get("KMS_KEY_ARN", ""),
                params.get("PUBLISHING_DESTINATION_BUCKET_ARN", "")
            )
        else:
            raise ValueError(
                "GuardDuty Detectors did not get created in the allowed time. "
                "Check the Org Management delegated admin setup."
            )
    except Exception as exc:
        logger.error(f"Unexpected error {exc}")
        raise ValueError("Unexpected error. Review logs for details.")

    if request_type == "Create":
        return "GuardDutyResourceId"


def delete_detectors(guardduty_client, region: str, is_delegated_admin: bool = False):
    """
    Delete GuardDuty Detectors
    :param guardduty_client:
    :param region:
    :param is_delegated_admin:
    :return:
    """
    try:
        detectors = guardduty_client.list_detectors()

        if detectors["DetectorIds"]:
            for detector_id in detectors["DetectorIds"]:
                if is_delegated_admin:
                    account_ids = get_associated_members(guardduty_client, detector_id)
                    logger.info(f"Account IDs: {account_ids}")

                    if account_ids:
                        guardduty_client.disassociate_members(DetectorId=detector_id, AccountIds=account_ids)
                        logger.info(f"GuardDuty accounts disassociated in {region}")

                        guardduty_client.delete_members(DetectorId=detector_id, AccountIds=account_ids)
                        logger.info(f"GuardDuty members deleted in {region}")

                guardduty_client.delete_detector(DetectorId=detector_id)
    except ClientError as error:
        logger.error(f"delete_detectors ClientError: {error}")
        raise ValueError(f"Error deleting the detector in {region}")


def cleanup_member_account(account_id: str, aws_partition: str, delete_detector_role_name: str,
                           available_regions: list):
    """
    cleanup member account
    :param account_id:
    :param aws_partition:
    :param delete_detector_role_name:
    :param available_regions:
    :return:
    """

    try:
        session = assume_role(
            account_id,
            aws_partition,
            delete_detector_role_name,
            "DeleteGuardDuty"
        )

        for region in available_regions:
            try:
                logger.info(f"Deleting GuardDuty detector in {account_id} {region}")
                session_guardduty = get_service_client("guardduty", region, session)
                delete_detectors(session_guardduty, region, False)
            except Exception as exc:
                logger.error(f"Error deleting GuardDuty detector in {account_id} {region} Exception: {exc}")
                raise ValueError(f"Error deleting GuardDuty detector in {account_id} {region}")
    except Exception as exc:
        logger.error(f"Unable to assume {delete_detector_role_name} in {account_id} {exc}")


def deregister_delegated_administrator(session, delegated_admin_account_id: str,
                                       service_principal: str = SERVICE_NAME):
    """
    Deregister the delegated administrator account for the provided service principal within AWS Organizations
    :param session:
    :param delegated_admin_account_id:
    :param service_principal:
    :return:
    """
    try:
        logger.info(f"Deregistering the delegated admin {delegated_admin_account_id} for {service_principal}")
        organizations_client = get_service_client("organizations", "", session)
        organizations_client.deregister_delegated_administrator(
            AccountId=delegated_admin_account_id,
            ServicePrincipal=service_principal
        )
    except organizations_client.exceptions.AccountNotRegisteredException as error:
        logger.debug(f"Account is not a registered delegated administrator: {error}")
    except Exception as error:
        logger.error(f"Error deregister_delegated_administrator: {error}")
        raise ValueError("Error during deregister delegated administrator")


@helper.delete
def delete(event, context):
    """
    CloudFormation Delete Event.
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("Delete Event")
    try:
        check_parameters(event)
        params = event.get("ResourceProperties")

        available_regions = get_available_service_regions(params.get("ENABLED_REGIONS", ""), "guardduty")
        session = assume_role(
            params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
            params.get("AWS_PARTITION", "aws"),
            params.get("CONFIGURATION_ROLE_NAME", ""),
            "DeleteGuardDuty")
        # Loop through the regions and disable GuardDuty in the delegated admin account
        for region in available_regions:
            try:
                regional_guardduty = get_service_client("guardduty", region)
                disable_organization_admin_account(regional_guardduty, region)

                # Delete Detectors in the Delegated Admin Account
                session_guardduty = get_service_client("guardduty", region, session)
                delete_detectors(session_guardduty, region, True)
            except Exception as exc:
                logger.error(f"GuardDuty Exception: {exc}")
                raise ValueError(f"GuardDuty API Exception: {exc}")

        deregister_delegated_administrator(session, params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), SERVICE_NAME)
        accounts, account_ids = get_all_organization_accounts(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""))

        # Cleanup member account GuardDuty detectors
        start = now()
        processes = []
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for account_id in account_ids:
                try:
                    processes.append(executor.submit(
                        cleanup_member_account,
                        account_id,
                        params.get("AWS_PARTITION", "aws"),
                        params.get("DELETE_DETECTOR_ROLE_NAME", ""),
                        available_regions
                    ))
                except Exception as error:
                    logger.error(f"{error}")
                    continue
        for task in as_completed(processes):
            logger.info(f"process task - {task.result()}")

        logger.info(f"Time taken to delete member account detectors: {now() - start}")
    except Exception as exc:
        logger.error(f"Unexpected error {exc}")
        raise ValueError("Unexpected error. Review logs for details.")


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("....Lambda Handler Started....")
    helper(event, context)
