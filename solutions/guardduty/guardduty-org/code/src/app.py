########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
import re
import time
import boto3
import botocore
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

"""
The purpose of this script is to configure GuardDuty within the delegated 
administrator account in all provided regions to add existing accounts, enable new accounts 
automatically, and publish findings to an S3 bucket.
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level="CRITICAL")

SERVICE_ROLE_NAME = "AWSServiceRoleForAmazonGuardDuty"
SERVICE_NAME = "guardduty.amazonaws.com"
PAGE_SIZE = 20  # Max page size for list_accounts
MAX_RUN_COUNT = 16  # 8 minute wait = 16 x 30 seconds
SLEEP_SECONDS = 30
STS_CLIENT = boto3.client('sts')

try:
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

    CONFIGURATION_ROLE_NAME = os.environ.get("CONFIGURATION_ROLE_NAME", "")
    if not CONFIGURATION_ROLE_NAME or not re.match("[\\w+=,.@-]+", CONFIGURATION_ROLE_NAME):
        raise ValueError("DELEGATED_ADMIN_ROLE_NAME missing or invalid")

    DELETE_DETECTOR_ROLE_NAME = os.environ.get("DELETE_DETECTOR_ROLE_NAME", "")
    if not DELETE_DETECTOR_ROLE_NAME or not re.match("[\\w+=,.@-]+", DELETE_DETECTOR_ROLE_NAME):
        raise ValueError("DELETE_DETECTOR_ROLE_NAME missing or invalid")

    DELEGATED_ADMIN_ACCOUNT_ID = os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID", "")
    if not DELEGATED_ADMIN_ACCOUNT_ID or not re.match("^[0-9]{12}$", DELEGATED_ADMIN_ACCOUNT_ID):
        raise ValueError("DELEGATED_ADMIN_ACCOUNT_ID missing or invalid")

    PUBLISHING_DESTINATION_BUCKET_ARN = os.environ.get(
        "PUBLISHING_DESTINATION_BUCKET_ARN", ""
    )
    if not PUBLISHING_DESTINATION_BUCKET_ARN or not isinstance(
        PUBLISHING_DESTINATION_BUCKET_ARN, str
    ):
        raise ValueError("PUBLISHING_DESTINATION_BUCKET_NAME missing or invalid")

    KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN", "")
    if not KMS_KEY_ARN or not isinstance(KMS_KEY_ARN, str):
        raise ValueError("KMS_KEY_ARN missing or invalid")

    ENABLED_REGIONS = os.environ.get("ENABLED_REGIONS", "")  # 'us-east-1,us-east-2'
    if not isinstance(ENABLED_REGIONS, str):
        raise ValueError("ENABLED_REGIONS missing or invalid")

    AWS_PARTITION = os.environ.get("AWS_PARTITION", "")
    if AWS_PARTITION not in ("aws", "aws-cn", "aws-us-gov"):
        raise ValueError("AWS_PARTITION parameter is missing or invalid")

    AUTO_ENABLE_S3_LOGS = (os.environ.get("AUTO_ENABLE_S3_LOGS", "false")).lower() in "true"

except Exception as e:
    logger.error(f"{e}")
    helper.init_failure(e)


def get_service_client(aws_service: str, aws_region: str, session=None):
    """
    Get boto3 client for an AWS service
    :param session:
    :param aws_service:
    :param aws_region:
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


def get_all_organization_accounts(account_info: bool, exclude_account_id: str):
    """
    Gets a list of active AWS Accounts in the AWS Organization
    :param account_info: True = return account info dict, False = return account id list
    :param exclude_account_id
    :return: accounts dict or account_id list
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
    except ClientError as ce:
        logger.error(f"get_all_organization_accounts error: {ce}")
        raise ValueError("Error getting accounts")
    except Exception as exc:
        logger.error(f"get_all_organization_accounts error: {exc}")
        raise ValueError("Unexpected error getting accounts")

    if account_info:
        return accounts

    return account_ids


def assume_role(aws_account_number, role_name, session_name):
    """
    Assumes the provided role in the provided account and returns a session
    :param aws_account_number: AWS Account Number
    :param role_name: Role name to assume in target account
    :param session_name: Session name
    :return: session for the account and role name
    """
    try:
        response = STS_CLIENT.assume_role(
            RoleArn=f"arn:{AWS_PARTITION}:iam::{aws_account_number}:role/{role_name}",
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


def update_guardduty_configuration(guardduty_client, detector_id: str):
    """
    Update GuardDuty configuration to auto enable new accounts and S3 log protection
    :param guardduty_client: GuardDuty Client
    :param detector_id: GuardDuty detector ID
    :return: None
    """
    try:
        org_configuration_params = {
            "DetectorId": detector_id,
            "AutoEnable": True
        }
        admin_configuration_params = {
            "DetectorId": detector_id
        }

        if AUTO_ENABLE_S3_LOGS:
            org_configuration_params["DataSources"] = {"S3Logs": {"AutoEnable": AUTO_ENABLE_S3_LOGS}}
            admin_configuration_params["DataSources"] = {"S3Logs": {"Enable": AUTO_ENABLE_S3_LOGS}}

        guardduty_client.update_organization_configuration(**org_configuration_params)
        guardduty_client.update_detector(**admin_configuration_params)
    except ClientError as error:
        logger.error(f"update_guardduty_configuration {error}")
        raise ValueError(f"Error updating GuardDuty configuration")


def configure_guardduty(session, delegated_account_id: str, available_regions: list):
    """
    Configure GuardDuty with provided parameters
    :param session:
    :param delegated_account_id:
    :param available_regions:
    :return: None
    """
    accounts = get_all_organization_accounts(True, delegated_account_id)
    publishing_destination_arn = PUBLISHING_DESTINATION_BUCKET_ARN

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
                            "KmsKeyArn": KMS_KEY_ARN,
                        },
                    )
                else:
                    # Create Publish Destination
                    regional_guardduty.create_publishing_destination(
                        DetectorId=detector_id,
                        DestinationType="S3",
                        DestinationProperties={
                            "DestinationArn": publishing_destination_arn,
                            "KmsKeyArn": KMS_KEY_ARN,
                        },
                    )

                # Create members for existing Organization accounts
                logger.info(f"Members created for existing accounts: {accounts} in {region}")
                gd_create_members(regional_guardduty, detector_id, accounts)
                update_guardduty_configuration(regional_guardduty, detector_id)

        except Exception as exc:
            logger.error(f"configure_guardduty Exception: {exc}")
            raise ValueError(f"Configure GuardDuty Exception. Review logs for details.")


def create_service_linked_role(role_name, service_name):
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

        for page in paginator.paginate(
            DetectorId=detector_id,
            OnlyAssociated="false",
            PaginationConfig={"PageSize": 20},
        ):
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

        except ClientError as error:
            logger.error(f"Unexpected Client Exception for {region}: {error}")
        except Exception as exc:
            logger.error(f"GuardDuty Exception {region}: {exc}")
            raise ValueError(f"GuardDuty API Exception. Review logs for details.")


def disable_organization_admin_account(regional_guardduty, region):
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
                    regional_guardduty.disable_organization_admin_account(
                        AdminAccountId=admin_account_id
                    )
                    logger.info(f"GuardDuty Admin Account {admin_account_id} Disabled in {region}")
        else:
            logger.info(f"No GuardDuty Admin Accounts in {region}")
    except ClientError as error:
        logger.error(f"disable_organization_admin_account ClientError: {error}")
        raise ValueError(f"Error disabling admin account in {region}")


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
    # Required to enable GuardDuty in the Org Master account from the delegated admin
    create_service_linked_role(SERVICE_ROLE_NAME, SERVICE_NAME)

    try:
        available_regions = get_available_service_regions(ENABLED_REGIONS, "guardduty")
        enable_organization_admin_account(DELEGATED_ADMIN_ACCOUNT_ID, available_regions)
        session = assume_role(DELEGATED_ADMIN_ACCOUNT_ID, CONFIGURATION_ROLE_NAME, "CreateGuardDuty")
        detectors_exist = False
        run_count = 0
        while not detectors_exist and run_count < MAX_RUN_COUNT:
            run_count += 1
            detectors_exist = check_for_detectors(session, available_regions)
            logger.info(f"All Detectors Exist: {detectors_exist} Count: {run_count}")
            if not detectors_exist:
                time.sleep(SLEEP_SECONDS)

        if detectors_exist:
            configure_guardduty(session, DELEGATED_ADMIN_ACCOUNT_ID, available_regions)
        else:
            raise ValueError(
                "GuardDuty Detectors did not get created in the allowed time. "
                "Check the Org Master delegated admin setup."
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
                        guardduty_client.disassociate_members(
                            DetectorId=detector_id, AccountIds=account_ids
                        )
                        logger.info(f"GuardDuty accounts disassociated in {region}")

                        guardduty_client.delete_members(
                            DetectorId=detector_id, AccountIds=account_ids
                        )
                        logger.info(f"GuardDuty members deleted in {region}")

                guardduty_client.delete_detector(DetectorId=detector_id)
    except ClientError as error:
        logger.error(f"delete_detectors ClientError: {error}")
        raise ValueError(f"Error deleting the detector in {region}")


@helper.delete
def delete(event, context):
    """
    CloudFormation Delete Event.
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("Delete Event")
    available_regions = get_available_service_regions(ENABLED_REGIONS, "guardduty")
    session = assume_role(DELEGATED_ADMIN_ACCOUNT_ID, CONFIGURATION_ROLE_NAME, "DeleteGuardDuty")
    # Loop through the regions and disable GuardDuty
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

    accounts = get_all_organization_accounts(False, DELEGATED_ADMIN_ACCOUNT_ID)

    # Cleanup member account GuardDuty detectors
    for account_id in accounts:
        try:
            session = assume_role(account_id, DELETE_DETECTOR_ROLE_NAME, "DeleteGuardDuty")

            for region in available_regions:
                try:
                    logger.info(f"Deleting GuardDuty detector in {account_id} {region}")
                    session_guardduty = get_service_client("guardduty", region, session)
                    delete_detectors(session_guardduty, region, False)
                except Exception as exc:
                    logger.error(f"Error deleting GuardDuty detector in {account_id} {region} Exception: {exc}")
                    raise ValueError(f"Error deleting GuardDuty detector in {account_id} {region}")
        except Exception as exc:
            logger.error(f"Unable to assume {DELETE_DETECTOR_ROLE_NAME} in {account_id} {exc}")
            continue


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("....Lambda Handler Started....")
    helper(event, context)