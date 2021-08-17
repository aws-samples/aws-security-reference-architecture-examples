########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

"""
The purpose of this script is to configure Macie within the delegated 
administrator account in all provided regions to add existing accounts, enable new accounts 
automatically, and publish findings to an S3 bucket.
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level="CRITICAL")

CLOUDFORMATION_PARAMETERS = ["AWS_PARTITION", "CONFIGURATION_ROLE_NAME", "CONTROL_TOWER_REGIONS_ONLY",
                             "DELEGATED_ADMIN_ACCOUNT_ID", "DISABLE_MACIE_ROLE_NAME", "ENABLED_REGIONS", "KMS_KEY_ARN",
                             "S3_BUCKET_NAME"]

ROLE_NAME = "AWSServiceRoleForAmazonMacie"
AWS_SERVICE_PRINCIPAL = "macie.amazonaws.com"
PAGE_SIZE = 20  # Max page size for list_accounts
STS_CLIENT = boto3.client('sts')

try:
    # Environment Variables
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


def enable_aws_service_access(service_principal: str):
    """
    Enables the AWS Service Access for the provided service principal
    :param service_principal: AWS Service Principal format: service_name.amazonaws.com
    :return: None
    """
    logger.info("Enable AWS Service Access for: " + str(service_principal))

    try:
        organizations = boto3.client("organizations")
        organizations.enable_aws_service_access(ServicePrincipal=service_principal)
    except Exception as exc:
        logger.error(f"Exception: {str(exc)}")
        raise


def get_service_client(aws_service: str, aws_region: str):
    """
    Get boto3 client
    :param aws_service:
    :param aws_region:
    :return: service client
    """
    if aws_region:
        return boto3.client(aws_service, aws_region)
    else:
        return boto3.client(aws_service)


def get_session_client(session, aws_service: str, aws_region: str):
    """
    Get boto3 client
    :param session:
    :param aws_service:
    :param aws_region:
    :return: service client
    """
    if aws_region:
        return session.client(aws_service, region_name=aws_region)
    else:
        return boto3.client(aws_service)


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

        logger.error(f"{error}")


def get_available_service_regions(user_regions: str, aws_service: str,
                                  control_tower_regions_only: bool = False) -> list:
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
        elif control_tower_regions_only:
            cf_client = boto3.Session().client('cloudformation')
            paginator = cf_client.get_paginator("list_stack_instances")
            region_set = set()
            for page in paginator.paginate(StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH"):
                for summary in page["Summaries"]:
                    region_set.add(summary["Region"])
            service_regions = list(region_set)
        else:
            service_regions = boto3.session.Session().get_available_regions(aws_service)
        logger.info(f"SERVICE REGIONS: {service_regions}")
    except ClientError as ce:
        logger.error(f"get_available_service_regions error: {ce}")
        raise ValueError("Error getting service regions")

    for region in service_regions:
        if is_region_available(region):
            available_regions.append(region)

    logger.info(f"AVAILABLE REGIONS: {available_regions}")
    return available_regions


def get_all_organization_accounts(exclude_account_id: str = "111"):
    """
    Gets a list of active AWS Accounts in the AWS Organization
    :param exclude_account_id: account id to exclude
    :return: accounts dict, account_id list
    """
    accounts = []  # used for create_members
    account_ids = []  # used for disassociate_members

    try:
        organizations = boto3.client("organizations")
        paginator = organizations.get_paginator("list_accounts")

        for page in paginator.paginate(PaginationConfig={"PageSize": PAGE_SIZE}):
            for acct in page["Accounts"]:
                if exclude_account_id and exclude_account_id != acct["Id"]:
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

    return accounts, account_ids


def assume_role(aws_account_number: str, role_name: str, session_name: str, aws_partition: str):
    """
    Assumes the provided role in the provided account and returns a session
    :param aws_account_number: AWS Account Number
    :param role_name: Role name to assume in target account
    :param session_name: Session name
    :param aws_partition: AWS Partition
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


def enable_organization_admin_account(admin_account_id: str, available_regions: list):
    """
    Enable delegated admin account for each region
    :param admin_account_id:
    :param available_regions:
    :return: None
    """
    for region in available_regions:
        try:
            service_client = get_service_client("macie2", region)
            response = service_client.list_organization_admin_accounts()

            if not response["adminAccounts"]:
                enable_admin_account = True
                logger.info(f"Delegated admin {admin_account_id} enabled in {region}")
            else:
                admin_account = [admin_account for admin_account in response["adminAccounts"]
                                 if admin_account["accountId"] == admin_account_id]
                if admin_account:
                    enable_admin_account = False
                    logger.info(f"Delegated admin {admin_account_id} already enabled in {region}")
                else:
                    enable_admin_account = True

            if enable_admin_account:
                service_client.enable_organization_admin_account(
                    adminAccountId=admin_account_id
                )

        except ClientError as error:
            logger.error(f"Unexpected Client Exception for {region}: {error}")
        except Exception as exc:
            logger.error(f"Exception {region}: {exc}")
            raise ValueError(f"API Exception. Review logs for details.")


def disable_organization_admin_account(service_client, region):
    """
    Disable the organization admin account
    :param service_client:
    :param region:
    :return: None
    """
    try:
        response = service_client.list_organization_admin_accounts()
        if "adminAccounts" in response and response["adminAccounts"]:
            for admin_account in response["adminAccounts"]:
                admin_account_id = admin_account["accountId"]
                if admin_account["status"] == "ENABLED":
                    service_client.disable_organization_admin_account(
                        adminAccountId=admin_account_id
                    )
                    logger.info(f"Admin Account {admin_account_id} Disabled in {region}")
        else:
            logger.info(f"No Admin Accounts in {region}")
    except ClientError as error:
        logger.error(f"disable_organization_admin_account ClientError: {error}")


def macie_create_members(service_client, accounts: list):
    """
    Create members with existing accounts.
    :param service_client:
    :param accounts:
    :return:
    """
    try:
        logger.info("Creating members")
        for existing_account in accounts:
            service_client.create_member(
                account={
                    'accountId': existing_account["AccountId"],
                    'email': existing_account["Email"]
                }
            )
    except Exception as exc:
        logger.error(f"{exc}")


def configure_macie(session, delegated_account_id: str, available_regions: list, s3_bucket_name: str, kms_key_arn: str):
    """
    Configure Macie with provided parameters
    :param session:
    :param delegated_account_id:
    :param available_regions:
    :param s3_bucket_name:
    :param kms_key_arn:
    :return: None
    """
    accounts, account_ids = get_all_organization_accounts(delegated_account_id)

    # Loop through the regions and enable Macie
    for region in available_regions:
        try:
            regional_client = get_session_client(session, "macie2", region)
            regional_client.put_classification_export_configuration(
                configuration={
                    's3Destination': {
                        'bucketName': s3_bucket_name,
                        'kmsKeyArn': kms_key_arn
                    }
                }
            )

            # Create members for existing Organization accounts
            logger.info(f"Existing Accounts: {accounts}")
            macie_create_members(regional_client, accounts)

            # Update Organization configuration to automatically enable new accounts
            regional_client.update_organization_configuration(
                autoEnable=True
            )
        except Exception as exc:
            logger.error(f"configure_macie Exception: {exc}")
            raise ValueError(f"API Exception. Review logs for details.")


def list_members(service_client):
    """
    List members
    :param service_client: Service Client
    :return: account_ids
    """
    account_ids = []

    try:
        paginator = service_client.get_paginator("list_members")

        for page in paginator.paginate(
                onlyAssociated="false",
                PaginationConfig={"PageSize": 20},
        ):
            for member in page["members"]:
                account_ids.append(member["accountId"])
    except ClientError as ce:
        logger.error(f"get_associated_members error: {ce}")
        raise ValueError(f"Error listing members")

    return account_ids


def delete_members(service_client, region: str):
    """
    Delete Members
    :param service_client:
    :param region:
    :return:
    """
    try:
        account_ids = list_members(service_client)
        logger.info(f"Account IDs: {account_ids}")

        if account_ids:
            for account_id in account_ids:
                service_client.disassociate_member(
                    id=account_id
                )
                logger.info(f"Member {account_id} disassociated in {region}")

                service_client.delete_member(
                    id=account_id
                )
                logger.info(f"Member {account_id} deleted in {region}")
            logger.info(f"Members deleted in {region}")
    except ClientError as error:
        logger.error(f"delete_members ClientError: {error}")
        raise ValueError(f"Error deleting the member in {region}")


def check_parameters(event: dict):
    """
    Check event for required parameters in the ResourceProperties
    :param event:
    :return: None
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
def create(event, _):
    """
    CloudFormation Create Event.
    :param event: event data
    :param _:
    :return: ResourceId
    """
    logger.debug(f"Create Event - {event}")

    try:
        check_parameters(event)
        params = event.get("ResourceProperties")
        control_tower_regions_only = (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true"

        enable_aws_service_access(AWS_SERVICE_PRINCIPAL)
        create_service_linked_role(ROLE_NAME, AWS_SERVICE_PRINCIPAL)

        available_regions = get_available_service_regions(params.get("ENABLED_REGIONS"), "macie2",
                                                          control_tower_regions_only)

        enable_organization_admin_account(params.get("DELEGATED_ADMIN_ACCOUNT_ID"), available_regions)
        session = assume_role(params.get("DELEGATED_ADMIN_ACCOUNT_ID"), params.get("CONFIGURATION_ROLE_NAME"),
                              "EnableMacie", params.get("AWS_PARTITION"))

        configure_macie(session, params.get("DELEGATED_ADMIN_ACCOUNT_ID"), available_regions,
                        params.get("S3_BUCKET_NAME"), params.get("KMS_KEY_ARN"))
    except Exception as exc:
        logger.error(f"Unexpected error {exc}")
        raise ValueError(f"Unexpected error. Review logs for details.")

    if event.get("RequestType") == "Create":
        return "MacieResourceId"


@helper.delete
def delete(event, _):
    """
    CloudFormation Delete Event.
    :param event: event data
    :param _:
    :return: CloudFormation response
    """
    try:
        logger.debug(f"Delete Event - {event}")
        check_parameters(event)
        params = event.get("ResourceProperties")
        control_tower_regions_only = (params.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true"
        available_regions = get_available_service_regions(params.get("ENABLED_REGIONS"), "macie2",
                                                          control_tower_regions_only)
        session = assume_role(params.get("DELEGATED_ADMIN_ACCOUNT_ID"), params.get("CONFIGURATION_ROLE_NAME"),
                              "DeleteMacie", params.get("AWS_PARTITION"))

        # Loop through the regions and disable Macie
        for region in available_regions:
            try:
                regional_client = get_service_client("macie2", region)
                session_client = get_session_client(session, "macie2", region)
                disable_organization_admin_account(regional_client, region)
                delete_members(session_client, region)
            except Exception as exc:
                logger.error(f"Exception: {exc}")
                raise ValueError(f"API Exception: {exc}")

        accounts, account_ids = get_all_organization_accounts("1")

        # Cleanup member accounts
        for account_id in account_ids:
            try:
                account_session = assume_role(account_id, params.get("DISABLE_MACIE_ROLE_NAME"), "DisableMacie",
                                              params.get("AWS_PARTITION"))
            except Exception as exc:
                logger.info(f"Unable to assume {params.get('DISABLE_MACIE_ROLE_NAME')} in {account_id} {exc}")
                continue

            for region in available_regions:
                try:
                    logger.info(f"Disabling Macie in {account_id} {region}")
                    session_client = get_session_client(account_session, "macie2", region)
                    session_client.disable_macie()
                except Exception as exc:
                    logger.info(f"Error Disabling Macie in {account_id} {region} Exception: {exc}")
                    continue
    except Exception as error:
        logger.error(f"Exception: {error}")
        raise ValueError(f"Delete event exception. See logs for error.")


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info(f"Event: {event}")
    helper(event, context)
