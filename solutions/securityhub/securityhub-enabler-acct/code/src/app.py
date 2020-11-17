########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import boto3
import json
import os
import re
import logging
import requests
from botocore.exceptions import ClientError

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

"""
The purpose of this script is to enable Security Hub within all the available 
AWS Organization accounts and regions. Security Hub standards will also get 
configured based on the parameters provided.
"""
try:
    SESSION = boto3.Session()

    LOG_LEVEL = os.environ.get("LOG_LEVEL")
    if isinstance(LOG_LEVEL, str):
        LOG_LEVEL = logging.getLevelName(LOG_LEVEL.upper())
        logger.setLevel(LOG_LEVEL)
    else:
        raise ValueError("LOG_LEVEL parameter is not a string")

    AWS_REGION = os.environ.get("AWS_REGION", "")
    SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

    MGMT_ACCOUNT_ID = os.environ["MGMT_ACCOUNT_ID"]
    if not MGMT_ACCOUNT_ID or not re.match("^[0-9]{12}$", MGMT_ACCOUNT_ID):
        raise ValueError("MGMT_ACCOUNT_ID parameter is missing or invalid")

    USER_REGIONS = os.environ.get("REGIONS_TO_ENABLE", "")

    ASSUME_ROLE_NAME = os.environ.get("ASSUME_ROLE", "")
    if not ASSUME_ROLE_NAME or not re.match("[\\w+=,.@-]+", ASSUME_ROLE_NAME):
        logger.error("ASSUME_ROLE is missing or invalid")
        raise ValueError("ASSUME_ROLE_NAME parameter is missing or invalid")

    ENABLE_CIS_STANDARD = (os.environ.get("ENABLE_CIS_STANDARD", "false")).lower() in "true"
    ENABLE_PCI_STANDARD = (os.environ.get("ENABLE_PCI_STANDARD", "false")).lower() in "true"
    ENABLE_SBP_STANDARD = (os.environ.get("ENABLE_SBP_STANDARD", "false")).lower() in "true"

    SBP_STANDARD_VERSION = os.environ.get("SBP_STANDARD_VERSION", "1.0.0")
    CIS_STANDARD_VERSION = os.environ.get("CIS_STANDARD_VERSION", "1.2.0")
    PCI_STANDARD_VERSION = os.environ.get("PCI_STANDARD_VERSION", "3.2.1")

    CONTROL_TOWER_REGIONS_ONLY = (os.environ.get("CONTROL_TOWER_REGIONS_ONLY", "false")).lower() in "true"
    ENABLE_PROWLER_INTEGRATION = (os.environ.get("ENABLE_PROWLER_INTEGRATION", "false")).lower() in "true"
    DISABLE_ALL_ACCOUNTS = (os.environ.get("DISABLE_ALL_ACCOUNTS", "false")).lower() in "true"
except Exception as e:
    logger.error(f"Unexpected error: {str(e)}")
    raise


def send_response(event, context, response_status, response_data, physical_resource_id=None, no_echo=False):
    """
    Send response
    :param event: CloudFormation event
    :param context:
    :param response_status:
    :param response_data:
    :param physical_resource_id:
    :param no_echo:
    :return: None
    """
    response_url = event["ResponseURL"]

    logger.info(response_url)
    ls = context.log_stream_name
    response_body = {
        "Status": response_status,
        "Reason": "See the details in CloudWatch Log Stream: " + ls,
        "PhysicalResourceId": physical_resource_id or ls,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": no_echo,
        "Data": response_data,
    }

    json_response_body = json.dumps(response_body)

    logger.info("Response body:\n" + json_response_body)

    headers = {"content-type": "", "content-length": str(len(json_response_body))}
    try:
        response = requests.put(response_url, data=json_response_body, headers=headers)
        logger.info("Status code: " + response.reason)
    except Exception as exc:
        logger.error(f"send(..) failed executing requests.put(..): {str(exc)}")


def get_validated_securityhub_regions(user_regions: str, control_tower_regions_only: bool = False):
    """
    Get the SecurityHub regions and check if they are enabled
    :param user_regions: User provided regions
    :param control_tower_regions_only: Control Tower regions only
    :return: validated SecurityHub regions
    """
    enabled_regions = []

    try:
        if user_regions:
            securityhub_regions = [value.strip() for value in user_regions.split(",") if value != '']
        elif control_tower_regions_only:
            cf_client = SESSION.client('cloudformation')
            paginator = cf_client.get_paginator("list_stack_instances")
            region_set = set()
            for page in paginator.paginate(
                StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH"
            ):
                for summary in page["Summaries"]:
                    region_set.add(summary["Region"])
            securityhub_regions = list(region_set)
        else:
            securityhub_regions = SESSION.get_available_regions("securityhub")

        logging.info(f"SecurityHub regions: {securityhub_regions}")
    except ClientError as ce:
        logger.error(f"Error getting available regions: {str(ce)}")
        raise

    for region in securityhub_regions:
        sts_client = SESSION.client("sts", region_name=region)
        try:
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except ClientError as ce:
            if ce.response["Error"]["Code"] == "InvalidClientTokenId":
                logger.info(f"{region} region is disabled")
            else:
                err = ce.response["Error"]
                logger.error(f"Error {err} occurred testing region {region}")
    return enabled_regions


def get_all_organization_accounts() -> dict:
    """
    Gets a list of Active AWS Accounts in the Organization.
    This is called if the function is not executed by an SNS trigger and
    used to periodically ensure all accounts are correctly configured, and
    prevent gaps in security from activities like new regions being added and
    SecurityHub being disabled.
    :return: AWS Account Dictionary
    """
    aws_accounts_dict = dict()

    try:
        org_client = SESSION.client("organizations", region_name="us-east-1")
        paginator = org_client.get_paginator("list_accounts")

        for page in paginator.paginate(PaginationConfig={"PageSize": 20}):
            for acct in page["Accounts"]:

                if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                    account_id = acct["Id"]
                    email = acct["Email"]
                    aws_accounts_dict.update({account_id: email})

        logger.info(
            "Active accounts count: {}, Active accounts: {}".format(
                len(aws_accounts_dict.keys()), json.dumps(aws_accounts_dict)
            )
        )
    except ClientError as ce:
        logger.error(f"Error: {str(ce)}")
        raise

    return aws_accounts_dict


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :return: Session object for the specified AWS Account and Region
    """
    try:
        sts_client = SESSION.client("sts")
        partition = sts_client.get_caller_identity()["Arn"].split(":")[1]
        response = sts_client.assume_role(
            RoleArn="arn:{}:iam::{}:role/{}".format(
                partition, aws_account_number, role_name
            ),
            RoleSessionName="EnableSecurityHub",
        )
        sts_session = boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )
        logger.info("Assumed session for {}.".format(aws_account_number))
        return sts_session
    except Exception as e:
        logging.error(f"{e}")


def get_mgmt_members(mgmt_session, aws_region):
    """
    Returns a list of current members of the SecurityHub management account
    :param mgmt_session: Security Hub Management Account Session
    :param aws_region: AWS Region of the SecurityHub management account
    :return: dict of AwsAccountId:MemberStatus
    """
    member_dict = dict()
    sh_client = mgmt_session.client("securityhub", region_name=aws_region)

    try:
        paginator = sh_client.get_paginator("list_members")
        operation_parameters = {"OnlyAssociated": False}
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            if page["Members"]:
                for member in page["Members"]:
                    member_dict.update({member["AccountId"]: member["MemberStatus"]})
        logger.info(f"Members of SecurityHub Management Account: {member_dict}")
    except Exception as exc:
        if "BadRequestException" in str(exc):
            logger.info("No members exist")
        else:
            raise ValueError(f"List members exception {exc}")
    return member_dict


def process_integrations(sh_client, partition, region, account_id):
    """
    Enable Security Hub Integrations
    :param sh_client: SecurityHub boto3 client
    :param partition: AWS Partition
    :param region: region to configure
    :param account_id: account to configure
    :return:
    """
    try:
        if ENABLE_PROWLER_INTEGRATION:
            logger.info(f"Enabling Prowler SecurityHub integration in  {account_id} {region}")
            prowler_product_arn = f"arn:{partition}:securityhub:{region}::product/prowler/prowler"
            sh_client.enable_import_findings_for_product(
                ProductArn=prowler_product_arn
            )
    except ClientError as error:
        if "InvalidAccessException" in str(error):
            logger.info(f"Account {account_id} is not subscribed to AWS Security Hub in {region}")
        elif "ResourceConflictException" in str(error):
            logger.info(f"SecurityHub integration already enabled in Account {account_id} and {region}")
        else:
            logger.error(f"Client Error: {error}")
    except Exception as exc:
        logger.error(f"Error Enabling SecurityHub integration in {account_id} {region} Exception: {exc}")
        raise ValueError(f"Enabling SecurityHub integration in {account_id} {region}")


def process_security_standards(sh_client, partition, region, account):
    """
    Configure the security standards
    :param sh_client: SecurityHub boto3 client
    :param partition: AWS partition
    :param region: region to configure
    :param account: account to configure
    :return: None
    """
    logger.info(f"Processing Security Standards for Account {account} " f"in {region}")
    # AWS Standard ARNs
    aws_standard_arn = (
        f"arn:{partition}:securityhub:{region}::standards/"
        f"aws-foundational-security-best-practices/v/{SBP_STANDARD_VERSION}"
    )
    aws_subscription_arn = (
        f"arn:{partition}:securityhub:{region}:{account}:"
        f"subscription/aws-foundational-security-best-practices"
        f"/v/{SBP_STANDARD_VERSION}"
    )
    logger.debug(f"ARN: {aws_standard_arn}")
    # CIS Standard ARNs
    cis_standard_arn = (
        f"arn:{partition}:securityhub:::ruleset/"
        f"cis-aws-foundations-benchmark/v/{CIS_STANDARD_VERSION}"
    )
    cis_subscription_arn = (
        f"arn:{partition}:securityhub:{region}:{account}:"
        f"subscription/cis-aws-foundations-benchmark"
        f"/v/{CIS_STANDARD_VERSION}"
    )
    logger.debug(f"ARN: {cis_standard_arn}")
    # PCI Standard ARNs
    pci_standard_arn = (
        f"arn:{partition}:securityhub:{region}::standards/" f"pci-dss/v/{PCI_STANDARD_VERSION}"
    )
    pci_subscription_arn = (
        f"arn:{partition}:securityhub:{region}:{account}:"
        f"subscription/pci-dss/v/{PCI_STANDARD_VERSION}"
    )
    logger.debug(f"ARN: {pci_standard_arn}")
    # Check for Enabled Standards
    aws_standard_enabled = False
    cis_standard_enabled = False
    pci_standard_enabled = False
    enabled_standards = sh_client.get_enabled_standards()
    logger.info(
        f"Account {account} in {region}. " f"Enabled Standards: {enabled_standards}"
    )
    for item in enabled_standards["StandardsSubscriptions"]:
        if aws_standard_arn in item["StandardsArn"]:
            aws_standard_enabled = True
        if cis_standard_arn in item["StandardsArn"]:
            cis_standard_enabled = True
        if pci_standard_arn in item["StandardsArn"]:
            pci_standard_enabled = True
    # Enable AWS Standard
    if ENABLE_SBP_STANDARD:
        if aws_standard_enabled:
            logger.info(
                f"AWS Foundational Security Best Practices "
                f"Security Standard is already enabled in Account "
                f"{account} in {region}"
            )
        else:
            try:
                sh_client.batch_enable_standards(
                    StandardsSubscriptionRequests=[{"StandardsArn": aws_standard_arn}]
                )
                logger.info(
                    f"Enabled AWS Foundational Security Best Practices "
                    f"Security Standard in Account {account} in "
                    f"{region}"
                )
            except Exception as error:
                logger.info(
                    f"Failed to enable AWS Foundational Security Best Practices "
                    f"Security Standard in Account {account} in "
                    f"{region} - {error}"
                )
    # Disable AWS Standard
    else:
        if not aws_standard_enabled:
            logger.info(
                f"AWS Foundational Security Best Practices v{SBP_STANDARD_VERSION} "
                f"Security Standard is already disabled in Account "
                f"{account} in {region}"
            )
        else:
            try:
                sh_client.batch_disable_standards(
                    StandardsSubscriptionArns=[aws_subscription_arn]
                )
                logger.info(
                    f"Disabled AWS Foundational Security Best Practices "
                    f"v{SBP_STANDARD_VERSION} Security Standard in Account {account} in "
                    f"{region}"
                )
            except Exception as error:
                logger.info(
                    f"Failed to disable AWS Foundational Security Best Practices "
                    f"Security Standard in Account {account} in "
                    f"{region} - {error}"
                )
    # Enable CIS Standard
    if ENABLE_CIS_STANDARD:
        if cis_standard_enabled:
            logger.info(
                f"CIS AWS Foundations Benchmark Security "
                f"Standard is already enabled in Account {account} "
                f"in {region}"
            )
        else:
            try:
                sh_client.batch_enable_standards(
                    StandardsSubscriptionRequests=[{"StandardsArn": cis_standard_arn}]
                )
                logger.info(
                    f"Enabled CIS AWS Foundations Benchmark "
                    f"Security Standard in Account {account} in {region}"
                )
            except Exception as error:
                logger.info(
                    f"Failed to enable CIS AWS Foundations Benchmark "
                    f"Security Standard in Account {account} in "
                    f"{region} - {error}"
                )
    # Disable CIS Standard
    else:
        if not cis_standard_enabled:
            logger.info(
                f"CIS AWS Foundations Benchmark Security "
                f"Standard is already disabled in Account {account} "
                f"in {region}"
            )
        else:
            try:
                sh_client.batch_disable_standards(
                    StandardsSubscriptionArns=[cis_subscription_arn]
                )
                logger.info(
                    f"Disabled CIS AWS Foundations Benchmark "
                    f"Security Standard in Account {account} in {region}"
                )
            except Exception as error:
                logger.info(
                    f"Failed to disable CIS AWS Foundations Benchmark "
                    f"Security Standard in Account {account} in "
                    f"{region} - {error}"
                )
    # Enable PCI Standard
    if ENABLE_PCI_STANDARD:
        if pci_standard_enabled:
            logger.info(
                f"PCI DSS v3.2.1 Security Standard is already "
                f"enabled in Account {account} in {region}"
            )
        else:
            try:
                sh_client.batch_enable_standards(
                    StandardsSubscriptionRequests=[{"StandardsArn": pci_standard_arn}]
                )
                logger.info(
                    f"Enabled PCI DSS Security Standard "
                    f"in Account {account} in {region}"
                )
            except Exception as error:
                logger.info(
                    f"Failed to enable PCI DSS Security Standard "
                    f"Security Standard in Account {account} in "
                    f"{region} - {error}"
                )
    # Disable PCI Standard
    else:
        if not pci_standard_enabled:
            logger.info(
                f"PCI DSS Security Standard is already "
                f"disabled in Account {account} in {region}"
            )
        else:
            try:
                sh_client.batch_disable_standards(
                    StandardsSubscriptionArns=[pci_subscription_arn]
                )
                logger.info(
                    f"Disabled PCI DSS Security Standard "
                    f"in Account {account} in {region}"
                )
            except Exception as error:
                logger.info(
                    f"Failed to disable PCI DSS Security Standard "
                    f"Security Standard in Account {account} in "
                    f"{region} - {error}"
                )


def disable_mgmt(mgmt_session, role, securityhub_regions):
    """
    Disable SecurityHub in the Management Account
    :param mgmt_session: Management account session
    :param role: Role to assume
    :param securityhub_regions: regions to enable
    :return: None
    """

    for region in securityhub_regions:
        sh_mgmt_client = mgmt_session.client("securityhub", region_name=region)
        mgmt_members = get_mgmt_members(mgmt_session, region)
        member_accounts = []

        for member in mgmt_members:
            member_accounts.append(member)

        if member_accounts:
            sh_mgmt_client.disassociate_members(AccountIds=member_accounts)
            logger.info(
                f"Disassociated Member Accounts {member_accounts} "
                f"from the Management Account in {region}"
            )
            sh_mgmt_client.delete_members(AccountIds=member_accounts)
            logger.info(
                f"Deleted Member Accounts {member_accounts} "
                f"from the Management Account in {region}"
            )
            for member in mgmt_members:
                member_session = assume_role(member, role)
                member_client = member_session.client("securityhub", region_name=region)
                member_client.disable_security_hub()
                logger.info(
                    f"Disabled SecurityHub in member Account {member} " f"in {region}"
                )
        try:
            sh_mgmt_client.disable_security_hub()
            logger.info(f"Disabled SecurityHub in Management Account in {region}")
        except ClientError:
            logger.info(
                f"SecurityHub already Disable in Management Account " f"in {region}"
            )
    return


def enable_mgmt(mgmt_session, securityhub_regions, partition):
    """
    Enable Security Hub in the Management Account
    :param mgmt_session: Management Account Session
    :param securityhub_regions: regions to enable
    :param partition: AWS partition
    :return: None
    """

    for region in securityhub_regions:
        sh_mgmt_client = mgmt_session.client("securityhub", region_name=region)
        # Ensure SecurityHub is Enabled in the Management Account
        try:
            sh_mgmt_client.get_findings()
        except ClientError as ce:
            logger.info(
                f"SecurityHub not currently Enabled on Management Account "
                f"{MGMT_ACCOUNT_ID} in {region}. Enabling it."
            )
            try:
                sh_mgmt_client.enable_security_hub(EnableDefaultStandards=False)
            except Exception as exc:
                logger.info(
                    f"Unable to Enable Security Hub on Management Account "
                    f"{MGMT_ACCOUNT_ID} in {region}. Error: {exc}"
                )
                continue
        else:
            logger.info(
                f"SecurityHub already Enabled in Management Account "
                f"{MGMT_ACCOUNT_ID} in {region}"
            )
        try:
            # Enable Action Target
            sh_mgmt_client.create_action_target(
                Name="CWExportS3", Description="CWExportS3", Id="CWExportS3"
            )
        except ClientError:
            logger.info(f"SecurityHub Action Target Already Present")

        process_security_standards(sh_mgmt_client, partition, region, MGMT_ACCOUNT_ID)
        process_integrations(sh_mgmt_client, partition, region, MGMT_ACCOUNT_ID)
    return


def processing_accounts(mgmt_session, aws_account_dict, securityhub_regions, partition, action):
    """
    Process all accounts provided
    :param mgmt_session: Management account session
    :param aws_account_dict: Account dictionary
    :param securityhub_regions: Regions to enable
    :param partition: AWS partition
    :param action: CloudFormation event action
    :return: None
    """
    # Processing Accounts
    logger.info(f"Processing: {json.dumps(aws_account_dict)}")

    for account in aws_account_dict.keys():
        email_address = aws_account_dict[account]
        if account == MGMT_ACCOUNT_ID:
            logger.info(f"Account {account} cannot become a member of itself")
            continue
        logger.debug(
            f"Working on SecurityHub on Account {account} in \
                     regions %{securityhub_regions}"
        )
        failed_invitations = []
        member_session = assume_role(account, ASSUME_ROLE_NAME)
        # Process Regions
        for aws_region in securityhub_regions:
            sh_member_client = member_session.client(
                "securityhub", region_name=aws_region
            )
            sh_mgmt_client = mgmt_session.client("securityhub", region_name=aws_region)
            mgmt_members = get_mgmt_members(mgmt_session, aws_region)
            logger.info(f"Beginning {aws_region} in Account {account}")

            if account in mgmt_members:
                if mgmt_members[account] == "Associated":
                    logger.info(
                        f"Account {account} is already associated "
                        f"with Management Account {MGMT_ACCOUNT_ID} in "
                        f"{aws_region}"
                    )
                    if action == "Delete":
                        try:
                            sh_mgmt_client.disassociate_members(AccountIds=[account])
                        except ClientError:
                            continue
                        try:
                            sh_mgmt_client.delete_members(AccountIds=[account])
                        except ClientError:
                            continue
                else:
                    logger.warning(
                        f"Account {account} exists, but not "
                        f"associated to Management Account "
                        f"{MGMT_ACCOUNT_ID} in {aws_region}"
                    )
                    logger.info(
                        f"Disassociating Account {account} from "
                        f"Management Account {MGMT_ACCOUNT_ID} in "
                        f"{aws_region}"
                    )
                    try:
                        sh_mgmt_client.disassociate_members(AccountIds=[account])
                    except ClientError:
                        continue
                    try:
                        sh_mgmt_client.delete_members(AccountIds=[account])
                    except ClientError:
                        continue
            try:
                sh_member_client.get_findings()
            except Exception as exc:
                logger.debug(str(exc))
                logger.info(
                    f"SecurityHub not currently Enabled on Account "
                    f"{account} in {aws_region}"
                )
                if action != "Delete":
                    logger.info(
                        f"Enabled SecurityHub on Account {account} " f"in {aws_region}"
                    )
                    try:
                        sh_member_client.enable_security_hub(EnableDefaultStandards=False)
                    except ClientError:
                        logger.info(f"Unable to Enable Security Hub in {account} and {aws_region}")
                        continue
            else:
                # Security Hub is already enabled
                if action != "Delete":
                    logger.info(
                        f"SecurityHub already Enabled in Account "
                        f"{account} in {aws_region}"
                    )
                else:
                    logger.info(
                        f"Disabled SecurityHub in Account " f"{account} in {aws_region}"
                    )
                    try:
                        sh_member_client.disable_security_hub()
                    except ClientError:
                        continue
            if action != "Delete":
                process_security_standards(sh_member_client, partition, aws_region, account)
                process_integrations(sh_member_client, partition, aws_region, account)
                logger.info(
                    f"Creating member for Account {account} and "
                    f"Email, {email_address} in {aws_region}"
                )
                member_response = sh_mgmt_client.create_members(
                    AccountDetails=[{"AccountId": account, "Email": email_address}]
                )
                if len(member_response["UnprocessedAccounts"]) > 0:
                    logger.warning(
                        f"Could not create member Account " f"{account} in {aws_region}"
                    )
                    failed_invitations.append(
                        {"AccountId": account, "Region": aws_region}
                    )
                    continue
                logger.info(f"Inviting Account {account} in {aws_region}")
                sh_mgmt_client.invite_members(AccountIds=[account])
            # go through each invitation (hopefully only 1)
            # and pull the one matching the Security Management Account ID
            try:
                paginator = sh_member_client.get_paginator("list_invitations")
                invitation_iterator = paginator.paginate()
                for invitation in invitation_iterator:
                    mgmt_invitation = next(
                        item
                        for item in invitation["Invitations"]
                        if item["AccountId"] == MGMT_ACCOUNT_ID
                    )
                logger.info(
                    f"Accepting invitation on Account {account} "
                    f"from Management Account {MGMT_ACCOUNT_ID} in "
                    f"{aws_region}"
                )
                sh_member_client.accept_invitation(
                    MasterId=MGMT_ACCOUNT_ID,
                    InvitationId=mgmt_invitation["InvitationId"],
                )
            except Exception as exc:
                logger.warning(
                    f"Account {account} could not accept "
                    f"invitation from Management Account "
                    f"{MGMT_ACCOUNT_ID} in {aws_region}"
                )
                logger.warning(f"{exc}")

        if len(failed_invitations) > 0:
            failed_accounts = json.dumps(
                failed_invitations, sort_keys=True, default=str
            )
            logger.warning(
                f"Error Processing the following Accounts: {failed_accounts}"
            )


def enabling_securityhub_all_regions(
        mgmt_session, securityhub_regions, partition, action, event
):
    """
    Enable SecurityHub in all regions
    :param mgmt_session: Management account session
    :param securityhub_regions:
    :param partition: AWS Partition
    :param action: CloudFormation event action
    :param event: event containing records to process
    :return: None
    """
    logger.info(f"Enabling SecurityHub in Regions: {securityhub_regions}")
    aws_account_dict = dict()
    # Checks if Function was called by SNS
    if "Records" in event:
        message = event["Records"][0]["Sns"]["Message"]
        json_message = json.loads(message)
        logger.info(f"SNS message: {json.dumps(json_message, default=str)}")
        account_id = json_message["AccountId"]
        email = json_message["Email"]
        aws_account_dict.update({account_id: email})
        action = json_message["Action"]
        # Ensure the Security Hub Management is still enabled
        enable_mgmt(mgmt_session, securityhub_regions, partition)
        processing_accounts(
            mgmt_session, aws_account_dict, securityhub_regions, partition, action
        )
    else:
        # Publish SNS messages for each Organization Account
        aws_account_dict = get_all_organization_accounts()
        sns_client = SESSION.client("sns", region_name=AWS_REGION)
        for account_id, email in aws_account_dict.items():
            sns_message = {"AccountId": account_id, "Email": email, "Action": action}
            logger.info(f"Publishing to configure Account {account_id}")
            sns_client.publish(TopicArn=SNS_TOPIC_ARN, Message=json.dumps(sns_message))


def disable_sh_all_accounts():
    """
    Disable Security Hub in all accounts
    :return:
    """
    try:
        aws_account_dict = get_all_organization_accounts()
        regions = get_validated_securityhub_regions("", False)
    except Exception as error:
        logger.info(f"{error}")

    for account_id, email in aws_account_dict.items():
        try:
            member_session = assume_role(account_id, ASSUME_ROLE_NAME)
        except Exception as error:
            logger.info(f"{account_id} {region} - {error}")

        for region in regions:
            try:
                member_client = member_session.client("securityhub", region_name=region)
                member_client.disassociate_from_master_account()
                member_client.disable_security_hub()
                logger.info(
                    f"Disabled SecurityHub in member Account {account_id} " f"in {region}"
                )
            except Exception as error:
                logger.info(f"{account_id} {region} - {error}")


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: None
    """
    logger.info(event)
    partition = context.invoked_function_arn.split(":")[1]

    response_data = {}
    try:
        mgmt_session = assume_role(MGMT_ACCOUNT_ID, ASSUME_ROLE_NAME)
        if mgmt_session is None:
            raise NameError("STS Assume Role Failed")
        # Regions to Deploy
        securityhub_regions = get_validated_securityhub_regions(USER_REGIONS, CONTROL_TOWER_REGIONS_ONLY)

        # Check for Custom Resource Call
        if "RequestType" in event and (
                event["RequestType"] == "Delete"
                or event["RequestType"] == "Create"
                or event["RequestType"] == "Update"
        ):
            action = event["RequestType"]
            if action == "Create":
                enable_mgmt(mgmt_session, securityhub_regions, partition)
            if action == "Delete":
                disable_mgmt(mgmt_session, ASSUME_ROLE_NAME, securityhub_regions)
                if DISABLE_ALL_ACCOUNTS:
                    disable_sh_all_accounts()
            logger.info(f"Sending Custom Resource Response")
            send_response(event, context, "SUCCESS", response_data)
        else:
            action = "Create"
            enabling_securityhub_all_regions(mgmt_session, securityhub_regions, partition, action, event)
    except NameError:
        logger.error("STS Assume Failed")

        if "RequestType" in event:
            send_response(event, context, "SUCCESS", response_data)

    except Exception as exc:
        logger.error(exc)
        if "RequestType" in event:
            send_response(event, context, "FAILED", response_data)

