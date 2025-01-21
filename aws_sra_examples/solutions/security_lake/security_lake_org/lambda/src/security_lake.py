"""This script performs operations to enable, configure, and disable security lake.

Version: 1.0
'security_lake_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep
from typing import TYPE_CHECKING, List, Literal, Sequence, Union

import boto3
import common
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_glue import GlueClient
    from mypy_boto3_lakeformation import LakeFormationClient
    from mypy_boto3_lakeformation.type_defs import ResourceTypeDef
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ram import RAMClient
    from mypy_boto3_ram.type_defs import ResourceShareInvitationTypeDef
    from mypy_boto3_securitylake import SecurityLakeClient
    from mypy_boto3_securitylake.literals import AwsLogSourceNameType
    from mypy_boto3_securitylake.paginator import ListLogSourcesPaginator
    from mypy_boto3_securitylake.type_defs import (
        AwsLogSourceConfigurationTypeDef,
        AwsLogSourceResourceTypeDef,
        CreateDataLakeResponseTypeDef,
        CreateSubscriberResponseTypeDef,
        DataLakeAutoEnableNewAccountConfigurationTypeDef,
        ListDataLakesResponseTypeDef,
        LogSourceResourceTypeDef,
    )

LOGGER = logging.getLogger("sra")
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
UNEXPECTED = "Unexpected!"
EMPTY_STRING = ""
SECURITY_LAKE_THROTTLE_PERIOD = 0.2
ENABLE_RETRY_ATTEMPTS = 10
ENABLE_RETRY_SLEEP_INTERVAL = 10
MAX_RETRY = 5
SLEEP_SECONDS = 10
KEY = "sra-solution"
VALUE = "sra-security-lake"

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def check_organization_admin_enabled(delegated_admin_account_id: str, service_principal: str) -> bool:
    """Check if the delegated administrator account for the provided service principal exists.

    Args:
        delegated_admin_account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal

    Raises:
        ValueError: If the delegated administrator other than Log Archive account already exists

    Returns:
        bool: True if the delegated administrator account exists, False otherwise
    """
    LOGGER.info(f"Checking if delegated administrator registered for '{service_principal}' service principal.")
    try:
        delegated_admins = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)
        api_call_details = {"API_Call": "organizations:ListDelegatedAdministrators", "API_Response": delegated_admins}
        LOGGER.info(api_call_details)
        if not delegated_admins["DelegatedAdministrators"]:  # noqa R505
            LOGGER.info(f"Delegated administrator not registered for '{service_principal}'")
            return False
        elif delegated_admins["DelegatedAdministrators"][0]["Id"] == delegated_admin_account_id:
            LOGGER.info(f"Log Archive account ({delegated_admin_account_id}) already registered as delegated administrator for '{service_principal}'")
            return True
        else:
            registered_admin = delegated_admins["DelegatedAdministrators"][0]["Id"]
            LOGGER.info(f"Account {registered_admin} already registered as delegated administrator")
            LOGGER.info("Important: removing the delegated Security Lake admin deletes your data lake and disables it for the accounts in your org")
            raise ValueError(f"Deregister account {registered_admin} to delegate administration to Log Archive account")
    except ClientError as e:
        LOGGER.error(f"Delegated administrator check error occurred: {e}")
        return False


def register_delegated_admin(admin_account_id: str, region: str, service_principal: str) -> None:
    """Set the delegated admin account for the given region.

    Args:
        admin_account_id: Admin account ID
        region: AWS Region
        service_principal: AWS Service Principal
    """
    sl_client: SecurityLakeClient = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region, config=BOTO3_CONFIG)  # type: ignore
    if not check_organization_admin_enabled(admin_account_id, service_principal):
        LOGGER.info(f"Registering delegated administrator ({admin_account_id})...")
        sl_client.register_data_lake_delegated_administrator(accountId=admin_account_id)
        LOGGER.info(f"Account {admin_account_id} registered as delegated administrator for '{service_principal}'")


def check_data_lake_exists(sl_client: SecurityLakeClient, region: str, max_retries: int = MAX_RETRY, initial_delay: int = 1) -> bool:
    """Check if Security Lake enabled for the given region.

    Args:
        sl_client: SecurityLakeClient
        region: AWS region
        max_retries: maximum number of retries
        initial_delay: initial delay in seconds

    Raises:
        ValueError: If the maximum number of retries is reached or if the Security Lake creation failed

    Returns:
        bool: True if Security Lake enabled, False otherwise
    """
    status: bool = False
    retry_count: int = 0
    delay: float = initial_delay
    max_delay: int = 30
    while not status:
        try:
            response: ListDataLakesResponseTypeDef = sl_client.list_data_lakes(regions=[region])
            if not response["dataLakes"]:
                break

            elif response["dataLakes"][0]["createStatus"] == "INITIALIZED":
                if retry_count < max_retries:
                    delay = min(delay * (2**retry_count), max_delay)
                    LOGGER.info(f"Security Lake create status ({region}): 'INITIALIZED'. Retrying ({retry_count + 1}/{max_retries}) in {delay}...")
                    sleep(delay)
                    retry_count += 1
            elif response["dataLakes"][0]["createStatus"] == "COMPLETED":
                status = True
                break
            elif response["dataLakes"][0]["createStatus"] == "FAILED":
                raise ValueError("Security Lake creation failed")
        except ClientError as e:
            LOGGER.error(f"Error calling 'securitylake:ListDataLakes' ({region}): {e}...")
            raise

    if not status:
        LOGGER.info(f"Security Lake is not enabled ({region})")
    return status


def check_data_lake_create_status(sl_client: SecurityLakeClient, regions: list, retries: int = 0) -> bool:
    """Check Security Lake creation status for given regions.

    Args:
        sl_client: boto3 client
        regions: list of AWS regions
        retries: Number of retries. Defaults to 0.

    Raises:
        ValueError: If the maximum number of retries is reached

    Returns:
        bool: True if creation completed, False otherwise
    """
    all_completed: bool = False
    max_retries: int = 20
    regions_status_list: list = []
    while retries < max_retries:
        response: ListDataLakesResponseTypeDef = sl_client.list_data_lakes(regions=regions)
        for data_lake in response["dataLakes"]:
            create_status = data_lake["createStatus"]
            regions_status_list.append(create_status)
        if set(regions_status_list) == {"COMPLETED"}:
            all_completed = True
            break
        if "INITIALIZED" in regions_status_list:
            LOGGER.info(f"Security Lake creation status: 'INITIALIZED'. Retrying ({retries+1}/{max_retries}) in 5 seconds...")
            sleep(5)
            retries += 1
            status = check_data_lake_create_status(sl_client, regions, retries)
            if status:
                all_completed = True
                break
        if "FAILED" in regions_status_list:
            raise ValueError("Security Lake creation failed")

        if retries >= max_retries:
            raise ValueError("Security Lake status not 'COMPLETED'")

    return all_completed


def create_security_lake(sl_client: SecurityLakeClient, sl_configurations: list, role_arn: str) -> None:
    """Create Security Lake for the given region(s).

    Args:
        sl_client: boto3 client
        sl_configurations: Security Lake configurations
        role_arn: role arn

    Raises:
        ValueError: Error creating Security Lake
    """
    base_delay = 10
    max_delay = 20
    data_lake_created = False

    for attempt in range(MAX_RETRY):
        try:
            security_lake_response: CreateDataLakeResponseTypeDef = sl_client.create_data_lake(
                configurations=sl_configurations,
                metaStoreManagerRoleArn=role_arn,
                tags=[
                    {"key": KEY, "value": VALUE},
                ],
            )
            api_call_details = {"API_Call": "securitylake:CreateDataLake", "API_Response": security_lake_response}
            LOGGER.info(api_call_details)
            sleep(20)
            data_lake_created = True
            break

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ["BadRequestException", "ConflictException"]:
                error_message = str(e)
                if "The CreateDataLake operation can't be used to update the settings for an existing data lake" in error_message:
                    raise ValueError("Security lake already exists.") from None
                else:
                    delay = min(base_delay * (1.0**attempt), max_delay)
                    LOGGER.info(f"'{error_code}' occurred: {e}. Retrying ({attempt + 1}/{MAX_RETRY}) in {delay} seconds...")
                    sleep(delay)
            else:
                LOGGER.error(f"Error calling CreateDataLake: {e}")
                raise
        attempt += 1
        if attempt >= MAX_RETRY:
            LOGGER.error("Error calling CreateDataLake")
            break
    if not data_lake_created:
        raise ValueError("Error creating security lake")


def encrypt_sqs_queues(configuration_role_name: str, account: str, region: str, key_id: str) -> None:
    """Encrypt Security Lake SQS queues with KMS key.

    Args:
        configuration_role_name: configuration role name
        account: AWS Account id
        region: AWS region
        key_id: KMS key id
    """
    sqs_queues = [
        f"https://sqs.{region}.amazonaws.com/{account}/AmazonSecurityLakeManager-{region}-Dlq",
        f"https://sqs.{region}.amazonaws.com/{account}/AmazonSecurityLakeManager-{region}-Queue",
    ]
    session = common.assume_role(configuration_role_name, "sra-configure-security-lake", account)
    sqs_client = session.client("sqs", region)
    for queue_url in sqs_queues:
        try:
            response = sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes={"KmsMasterKeyId": key_id})
            api_call_details = {"API_Call": "sqs:SetQueueAttributes", "API_Response": response}
            LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error(e)


class CheckLogSourceResult:
    """Log source check result."""

    def __init__(self, source_exists: bool, accounts_to_enable: list, accounts_to_disable: list, regions_to_enable: list):
        """Set result attributes.

        Args:
            source_exists: source exists
            accounts_to_enable: accounts to enable
            accounts_to_disable: accounts to disable
            regions_to_enable: regions to enable
        """
        self.source_exists = source_exists
        self.accounts_to_enable = accounts_to_enable
        self.accounts_to_disable = accounts_to_disable
        self.regions_to_enable = regions_to_enable


def check_log_source_enabled(
    sl_client: SecurityLakeClient,
    requested_accounts: list,
    org_accounts: list,
    requested_regions: list,
    log_source_name: AwsLogSourceNameType,
    log_source_version: str,
) -> CheckLogSourceResult:
    """Check if AWS log and event source enabled.

    Args:
        sl_client: SecurityLakeClient
        requested_accounts: requested accounts
        org_accounts: organization accounts
        requested_regions: requested regions
        log_source_name: log source name
        log_source_version: log source version

    Returns:
        CheckLogSourceResult
    """
    accounts_to_enable: list = []
    accounts_to_disable_log_source: list = []
    regions_with_source_enabled: list = []
    list_log_sources_paginator: ListLogSourcesPaginator = sl_client.get_paginator("list_log_sources")
    for page in list_log_sources_paginator.paginate(
        accounts=org_accounts,
        regions=requested_regions,
        sources=[{"awsLogSource": {"sourceName": log_source_name, "sourceVersion": log_source_version}}],
    ):
        if not page["sources"]:  # noqa R505
            return CheckLogSourceResult(False, requested_accounts, accounts_to_disable_log_source, requested_regions)
        else:
            enabled_accounts = {s["account"] for s in page["sources"] if s["account"] in org_accounts}
            regions_with_source_enabled = list({s["region"] for s in page["sources"]})
            accounts_to_enable = [account for account in requested_accounts if account not in enabled_accounts]
            accounts_to_disable_log_source = [account for account in enabled_accounts if account not in requested_accounts]
            regions_to_enable = [region for region in requested_regions if region not in regions_with_source_enabled]

            if accounts_to_enable:
                LOGGER.info(f"AWS log and event source {log_source_name} will be enabled in {', '.join(accounts_to_enable)} account(s)")
            if accounts_to_disable_log_source:
                LOGGER.info(f"AWS log and event source {log_source_name} will be deleted in {', '.join(accounts_to_disable_log_source)} account(s)")
            if regions_to_enable:
                LOGGER.info(f"AWS log and event source {log_source_name} will be enabled in {', '.join(regions_to_enable)} region(s)")

    return CheckLogSourceResult(True, accounts_to_enable, accounts_to_disable_log_source, regions_to_enable)


def add_aws_log_source(sl_client: SecurityLakeClient, aws_log_sources: list) -> None:
    """Create AWS log and event sources.

    Args:
        sl_client: boto3 client
        aws_log_sources: list of AWS log and event sources

    Raises:
        ClientError: Error calling CreateAwsLogSource
        ValueError: Error creating log and event source
    """
    create_log_source_retries = 10
    base_delay = 1
    max_delay = 30
    log_source_created = False
    for attempt in range(create_log_source_retries):
        try:
            LOGGER.info("Configuring requested AWS log and events sources")
            sl_client.create_aws_log_source(sources=aws_log_sources)
            log_source_created = True
            LOGGER.info("Enabled requested AWS log and event sources")
            break
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ConflictException":
                delay = min(base_delay * (2**attempt), max_delay)
                LOGGER.info(f"'ConflictException' occurred {e}. Retrying ({attempt + 1}/{create_log_source_retries}) in {delay} seconds...")
                sleep(delay)
            else:
                LOGGER.error(f"Error calling CreateAwsLogSource: {e}.")
                raise
        attempt += 1
        if log_source_created or attempt >= create_log_source_retries:
            break

    if not log_source_created:
        raise ValueError("Failed to create log events sources")


def update_aws_log_source(
    sl_client: SecurityLakeClient,
    requested_regions: list,
    source: AwsLogSourceNameType,
    requested_accounts: list,
    org_accounts: list,
    source_version: str,
) -> None:
    """Create AWS log and event sources.

    Args:
        sl_client: boto3 client
        requested_regions: list of AWS regions
        source: AWS log and event source name
        requested_accounts: list of AWS accounts
        org_accounts: list of all AWS accounts in organization
        source_version: log source version
    """
    result = check_log_source_enabled(sl_client, requested_accounts, org_accounts, requested_regions, source, source_version)
    accounts = list(result.accounts_to_enable)
    accounts_to_delete = list(result.accounts_to_disable)
    regions_to_enable = list(result.regions_to_enable)

    configurations: AwsLogSourceConfigurationTypeDef = {
        "accounts": requested_accounts,
        "regions": requested_regions,
        "sourceName": source,
        "sourceVersion": source_version,
    }
    if result.source_exists and accounts:
        configurations.update({"accounts": accounts})

    if result.source_exists and not accounts and not regions_to_enable:
        LOGGER.info("Log and event source already configured. No changes to apply")

    else:
        add_aws_log_source(sl_client, [configurations])

    if accounts_to_delete:
        delete_aws_log_source(sl_client, requested_regions, source, accounts_to_delete, source_version)


def get_org_configuration(sl_client: SecurityLakeClient) -> tuple:
    """Get Security Lake organization configuration.

    Args:
        sl_client: boto3 client

    Raises:
        ClientError: If there is an issue interacting with the AWS API

    Returns:
        tuple: (bool, dict)
    """
    try:
        org_configurations = sl_client.get_data_lake_organization_configuration()
        if org_configurations["autoEnableNewAccount"]:  # noqa R505
            return True, org_configurations["autoEnableNewAccount"]
        else:
            return False, org_configurations
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            return False, "ResourceNotFoundException"
        else:
            LOGGER.error(f"Error calling GetDataLakeConfiguration: {e}.")
            raise


def create_organization_configuration(sl_client: SecurityLakeClient, regions: list, org_sources: list, source_version: str, retry: int = 0) -> None:
    """Create Security Lake organization configuration.

    Args:
        sl_client: boto3 client
        regions: list of AWS regions
        org_sources: list of AWS log and event sources
        source_version: version of log source
        retry: retry counter. Defaults to 0
    """
    sources: List[AwsLogSourceResourceTypeDef] = [{"sourceName": source, "sourceVersion": source_version} for source in org_sources]
    auto_enable_config: List[DataLakeAutoEnableNewAccountConfigurationTypeDef] = []
    for region in regions:
        region_config: DataLakeAutoEnableNewAccountConfigurationTypeDef = {"region": region, "sources": sources}
        auto_enable_config.append(region_config)
    if retry < MAX_RETRY:
        try:
            sl_client.create_data_lake_organization_configuration(autoEnableNewAccount=auto_enable_config)
        except sl_client.exceptions.ConflictException:
            LOGGER.info("'ConflictException' occurred. Retrying...")
            sleep(SLEEP_SECONDS)
            create_organization_configuration(sl_client, regions, org_sources, source_version, retry + 1)


def set_sources_to_disable(org_configurations: list, region: str) -> list:
    """Update Security Lake.

    Args:
        org_configurations: list of configurations
        region: AWS region

    Returns:
        list: list of sources to disable
    """
    sources_to_disable = []
    for configuration in org_configurations:
        if configuration["region"] == region:
            for source in configuration["sources"]:
                sources_to_disable.append(source)

    return sources_to_disable


def update_organization_configuration(
    sl_client: SecurityLakeClient, regions: list, org_sources: list, source_version: str, existing_org_configuration: list
) -> None:
    """Update Security Lake organization configuration.

    Args:
        sl_client: boto3 client
        regions: list of AWS regions
        org_sources: list of AWS log and event sources
        source_version: version of log source
        existing_org_configuration: list of existing configurations
    """
    delete_organization_configuration(sl_client, existing_org_configuration)
    sources: List[AwsLogSourceResourceTypeDef] = [{"sourceName": source, "sourceVersion": source_version} for source in org_sources]
    auto_enable_config: List[DataLakeAutoEnableNewAccountConfigurationTypeDef] = []
    for region in regions:
        region_config: DataLakeAutoEnableNewAccountConfigurationTypeDef = {"region": region, "sources": sources}
        auto_enable_config.append(region_config)
    response = sl_client.create_data_lake_organization_configuration(autoEnableNewAccount=auto_enable_config)
    api_call_details = {"API_Call": "securitylake:CreateDataLakeOrganizationConfiguration", "API_Response": response}
    LOGGER.info(api_call_details)


def delete_organization_configuration(sl_client: SecurityLakeClient, existing_org_configuration: list) -> None:
    """Delete Security Lake organization configuration.

    Args:
        sl_client: boto3 client
        existing_org_configuration: list of existing configurations
    """
    sources_to_disable = existing_org_configuration
    if sources_to_disable:
        delete_response = sl_client.delete_data_lake_organization_configuration(autoEnableNewAccount=existing_org_configuration)
        api_call_details = {"API_Call": "securitylake:DeleteDataLakeOrganizationConfiguration", "API_Response": delete_response}
        LOGGER.info(api_call_details)


def check_subscriber_exists(sl_client: SecurityLakeClient, subscriber_name: str, next_token: str = EMPTY_STRING) -> tuple:  # noqa: CFQ004
    """List Security Lake subscribers.

    Args:
        sl_client: boto3 client
        subscriber_name: subscriber name
        next_token: next token. Defaults to EMPTY_STRING.

    Raises:
        ClientError: If there is an issue listing subscribers

    Returns:
        tuple: (bool, str, str)
    """
    subscriber_exists = False
    subscriber_id = ""
    external_id = ""
    try:
        if next_token != EMPTY_STRING:
            response = sl_client.list_subscribers(maxResults=10, nextToken=next_token)
        else:
            response = sl_client.list_subscribers(maxResults=10)
        if response["subscribers"]:  # noqa R505
            subscriber = next((subscriber for subscriber in response["subscribers"] if subscriber_name == subscriber["subscriberName"]), None)
            if subscriber:
                subscriber_id = subscriber["subscriberId"]
                external_id = subscriber["subscriberIdentity"]["externalId"]
                subscriber_exists = True
                return subscriber_exists, subscriber_id, external_id

            if "nextToken" in response:
                subscriber_exists, subscriber_id, external_id = check_subscriber_exists(sl_client, subscriber_name, response["nextToken"])
            return subscriber_exists, subscriber_id, external_id
        else:
            return subscriber_exists, subscriber_id, external_id

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":  # noqa: R505
            LOGGER.info(f"Error calling ListSubscribers: {e}. Skipping...")
            return subscriber_exists, subscriber_id, external_id
        else:
            LOGGER.error(f"Error calling ListSubscribers: {e}.")
            raise


def get_subscriber_resourceshare_arn(sl_client: SecurityLakeClient, subscriber_name: str, next_token: str = EMPTY_STRING) -> tuple:  # noqa S107
    """List Security Lake subscribers.

    Args:
        sl_client: boto3 client
        subscriber_name: subscriber name
        next_token: next token. Defaults to EMPTY_STRING.

    Returns:
        tuple: (bool, str, str)
    """
    resource_share_arn = ""
    subscriber_exists = False
    if next_token != EMPTY_STRING:
        response = sl_client.list_subscribers(maxResults=10, nextToken=next_token)
    else:
        response = sl_client.list_subscribers(maxResults=10)
    if response["subscribers"]:  # noqa R505
        for subscriber in response["subscribers"]:
            if subscriber_name == subscriber["subscriberName"]:
                resource_share_arn = subscriber.get("resourceShareArn", "")
                subscriber_exists = True
                return subscriber_exists, resource_share_arn
        if "nextToken" in response:
            subscriber_exists, resource_share_arn = get_subscriber_resourceshare_arn(sl_client, subscriber_name, response["nextToken"])
        return subscriber_exists, resource_share_arn
    else:
        return subscriber_exists, resource_share_arn


def create_subscribers(
    sl_client: SecurityLakeClient,
    data_access: Literal["LAKEFORMATION", "S3"],
    source_types: list,
    external_id: str,
    principal: str,
    subscriber_name: str,
    source_version: str,
) -> tuple:
    """Create Security Lake subscriber.

    Args:
        sl_client: boto3 client
        data_access: data access type
        source_types: list of source types
        external_id: external id
        principal: AWS account id
        subscriber_name: subscriber name
        source_version: source version

    Returns:
        tuple: subscriber id, resource share ARN
    """
    subscriber_sources: Sequence[LogSourceResourceTypeDef] = [
        {"awsLogSource": {"sourceName": source, "sourceVersion": source_version}} for source in source_types
    ]
    resource_share_arn = ""
    subscriber_id = ""
    base_delay = 1
    max_delay = 10
    done = False
    for attempt in range(ENABLE_RETRY_ATTEMPTS):
        try:
            response: CreateSubscriberResponseTypeDef = sl_client.create_subscriber(
                accessTypes=[data_access],
                sources=subscriber_sources,
                subscriberIdentity={"externalId": external_id, "principal": principal},
                subscriberName=subscriber_name,
                tags=[
                    {"key": KEY, "value": VALUE},
                ],
            )
            api_call_details = {"API_Call": "securitylake:CreateSubscriber", "API_Response": response}
            LOGGER.info(api_call_details)
            subscriber_id = response["subscriber"]["subscriberId"]
            if data_access == "LAKEFORMATION":  # noqa R505
                resource_share_arn = response["subscriber"]["resourceShareArn"]
                done = True
                return subscriber_id, resource_share_arn
            else:
                return subscriber_id, "s3_data_access"
        except sl_client.exceptions.BadRequestException as e:
            delay = min(base_delay * (2**attempt), max_delay)
            LOGGER.info(f"'Error occurred calling CreateSubscriber: {e}. Retrying ({attempt + 1}/{ENABLE_RETRY_ATTEMPTS}) in {delay}")
            sleep(delay)

        attempt += 1
        if done or attempt >= ENABLE_RETRY_ATTEMPTS:
            break

    return subscriber_id, resource_share_arn


def update_subscriber(
    sl_client: SecurityLakeClient, subscriber_id: str, source_types: list, external_id: str, principal: str, subscriber_name: str, source_version: str
) -> str:
    """Update Security Lake subscriber.

    Args:
        sl_client: boto3 client
        subscriber_id: subscriber id
        source_types: list of source types
        external_id: external id
        principal: AWS account id
        subscriber_name: subscriber name
        source_version: source version

    Returns:
        str: Resource share ARN

    Raises:
        ValueError: if subscriber not created
    """
    subscriber_sources: Sequence[LogSourceResourceTypeDef] = [
        {"awsLogSource": {"sourceName": source, "sourceVersion": source_version}} for source in source_types
    ]
    base_delay = 1
    max_delay = 3
    done = False
    for attempt in range(ENABLE_RETRY_ATTEMPTS):
        try:
            response = sl_client.update_subscriber(
                sources=subscriber_sources,
                subscriberId=subscriber_id,
                subscriberIdentity={"externalId": external_id, "principal": principal},
                subscriberName=subscriber_name,
            )
            api_call_details = {"API_Call": "securitylake:UpdateSubscriber", "API_Response": response}
            LOGGER.info(api_call_details)
            LOGGER.info(f"Subscriber '{subscriber_name}' updated")
            if response["subscriber"]["accessTypes"] == ["LAKEFORMATION"]:
                resource_share_arn = response["subscriber"]["resourceShareArn"]
                sleep(SLEEP_SECONDS)
                done = True
                return resource_share_arn
            return "s3_data_access"
        except sl_client.exceptions.BadRequestException:
            delay = min(base_delay * (2**attempt), max_delay)
            LOGGER.info(f"'BadRequestException' occurred calling UpdateSubscriber. Retrying ({attempt + 1}/{ENABLE_RETRY_ATTEMPTS}) in {delay}")
            sleep(delay)

        attempt += 1
        if done or attempt >= ENABLE_RETRY_ATTEMPTS:
            break
    if not done:
        raise ValueError("Subscriber not updated")

    return resource_share_arn


def configure_resource_share_in_subscriber_acct(ram_client: RAMClient, resource_share_arn: str) -> None:
    """Accept resource share invitation in subscriber account.

    Args:
        ram_client: boto3 client
        resource_share_arn: resource share arn

    Raises:
        ValueError: If there is an issue interacting with the AWS API
    """
    base_delay = 0.5
    max_delay = 5
    invitation_accepted = False
    for attempt in range(MAX_RETRY):
        paginator = ram_client.get_paginator("get_resource_share_invitations")
        invitation = next(
            (
                inv
                for page in paginator.paginate(PaginationConfig={"PageSize": 20})
                for inv in page["resourceShareInvitations"]
                if resource_share_arn == inv["resourceShareArn"]
            ),
            None,
        )  # noqa: E501, B950

        if invitation:
            if invitation["status"] == "PENDING":
                accept_resource_share_invitation(ram_client, invitation)
                delay = min(base_delay * (2**attempt), max_delay)
                sleep(delay)
            if invitation["status"] == "ACCEPTED":
                invitation_accepted = True
                break
        else:
            if check_shared_resource_exists(ram_client, resource_share_arn):
                invitation_accepted = True
                break
        attempt += 1
        if invitation_accepted or attempt >= MAX_RETRY:
            break
    if not invitation_accepted:
        raise ValueError("Error accepting resource share invitation") from None


def accept_resource_share_invitation(ram_client: RAMClient, invitation: ResourceShareInvitationTypeDef) -> None:
    """Accept the resource share invitation.

    Args:
        ram_client: The AWS RAM client to interact with the service.
        invitation: The invitation to accept.
    """
    ram_client.accept_resource_share_invitation(
        resourceShareInvitationArn=invitation["resourceShareInvitationArn"],
    )
    LOGGER.info(f"Accepted resource share invitation: {invitation['resourceShareInvitationArn']}")


def check_shared_resource_exists(ram_client: RAMClient, resource_share_arn: str) -> bool:
    """Check if a shared resource exists in the organization that has AWS RAM access enabled.

    Args:
        ram_client: The AWS RAM client to interact with the service.
        resource_share_arn: The ARN (Amazon Resource Name) of the shared resource.

    Returns:
        bool: True or False.
    """
    response = ram_client.list_resources(resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[resource_share_arn])
    if response["resources"]:
        return True
    return False


def get_shared_resource_names(ram_client: RAMClient, resource_share_arn: str) -> tuple:
    """Get resource names from resource share arn.

    Args:
        ram_client: boto3 client
        resource_share_arn: resource share arn

    Returns:
        tuple: database name and table names
    """
    db_name = ""
    table_names = []
    retry = 0
    resources_created = False
    LOGGER.info("Getting shared resources")
    while retry < MAX_RETRY:
        response = ram_client.list_resources(resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[resource_share_arn])
        if response["resources"]:
            db_name = next((resource["arn"].split("/")[-1] for resource in response["resources"] if resource["type"] == "glue:Database"), "")
            table_names = [resource["arn"].split("/")[-1] for resource in response["resources"] if resource["type"] == "glue:Table"]
            resources_created = True
            break
        else:
            LOGGER.info(f"No shared resources found. Retrying {retry+1}")
            retry += 1
            sleep(SLEEP_SECONDS)
    if not resources_created:
        LOGGER.error("Max retries reached. Unable to retrieve resource names.")
    return db_name, table_names


def create_db_in_data_catalog(glue_client: GlueClient, subscriber_acct: str, shared_db_name: str, region: str, role_name: str) -> None:
    """Create database in data catalog.

    Args:
        glue_client: boto3 client
        subscriber_acct: Security Lake query access subscriber AWS account id
        shared_db_name: name of shared database
        role_name: subscriber configuration role name
        region: AWS region

    Raises:
        ClientError: If there is an issue interacting with the AWS API
    """
    try:
        response = glue_client.create_database(
            CatalogId=subscriber_acct, DatabaseInput={"Name": shared_db_name + "_subscriber", "CreateTableDefaultPermissions": []}
        )
        api_call_details = {"API_Call": "glue:CreateDatabase", "API_Response": response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AlreadyExistsException":
            LOGGER.info(f"Database '{shared_db_name}_subscriber' already exists")
        else:
            LOGGER.error(f"Error calling CreateDatabase: {e}")
            raise
    subscriber_session = common.assume_role(role_name, "sra-configure-resource-link", subscriber_acct)
    lf_client = subscriber_session.client("lakeformation", region)
    set_lake_formation_permissions(lf_client, subscriber_acct, shared_db_name)


def create_table_in_data_catalog(glue_client: GlueClient, shared_db_name: str, shared_table_names: str, security_lake_acct: str, region: str) -> None:
    """Create table in data catalog.

    Args:
        glue_client: boto3 client
        shared_db_name: name of shared database
        shared_table_names: name of shared tables
        security_lake_acct: Security Lake delegated administrator AWS account id
        region: AWS region

    Raises:
        ValueError: If there is an creating Glue table
    """
    for table in shared_table_names:
        table_name = "rl_" + table
        try:
            response = glue_client.create_table(
                DatabaseName=shared_db_name + "_subscriber",
                TableInput={
                    "Name": table_name,
                    "TargetTable": {"CatalogId": security_lake_acct, "DatabaseName": shared_db_name, "Name": table},
                },
            )
            api_call_details = {"API_Call": "glue:CreateTable", "API_Response": response}
            LOGGER.info(api_call_details)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AlreadyExistsException":
                LOGGER.info(f"Table '{table_name}' already exists in {region} region.")
                continue
            if error_code == "AccessDeniedException":  # noqa R505
                LOGGER.info("'AccessDeniedException' error occurred. Review and update Lake Formation permission(s)")
                LOGGER.info("Skipping...")
                continue
            else:
                raise ValueError(f"Error calling glue:CreateTable {e}") from None


def set_lake_formation_permissions(lf_client: LakeFormationClient, account: str, db_name: str) -> None:
    """Set Lake Formation permissions.

    Args:
        lf_client: boto3 client
        account: AWS account
        db_name: database name

    Raises:
        ClientError: If there is an issue interacting with the AWS API

    """
    LOGGER.info("Setting lakeformation permissions for db")
    try:
        resource: Union[ResourceTypeDef] = {
            "Database": {"CatalogId": account, "Name": db_name + "_subscriber"},
            "Table": {"CatalogId": account, "DatabaseName": db_name + "_subscriber", "Name": "rl_*"},  # type: ignore
        }
        lf_client.grant_permissions(
            CatalogId=account,
            Principal={"DataLakePrincipalIdentifier": f"arn:aws:iam::{account}:role/sra-security-lake-query-subscriber"},
            Resource=resource,
            Permissions=["ALL"],
            PermissionsWithGrantOption=["ALL"],
        )
    except ClientError as e:
        LOGGER.error(f"Error calling GrantPermissions {e}.")
        raise


def delete_subscriber(sl_client: SecurityLakeClient, subscriber_name: str, region: str) -> None:
    """Delete Security Lake subscriber.

    Args:
        sl_client: boto3 client
        subscriber_name: subscriber name
        region: AWS region
    """
    subscriber_exists, subscriber_id, _ = check_subscriber_exists(sl_client, subscriber_name)
    LOGGER.info(f"Subscriber exists: {subscriber_exists}. Subscriber name {subscriber_name} sub id {subscriber_id}")
    if subscriber_exists:

        try:
            response = sl_client.delete_subscriber(subscriberId=subscriber_id)
            api_call_details = {"API_Call": "securitylake:DeleteSubscriber", "API_Response": response}
            LOGGER.info(api_call_details)
        except sl_client.exceptions.ResourceNotFoundException as e:
            LOGGER.info(f"Subscriber not found in {region} region. {e}")
            pass
    else:
        LOGGER.info(f"Subscriber not found in {region} region. Skipping delete subscriber...")


def delete_aws_log_source(sl_client: SecurityLakeClient, regions: list, source: AwsLogSourceNameType, accounts: list, source_version: str) -> None:
    """Delete AWS log and event source.

    Args:
        sl_client: boto3 client
        regions: list of AWS regions
        source: AWS log source name
        accounts: list of AWS accounts
        source_version: AWS log source version

    Raises:
        ClientError: If there is an issue interacting with the AWS API.
    """
    configurations: AwsLogSourceConfigurationTypeDef = {
        "accounts": accounts,
        "regions": regions,
        "sourceName": source,
        "sourceVersion": source_version,
    }
    try:
        sl_client.delete_aws_log_source(sources=[configurations])
        LOGGER.info(f"Deleted AWS log source {source} in {', '.join(accounts)} account(s) {', '.join(regions)} region(s)...")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "UnauthorizedException":
            LOGGER.info("'UnauthorizedException' occurred....")
        else:
            LOGGER.error(f"Error calling DeleteAwsLogSource {e}.")
            raise
