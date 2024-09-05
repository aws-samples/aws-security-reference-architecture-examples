"""This script performs operations to enable, configure, update, and disable Security Lake.

Version: 1.0

'security_lake_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING, Any

import boto3
import common
import security_lake
import sra_ssm_params
from botocore.config import Config
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_securitylake import SecurityLakeClient


LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "INFO")
LOGGER.setLevel(log_level)

ssm = sra_ssm_params.SraSsmParams(LOGGER)
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
UNEXPECTED = "Unexpected!"
SERVICE_NAME = "securitylake.amazonaws.com"
HOME_REGION = ssm.get_home_region()
AUDIT_ACCT_ID = ssm.get_security_acct()
AWS_LOG_SOURCES = ["ROUTE53", "VPC_FLOW", "SH_FINDINGS", "CLOUD_TRAIL_MGMT", "LAMBDA_EXECUTION", "S3_DATA", "EKS_AUDIT", "WAF"]
CLOUDFORMATION_PAGE_SIZE = 20

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    PARTITION: str = MANAGEMENT_ACCOUNT_SESSION.get_partition_for_region(HOME_REGION) # type: ignore
    CFN_CLIENT = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def process_add_event(params: dict, regions: list, accounts: dict) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts

    Returns:
        Status
    """
    LOGGER.info("...process_add_event")

    if params["action"] in ["Add"]:
        enable_and_configure_security_lake(params, regions, accounts)
        for region in regions:
            delegated_admin_session = common.assume_role(
                params["CONFIGURATION_ROLE_NAME"], "sra-process-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
            )
            sl_client = delegated_admin_session.client("securitylake", region)
            if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
                add_audit_acct_data_subscriber(sl_client, params, region)
            if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
                add_audit_acct_query_subscriber(sl_client, params, region)

        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"] and params["CREATE_RESOURCE_LINK"]:
            configure_audit_acct_for_query_access(params, regions)

        LOGGER.info("...ADD_COMPLETE")
        return

    LOGGER.info("...ADD_NO_EVENT")


def process_update_event(params: dict, regions: list, accounts: dict) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts

    Returns:
        Status
    """
    LOGGER.info("...process_update_event")

    if params["action"] in ["Update"]:
        if params["DISABLE_SECURITY_LAKE"]:
            disable_security_lake(params, regions, accounts)
        else:
            update_security_lake(params, regions)
            update_log_sources(params, regions, accounts)
            if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
                update_audit_acct_data_subscriber(params, regions)
            if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
                update_audit_acct_query_subscriber(params, regions)

            LOGGER.info("...UPDATE_COMPLETE")
            return

    LOGGER.info("...UPDATE_NO_EVENT")


def process_delete_event(params: dict, regions: list, accounts: dict) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts

    Returns:
        Status
    """
    LOGGER.info("...process_delete_event")
    if params["action"] in ["Update"]:
        if params["DISABLE_SECURITY_LAKE"]:
            LOGGER.info("...Disable Security Lake")
            disable_security_lake(params, regions, accounts)
        LOGGER.info("...DELETE_COMPLETE")
        return

    LOGGER.info("...DELETE_NO_EVENT")


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({"RequestType": "Update"})
    # excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
    accounts = common.get_active_organization_accounts()
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    process_update_event(params, regions, accounts)


def parameter_pattern_validator(parameter_name: str, parameter_value: str | None, pattern: str, is_optional: bool = False) -> dict:
    """Validate CloudFormation Custom Resource Properties and/or Lambda Function Environment Variables.

    Args:
        parameter_name: CloudFormation custom resource parameter name and/or Lambda function environment variable name
        parameter_value: CloudFormation custom resource parameter value and/or Lambda function environment variable value
        pattern: REGEX pattern to validate against.
        is_optional: Allow empty or missing value when True

    Raises:
        ValueError: Parameter has a value of empty string.
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern

    Returns:
        Validated Parameter
    """
    if parameter_value == "" and not is_optional:
        raise ValueError(f"({parameter_name}) parameter has a value of empty string.")
    elif not parameter_value and not is_optional:
        raise ValueError(f"({parameter_name}) parameter is missing.")
    elif not re.match(pattern, str(parameter_value)):
        raise ValueError(f"({parameter_name}) parameter with value of ({parameter_value})" + f" does not follow the allowed pattern: {pattern}.")
    return {parameter_name: parameter_value}


def get_validated_parameters(event: dict[str, Any]) -> dict:
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params: dict[str, str | bool] = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]
    true_false_pattern = r"^true|false$"
    log_source_pattern = r"(?i)^((ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF),?){0,7}($|ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF){1}$"
    version_pattern = r"^[0-9.]+$"
    source_target_pattern = r"^($|ALL|(\d{12})(,\s*\d{12})*)$"
    name_pattern = r"^[\w+=,.@-]{1,64}$"

    # Required Parameters
    params.update(parameter_pattern_validator("DISABLE_SECURITY_LAKE", os.environ.get("DISABLE_SECURITY_LAKE"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", os.environ.get("MANAGEMENT_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("AWS_PARTITION", os.environ.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$"))
    params.update(parameter_pattern_validator("CONFIGURATION_ROLE_NAME", os.environ.get("CONFIGURATION_ROLE_NAME"), pattern=name_pattern))
    params.update(parameter_pattern_validator("SUBSCRIBER_ROLE_NAME", os.environ.get("SUBSCRIBER_ROLE_NAME"), pattern=name_pattern))
    params.update(parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", os.environ.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern))
    params.update(
        parameter_pattern_validator("SET_AUDIT_ACCT_DATA_SUBSCRIBER", os.environ.get("SET_AUDIT_ACCT_DATA_SUBSCRIBER"), pattern=true_false_pattern)
    )
    params.update(
        parameter_pattern_validator("SET_AUDIT_ACCT_QUERY_SUBSCRIBER", os.environ.get("SET_AUDIT_ACCT_QUERY_SUBSCRIBER"), pattern=true_false_pattern)
    )
    params.update(parameter_pattern_validator("SOURCE_VERSION", os.environ.get("SOURCE_VERSION"), pattern=version_pattern))
    params.update(parameter_pattern_validator("SET_ORG_CONFIGURATION", os.environ.get("SET_ORG_CONFIGURATION"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("META_STORE_MANAGER_ROLE_NAME", os.environ.get("META_STORE_MANAGER_ROLE_NAME"), pattern=name_pattern))
    params.update(parameter_pattern_validator("CREATE_RESOURCE_LINK", os.environ.get("CREATE_RESOURCE_LINK"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("KEY_ALIAS", os.environ.get("KEY_ALIAS"), pattern=r"^[a-zA-Z0-9/_-]+$"))

    # Optional Parameters
    params.update(parameter_pattern_validator("ENABLED_REGIONS", os.environ.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True))
    params.update(
        parameter_pattern_validator("CLOUD_TRAIL_MGMT", os.environ.get("CLOUD_TRAIL_MGMT"), pattern=source_target_pattern, is_optional=True)
    )
    params.update(parameter_pattern_validator("ROUTE53", os.environ.get("ROUTE53"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("VPC_FLOW", os.environ.get("VPC_FLOW"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("SH_FINDINGS", os.environ.get("SH_FINDINGS"), pattern=source_target_pattern, is_optional=True))
    params.update(
        parameter_pattern_validator("LAMBDA_EXECUTION", os.environ.get("LAMBDA_EXECUTION"), pattern=source_target_pattern, is_optional=True)
    )
    params.update(parameter_pattern_validator("S3_DATA", os.environ.get("S3_DATA"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("EKS_AUDIT", os.environ.get("EKS_AUDIT"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("WAF", os.environ.get("WAF"), pattern=source_target_pattern, is_optional=True))
    params.update(
        parameter_pattern_validator(
            "ORG_CONFIGURATION_SOURCES", os.environ.get("ORG_CONFIGURATION_SOURCES"), pattern=log_source_pattern, is_optional=True
        )
    )

    params.update(
        parameter_pattern_validator(
            "AUDIT_ACCT_DATA_SUBSCRIBER", os.environ.get("AUDIT_ACCT_DATA_SUBSCRIBER"), pattern=name_pattern, is_optional=True
        )
    )
    params.update(
        parameter_pattern_validator(
            "DATA_SUBSCRIBER_EXTERNAL_ID", os.environ.get("DATA_SUBSCRIBER_EXTERNAL_ID"), pattern=r"^(?:[a-zA-Z0-9]{0,64})?$", is_optional=True
        )
    )

    params.update(
        parameter_pattern_validator(
            "AUDIT_ACCT_QUERY_SUBSCRIBER", os.environ.get("AUDIT_ACCT_QUERY_SUBSCRIBER"), pattern=name_pattern, is_optional=True
        )
    )
    params.update(
        parameter_pattern_validator(
            "QUERY_SUBSCRIBER_EXTERNAL_ID", os.environ.get("QUERY_SUBSCRIBER_EXTERNAL_ID"), pattern=r"^(?:[a-zA-Z0-9]{0,64})?$", is_optional=True
        )
    )

    #  Convert true/false string parameters to boolean
    params.update({"DISABLE_SECURITY_LAKE": (params["DISABLE_SECURITY_LAKE"] == "true")})
    params.update({"SET_AUDIT_ACCT_DATA_SUBSCRIBER": (params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"] == "true")})
    params.update({"SET_AUDIT_ACCT_QUERY_SUBSCRIBER": (params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"] == "true")})
    params.update({"CONTROL_TOWER_REGIONS_ONLY": (params["CONTROL_TOWER_REGIONS_ONLY"] == "true")})
    params.update({"SET_ORG_CONFIGURATION": (params["SET_ORG_CONFIGURATION"] == "true")})
    params.update({"CREATE_RESOURCE_LINK": (params["CREATE_RESOURCE_LINK"] == "true")})

    return params


def enable_and_configure_security_lake(params: dict, regions: list, accounts: dict) -> None:
    """Enable the security lake service and configure its global settings.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts
    """
    security_lake.register_delegated_admin(params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION, SERVICE_NAME)
    provision_security_lake(params, regions)
    add_log_sources(params, regions, accounts)
    for region in regions:
        key_id = f'alias/{params["KEY_ALIAS"]}-{region}'
        security_lake.encrypt_sqs_queues(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], region, key_id)


def provision_security_lake(params: dict, regions: list) -> None:
    """Enable Security Lake and configure Organization Configurations.

    Args:
        params: parameters
        regions: AWS regions
    """
    all_data = [{"region": region, "key_arn": f'alias/{params["KEY_ALIAS"]}-{region}'} for region in regions]
    sl_configurations = [{"encryptionConfiguration": {"kmsKeyId": data["key_arn"]}, "region": data["region"]} for data in all_data]
    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"],
        "sra-create-data-lake",
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
    )
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    LOGGER.info(f"Creating Security Lake in {(', '.join(regions))}")
    role_arn = f"arn:{PARTITION}:iam::{params['DELEGATED_ADMIN_ACCOUNT_ID']}:role/service-role/{params['META_STORE_MANAGER_ROLE_NAME']}"
    security_lake.create_security_lake(sl_client, sl_configurations, role_arn)
    status = security_lake.check_data_lake_create_status(sl_client, regions)
    if status:
        LOGGER.info("CreateDataLake status 'COMPLETED'")
    process_org_configuration(sl_client, params["SET_ORG_CONFIGURATION"], params["ORG_CONFIGURATION_SOURCES"], regions, params["SOURCE_VERSION"])


def update_security_lake(params: dict, regions: list) -> None:
    """Update Security Lake and Organization Configurations.

    Args:
        params: parameters
        regions: AWS regions
    """
    for region in regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"],
            "sra-update-security-lake",
            params["DELEGATED_ADMIN_ACCOUNT_ID"],
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        LOGGER.info(f"Checking if Security Lake is enabled in {region} region...")
        lake_exists = security_lake.check_data_lake_exists(sl_client, region)
        if lake_exists:
            LOGGER.info(f"Security Lake already enabled in {region} region.")
        else:
            LOGGER.info(f"Security Lake not found in {region} region. Enabling Security Lake...")
            key_id = f'alias/{params["KEY_ALIAS"]}-{region}'
            sl_configurations = [{"encryptionConfiguration": {"kmsKeyId": key_id}, "region": region}]
            role_arn = f"arn:{PARTITION}:iam::{params['DELEGATED_ADMIN_ACCOUNT_ID']}:role/service-role/{params['META_STORE_MANAGER_ROLE_NAME']}"
            security_lake.create_security_lake(sl_client, sl_configurations, role_arn)
            lake_exists = security_lake.check_data_lake_exists(sl_client, region)
            if lake_exists:
                LOGGER.info(f"Security Lake is enabled in {region}.")
            security_lake.encrypt_sqs_queues(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], region, key_id)
    process_org_configuration(sl_client, params["SET_ORG_CONFIGURATION"], params["ORG_CONFIGURATION_SOURCES"], regions, params["SOURCE_VERSION"])


def process_org_configuration(
    sl_client: SecurityLakeClient, set_org_configuration: bool, org_configuration_sources: str, regions: list, source_version: str
) -> None:
    """Set Security Lake organization configuration for new accounts.

    Args:
        sl_client: boto3 client
        set_org_configuration: enable organization configurations for new accounts
        org_configuration_sources: list of aws log sources
        regions: AWS regions
        source_version: source version
    """
    LOGGER.info(f"Checking if Organization Configuration enabled in {', '.join(regions)} region(s)")
    org_configuration_exists, existing_org_configuration = security_lake.get_org_configuration(sl_client)
    if set_org_configuration:
        sources = [source.strip() for source in org_configuration_sources.split(",")]
        if not org_configuration_exists:
            LOGGER.info(f"Organization Configuration not enabled in {', '.join(regions)} region(s). Creating...")
            security_lake.create_organization_configuration(sl_client, regions, sources, source_version)
            LOGGER.info("Enabled Organization Configuration")
        else:
            security_lake.update_organization_configuration(sl_client, regions, sources, source_version, existing_org_configuration)
    else:
        if org_configuration_exists:
            LOGGER.info(f"Deleting Organization Configuration in {r', '.join(regions)} region(s)...")
            security_lake.delete_organization_configuration(sl_client, existing_org_configuration)
            LOGGER.info("Deleted Organization Configuration")


def add_log_sources(params: dict, regions: list, org_accounts: dict) -> None:
    """Configure aws log sources.

    Args:
        params: Configuration parameters
        regions: A list of AWS regions.
        org_accounts: A list of AWS accounts.
    """
    aws_log_sources = []
    org_accounts_ids = [account["AccountId"] for account in org_accounts]
    delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-add-log-sources", params["DELEGATED_ADMIN_ACCOUNT_ID"])
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    for log_source in AWS_LOG_SOURCES:
        if params[log_source] != "":
            accounts = params[log_source].split(",") if params[log_source] != "ALL" else org_accounts_ids
            configurations = {"accounts": accounts, "regions": regions, "sourceName": log_source, "sourceVersion": params["SOURCE_VERSION"]}
            aws_log_sources.append(configurations)
    if aws_log_sources:
        security_lake.add_aws_log_source(sl_client, aws_log_sources)


def update_log_sources(params: dict, regions: list, org_accounts: dict) -> None:
    """Configure aws log sources.

    Args:
        params: Configuration parameters
        regions: A list of AWS regions.
        org_accounts: A list of AWS accounts.
    """
    org_accounts_ids = [account["AccountId"] for account in org_accounts]
    delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-update-log-sources", params["DELEGATED_ADMIN_ACCOUNT_ID"])
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    for log_source in AWS_LOG_SOURCES:
        if params[log_source] != "":
            accounts = params[log_source].split(",") if params[log_source] != "ALL" else org_accounts_ids
            security_lake.update_aws_log_source(sl_client, regions, log_source, accounts, org_accounts_ids, params["SOURCE_VERSION"])
        elif params[log_source] == "":
            result = security_lake.check_log_source_enabled(sl_client, [], org_accounts_ids, regions, log_source, params["SOURCE_VERSION"])
            accounts = list(result.accounts_to_disable)
            if result.source_exists:
                security_lake.delete_aws_log_source(sl_client, regions, log_source, accounts, params["SOURCE_VERSION"])
        else:
            LOGGER.info(f"Error reading value for {log_source} parameter")


def update_audit_acct_data_subscriber(params: dict, regions: list) -> None:
    """Configure Audit (Security Tooling) account as data access subscriber.

    Args:
        params: parameters
        regions: AWS regions
    """
    s3_access = "S3"
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for data access subscriber. Skipping...")
    else:
        for region in regions:
            subscriber_name = params["AUDIT_ACCT_DATA_SUBSCRIBER"] + "-" + region
            delegated_admin_session = common.assume_role(
                params["CONFIGURATION_ROLE_NAME"], "sra-process-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
            )
            sl_client = delegated_admin_session.client("securitylake", region, config=BOTO3_CONFIG)
            subscriber_exists, subscriber_id, external_id = security_lake.check_subscriber_exists(sl_client, subscriber_name)
            if subscriber_exists:
                security_lake.update_subscriber(
                    sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
                )
            else:
                external_id = params["DATA_SUBSCRIBER_EXTERNAL_ID"]
                LOGGER.info(f"Creating Audit account subscriber '{subscriber_name}' in {region} region...")
                subscriber_id, _ = security_lake.create_subscribers(
                    sl_client, s3_access, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
                )


def add_audit_acct_data_subscriber(sl_client: SecurityLakeClient, params: dict, region: str) -> None:
    """Configure Audit (Security Tooling) account as data access subscriber.

    Args:
        sl_client: boto3 client
        params: configuration parameters
        region: AWS region
    """
    subscriber_name = params["AUDIT_ACCT_DATA_SUBSCRIBER"] + "-" + region
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for data access subscriber. Skipping...")
    else:
        subscriber_exists, subscriber_id, external_id = security_lake.check_subscriber_exists(sl_client, subscriber_name)
        if subscriber_exists:
            security_lake.update_subscriber(sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"])
        else:
            external_id = params["DATA_SUBSCRIBER_EXTERNAL_ID"]
            LOGGER.info(f"Creating Audit account subscriber '{subscriber_name}' in {region} region...")
            subscriber_id, _ = security_lake.create_subscribers(
                sl_client, "S3", sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
            )


def update_audit_acct_query_subscriber(params: dict, regions: list) -> None:
    """Configure Audit (Security tooling) account as query access subscribe.

    Args:
        params: parameters
        regions: AWS regions
    """
    lakeformation_access = "LAKEFORMATION"
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for query access subscriber. Skipping...")
    else:
        for region in regions:
            subscriber_name = params["AUDIT_ACCT_QUERY_SUBSCRIBER"] + "-" + region
            delegated_admin_session = common.assume_role(
                params["CONFIGURATION_ROLE_NAME"], "sra-process-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
            )
            sl_client = delegated_admin_session.client("securitylake", region)
            subscriber_exists, subscriber_id, external_id = security_lake.check_subscriber_exists(sl_client, subscriber_name)
            if subscriber_exists:
                LOGGER.info(f"Audit account subscriber '{subscriber_name}' exists in {region} region. Updating subscriber...")
                resource_share_arn = security_lake.update_subscriber(
                    sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
                )
            else:
                external_id = params["QUERY_SUBSCRIBER_EXTERNAL_ID"]
                LOGGER.info(f"Audit account subscriber '{subscriber_name}' does not exist in {region} region. Creating subscriber...")
                subscriber_id, resource_share_arn = security_lake.create_subscribers(
                    sl_client, lakeformation_access, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
                )
            if params["CREATE_RESOURCE_LINK"]:
                configure_query_subscriber_on_update(
                    params["SUBSCRIBER_ROLE_NAME"], AUDIT_ACCT_ID, subscriber_name, params["DELEGATED_ADMIN_ACCOUNT_ID"], region, resource_share_arn, params["SUBSCRIBER_ROLE_NAME"]
                )


def add_audit_acct_query_subscriber(sl_client: SecurityLakeClient, params: dict, region: str) -> None:
    """Configure Audit (Security tooling) account as query access subscribe.

    Args:
        sl_client: boto3 client
        params: configuration parameters
        region: AWS region
    """
    subscriber_name = params["AUDIT_ACCT_QUERY_SUBSCRIBER"] + "-" + region
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for query access subscriber. Skipping...")
    else:
        external_id = params["QUERY_SUBSCRIBER_EXTERNAL_ID"]
        LOGGER.info(f"Audit account subscriber '{subscriber_name}' does not exist in {region} region. Creating subscriber...")
        security_lake.create_subscribers(sl_client, "LAKEFORMATION", sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"])


def configure_audit_acct_for_query_access(params: dict, regions: list) -> None:
    """Configure resources for query access in Audit account.

    Args:
        params: configuration parameters
        regions: AWS regions
    """
    for region in regions:
        subscriber_name = params["AUDIT_ACCT_QUERY_SUBSCRIBER"] + "-" + region
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-process-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_created, resource_share_arn = security_lake.get_subscriber_resourceshare_arn(sl_client, subscriber_name)
        if subscriber_created:
            LOGGER.info(f"Configuring Audit (Security tooling) account subscriber '{subscriber_name}' ({region})")
            if params["CREATE_RESOURCE_LINK"]:
                configure_query_subscriber_on_update(
                    params["SUBSCRIBER_ROLE_NAME"], AUDIT_ACCT_ID, subscriber_name, params["DELEGATED_ADMIN_ACCOUNT_ID"], region, resource_share_arn, params["SUBSCRIBER_ROLE_NAME"]
                )


def configure_query_subscriber_on_update(
    configuration_role_name: str, subscriber_acct: str, subscriber_name: str, security_lake_acct: str, region: str, resource_share_arn: str, subscriber_role: str
) -> None:
    """Configure query access subscriber.

    Args:
        configuration_role_name: configuration role name
        subscriber_acct: subscriber AWS account
        subscriber_name: subscriber name
        security_lake_acct: Security Lake delegated administrator account
        region: AWS region
        resource_share_arn: RAM resource share arn
    """
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
    ram_client = subscriber_session.client("ram", region)
    LOGGER.info(f"Configuring resource share link for subscriber '{subscriber_name}' ({region})")
    security_lake.configure_resource_share_in_subscriber_acct(ram_client, resource_share_arn)
    shared_db_name, shared_tables = security_lake.get_shared_resource_names(ram_client, resource_share_arn)
    if shared_tables == "" or shared_db_name == "":
        LOGGER.info(f"No shared resource names found for subscriber '{subscriber_name}' ({region})")
    else:
        subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share-link", subscriber_acct)
        glue_client = subscriber_session.client("glue", region)
        LOGGER.info(f"Creating database '{shared_db_name}_subscriber' for subscriber '{subscriber_name}' ({region})")
        security_lake.create_db_in_data_catalog(glue_client, subscriber_acct, shared_db_name, region, subscriber_role)
        security_lake.create_table_in_data_catalog(glue_client, shared_db_name, shared_tables, security_lake_acct, subscriber_acct, region)


def disable_security_lake(params: dict, regions: list, accounts: dict) -> None:
    """Disable Security Lake service.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts
    """
    for region in regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-delete-security-lake-subscribers", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
            subscriber_name = params["AUDIT_ACCT_DATA_SUBSCRIBER"] + "-" + region
            security_lake.delete_subscriber(sl_client, subscriber_name, region)
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            subscriber_name = params["AUDIT_ACCT_QUERY_SUBSCRIBER"] + "-" + region
            security_lake.delete_subscriber(sl_client, subscriber_name, region)

        org_configuration_exists, existing_org_configuration = security_lake.get_org_configuration(sl_client)
        if org_configuration_exists:
            # LOGGER.info(f"Deleting Organization Configuration in {region} region...")
            # security_lake.delete_organization_configuration(sl_client, existing_org_configuration)

    all_accounts = [account["AccountId"] for account in accounts]
    for source in AWS_LOG_SOURCES:
        security_lake.delete_aws_log_source(sl_client, regions, source, all_accounts, params["SOURCE_VERSION"])

    security_lake.delete_security_lake(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION, regions)  # todo: remove after testing


def orchestrator(event: dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        LOGGER.info("...calling helper...")
        helper(event, context)
    else:
        LOGGER.info("...else...just calling process_event...")
        process_event(event)


def lambda_handler(event: dict[str, Any], context: Any) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Lambda Handler Started....")
    boto3_version = boto3.__version__
    LOGGER.info(f"boto3 version: {boto3_version}")
    try:
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None


@helper.create
@helper.update
@helper.delete
def process_event_cloudformation(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa U100
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({"RequestType": event["RequestType"]})
    # excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
    accounts = common.get_active_organization_accounts()
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"])
    if params["action"] == "Add":
        process_add_event(params, regions, accounts)
    elif params["action"] == "Update":
        process_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable Security Lake from (process_event_cloudformation)")
        process_delete_event(params, regions, accounts)

    return f"sra-security-lake-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"
