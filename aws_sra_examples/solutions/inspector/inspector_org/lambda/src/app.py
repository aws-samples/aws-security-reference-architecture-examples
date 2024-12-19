"""This script performs operations to enable, configure, and disable Inspector.

Version: 1.0

'inspector_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Literal, Optional

import boto3
import common
import inspector
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_inspector2.type_defs import AutoEnableTypeDef
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sns.type_defs import PublishBatchResponseTypeDef

LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

UNEXPECTED = "Unexpected!"
SERVICE_NAME = "inspector2.amazonaws.com"
SNS_PUBLISH_BATCH_MAX = 10
ALL_INSPECTOR_SCAN_COMPONENTS = ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]

helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def process_add_update_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts

    Returns:
        Status
    """
    LOGGER.info("...process_add_update_event")

    if params["action"] == "Add":
        LOGGER.info("...Enable Inspector")
        setup_inspector_global(params, regions, accounts)
        LOGGER.info("...ADD_UPDATE_COMPLETE")
        return
    if params["action"] == "Update":
        LOGGER.info("...Update Inspector")
        setup_inspector_global(params, regions, accounts)
        LOGGER.info("...ADD_UPDATE_COMPLETE")

    LOGGER.info("...ADD_UPDATE_NO_EVENT")


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters({"RequestType": "Update"})

    excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
    accounts = common.get_active_organization_accounts(excluded_accounts)
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
    if event.get("ResourceType") == "Terraform" and event.get("tf", {}).get("action") == "delete":
        LOGGER.info("...Disable Inspector from Terraform")
        disabled_inspector_service(params, regions)
    elif event.get("RequestType") == "Delete":
        LOGGER.info("...Disable Inspector via process_event")
        disabled_inspector_service(params, regions)
    else:
        process_add_update_event(params, regions, accounts)


def parameter_pattern_validator(parameter_name: str, parameter_value: Optional[str], pattern: str, is_optional: bool = False) -> dict:
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


def get_validated_parameters(event: Dict[str, Any]) -> dict:
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]
    true_false_pattern = r"^true|false$"
    sns_topic_pattern = r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"

    # Required Parameters
    params.update(
        parameter_pattern_validator(
            "AWS_PARTITION",
            os.environ.get("AWS_PARTITION"),
            pattern=r"^(aws[a-zA-Z-]*)?$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "CONFIGURATION_ROLE_NAME",
            os.environ.get("CONFIGURATION_ROLE_NAME"),
            pattern=r"^[\w+=,.@-]{1,64}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "CONTROL_TOWER_REGIONS_ONLY",
            os.environ.get("CONTROL_TOWER_REGIONS_ONLY"),
            pattern=true_false_pattern,
        )
    )
    params.update(
        parameter_pattern_validator(
            "DELEGATED_ADMIN_ACCOUNT_ID",
            os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID"),
            pattern=r"^\d{12}$",
        )
    )
    params.update(
        parameter_pattern_validator(
            "MANAGEMENT_ACCOUNT_ID",
            os.environ.get("MANAGEMENT_ACCOUNT_ID"),
            pattern=r"^\d{12}$",
        )
    )
    params.update(parameter_pattern_validator("SNS_TOPIC_ARN", os.environ.get("SNS_TOPIC_ARN"), pattern=sns_topic_pattern))
    params.update(
        parameter_pattern_validator(
            "SCAN_COMPONENTS",
            os.environ.get("SCAN_COMPONENTS"),
            pattern=r"(?i)^((ec2|ecr|lambda|lambda_code),?){0,3}(ec2|ecr|lambda|lambda_code){1}$",
        )
    )
    params.update(parameter_pattern_validator("ECR_SCAN_DURATION", os.environ.get("ECR_SCAN_DURATION"), pattern=r"^(LIFETIME|DAYS_30|DAYS_180){1}$"))
    params.update(parameter_pattern_validator("EC2_SCAN_MODE", os.environ.get("EC2_SCAN_MODE"), pattern=r"^(EC2_SSM_AGENT_BASED|EC2_HYBRID){1}$"))

    # Optional Parameters
    params.update(
        parameter_pattern_validator(
            "ENABLED_REGIONS",
            os.environ.get("ENABLED_REGIONS"),
            pattern=r"^$|[a-z0-9-, ]+$",
            is_optional=True,
        )
    )

    return params


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
        LOGGER.info(f"Account ({delegated_admin_account_id}) is not a registered delegated administrator: {error}")


def check_aws_service_access(service_principal: str = SERVICE_NAME) -> bool:
    """Check service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service Principal. Defaults to SERVICE_NAME.

    Returns:
        bool: service access enabled true/false
    """
    aws_service_access_enabled = False
    LOGGER.info(f"Checking service access for {service_principal}...")
    try:
        org_svc_response = ORG_CLIENT.list_aws_service_access_for_organization()
        api_call_details = {
            "API_Call": "organizations:ListAwsServiceAccessForOrganization",
            "API_Response": org_svc_response,
        }
        LOGGER.info(api_call_details)

        for service in org_svc_response["EnabledServicePrincipals"]:
            if service["ServicePrincipal"] == service_principal:
                aws_service_access_enabled = True
                return True
    except ORG_CLIENT.exceptions.AccessDeniedException as error:
        LOGGER.info(f"Unable to check service access for {service_principal}: {error}")
    return aws_service_access_enabled


def check_delegated_administrator(delegated_admin_account: str, service_principal: str = SERVICE_NAME) -> bool:
    """Check delegated administrator for the provided service principal within AWS Organizations.

    Args:
        delegated_admin_account: delegated admin account Id
        service_principal: Service Principal Defaults to SERVICE_NAME.

    Returns:
        bool: delegated administrator enabled true/false
    """
    delegated_administrator_enabled = False
    try:
        LOGGER.info(f"Checking delegated admin for {service_principal}")
        list_delegated_admin_response = ORG_CLIENT.list_delegated_administrators(
            ServicePrincipal=service_principal,
        )
        for delegated_admin in list_delegated_admin_response["DelegatedAdministrators"]:
            if delegated_admin["Id"] == delegated_admin_account:
                LOGGER.info("Delegated admin account setup")
                delegated_administrator_enabled = True
    except ORG_CLIENT.exceptions.AccessDeniedException as error:
        LOGGER.info(f"Unable to check delegated admin for {service_principal}: {error}")
    return delegated_administrator_enabled


def enable_aws_service_access(service_principal: str = SERVICE_NAME) -> None:
    """Enable service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service Principal
    """
    if check_aws_service_access(service_principal) is False:
        try:
            LOGGER.info(f"Enabling service access for {service_principal}")
            ORG_CLIENT.enable_aws_service_access(ServicePrincipal=service_principal)
        except ORG_CLIENT.exceptions.AccessDeniedException as error:
            LOGGER.info(f"Failed to enable service access for {service_principal} in organizations: {error}")
    else:
        LOGGER.info(f"Organizations service access for {service_principal} is already enabled")


def register_delegated_administrator(delegated_admin_account: str, service_principal: str = SERVICE_NAME) -> None:
    """Register delegated administrator for the provided service principal within AWS Organizations.

    Args:
        delegated_admin_account: delegated admin account Id
        service_principal: Service Principal
    """
    if check_delegated_administrator(delegated_admin_account, service_principal) is False:
        LOGGER.info(f"Designating delegated admin account ({delegated_admin_account}) for {service_principal}")
        try:
            ORG_CLIENT.register_delegated_administrator(AccountId=delegated_admin_account, ServicePrincipal=service_principal)
        except ORG_CLIENT.exceptions.AccountAlreadyRegisteredException as error:
            LOGGER.info(f"Delegated admin account ({delegated_admin_account}) already registered for {service_principal}: {error}")
    else:
        LOGGER.info(f"Organizations delegated administrator ({delegated_admin_account} for {service_principal} is already set.")


def disable_aws_service_access(service_principal: str = SERVICE_NAME) -> None:
    """Disable service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service Principal
    """
    try:
        LOGGER.info(f"Disabling service access for {service_principal}")

        ORG_CLIENT.disable_aws_service_access(ServicePrincipal=service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
        LOGGER.info(f"Service ({service_principal}) does not have organizations access revoked: {error}")


def disabled_inspector_service(params: dict, regions: list) -> None:
    """Primary function to remove all components of the inspector sra feature.

    Args:
        params: Configuration Parameters
        regions: list of regions
    """
    scan_components = params["SCAN_COMPONENTS"].split(",")
    LOGGER.info("Remove inspector")
    LOGGER.info(f"disabled_inspector_service: scan_components as ({scan_components})")
    inspector.disable_inspector_in_associated_member_accounts(
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
        params["CONFIGURATION_ROLE_NAME"],
        regions,
        scan_components,
    )

    inspector.disable_auto_scanning_in_org(params["DELEGATED_ADMIN_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"], regions)

    inspector.disable_organization_admin_account(regions)

    inspector.disable_inspector2_in_mgmt_and_delegated_admin(
        regions,
        params["CONFIGURATION_ROLE_NAME"],
        params["MANAGEMENT_ACCOUNT_ID"],
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
        # ALL_INSPECTOR_SCAN_COMPONENTS,
        scan_components,
    )

    deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

    disable_aws_service_access(SERVICE_NAME)


def setup_inspector_global(params: dict, regions: list, accounts: list) -> None:
    """Enable the inspector service and configure its global settings.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts
    """
    enable_aws_service_access(SERVICE_NAME)

    register_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

    inspector.create_service_linked_role(params["MANAGEMENT_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"])
    for account in accounts:
        inspector.create_service_linked_role(account["AccountId"], params["CONFIGURATION_ROLE_NAME"])

    create_sns_messages(accounts, regions, params["SNS_TOPIC_ARN"], "configure")


def setup_inspector_in_region(
    region: str,
    accounts: list,
    delegated_admin_account: str,
    management_account: str,
    configuration_role_name: str,
    scan_components: list,
    ecr_scan_duration: Literal["DAYS_180", "DAYS_30", "LIFETIME"],
    ec2_scan_mode: Literal["EC2_SSM_AGENT_BASED", "EC2_HYBRID"],
) -> None:
    """Regional setup process of the inspector feature.

    Args:
        region: region
        accounts: list of account Ids
        delegated_admin_account: account Id of the delegated admin account
        management_account: account Id of the management account
        configuration_role_name: name of the configuration role
        scan_components: list of components to scan
        ecr_scan_duration: ecr scan duration
        ec2_scan_mode: ec2 scan mode
    """
    scan_component_dict: AutoEnableTypeDef = {"ec2": False, "ecr": False, "lambda": False, "lambdaCode": False}
    for scan_component in scan_components:
        scan_component_dict[common.snake_to_camel(scan_component)] = True  # type: ignore

    if scan_component_dict["lambdaCode"] and not scan_component_dict["lambda"]:
        scan_component_dict["lambda"] = True

    disabled_components: list = []
    for scan_component in scan_component_dict:
        if scan_component_dict[scan_component] is False:  # type: ignore
            disabled_components.append(scan_component)

    LOGGER.info(f"setup_inspector_in_region: scan_components - ({scan_components}) in {region}")
    LOGGER.info(f"setup_inspector_in_region: created scan_component_dict as ({scan_component_dict})")
    inspector.enable_inspector2_in_mgmt_and_delegated_admin(
        region, configuration_role_name, management_account, delegated_admin_account, scan_components
    )

    inspector.set_inspector_delegated_admin_in_mgmt(delegated_admin_account, region)
    LOGGER.info("Waiting 20 seconds before configuring inspector org auto-enable.")
    sleep(20)

    inspector.set_auto_enable_inspector_in_org(region, configuration_role_name, delegated_admin_account, scan_component_dict)

    LOGGER.info(f"setup_inspector_in_region: ECR_SCAN_DURATION - {ecr_scan_duration}")
    inspector.set_ecr_scan_duration(region, configuration_role_name, delegated_admin_account, ecr_scan_duration)

    LOGGER.info(f"setup_inspector_in_region: EC2_SCAN_MODE - {ec2_scan_mode}")
    inspector.set_ec2_scan_mode(region, configuration_role_name, delegated_admin_account, ec2_scan_mode)

    inspector.associate_inspector_member_accounts(configuration_role_name, delegated_admin_account, accounts, region)

    inspector.enable_inspector2_in_member_accounts(region, configuration_role_name, delegated_admin_account, scan_components, accounts)
    LOGGER.info("Waiting 20 seconds before checking for components that need to be disabled.")
    sleep(20)

    all_accounts: list = []
    for account in accounts:
        all_accounts.append(account["AccountId"])
    all_accounts.append(management_account)
    all_accounts.append(delegated_admin_account)
    inspector.check_scan_component_enablement_for_accounts(
        all_accounts, delegated_admin_account, disabled_components, configuration_role_name, region
    )


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
    excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
    accounts = common.get_active_organization_accounts(excluded_accounts)
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    if params["action"] in ["Add", "Update"]:
        LOGGER.info("calling process_add_update_event")
        process_add_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable Inspector from (process_event_cloudformation)")
        disabled_inspector_service(params, regions)

    return f"sra-inspector-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def create_sns_messages(accounts: list, regions: list, sns_topic_arn: str, action: str) -> None:
    """Create SNS Message.

    Args:
        accounts: Account List
        regions: list of AWS regions
        sns_topic_arn: SNS Topic ARN
        action: Action
    """
    sns_messages = []
    for region in regions:
        sns_message = {"Accounts": accounts, "Region": region, "Action": action}
        sns_messages.append(
            {
                "Id": region,
                "Message": json.dumps(sns_message),
                "Subject": "Inspector Configuration",
            }
        )

    process_sns_message_batches(sns_messages, sns_topic_arn)


def publish_sns_message_batch(message_batch: list, sns_topic_arn: str) -> None:
    """Publish SNS Message Batches.

    Args:
        message_batch: Batch of SNS messages
        sns_topic_arn: SNS Topic ARN
    """
    LOGGER.info("Publishing SNS Message Batch")
    LOGGER.info({"SNSMessageBatch": message_batch})
    response: PublishBatchResponseTypeDef = SNS_CLIENT.publish_batch(TopicArn=sns_topic_arn, PublishBatchRequestEntries=message_batch)
    api_call_details = {"API_Call": "sns:PublishBatch", "API_Response": response}
    LOGGER.info(api_call_details)


def process_sns_message_batches(sns_messages: list, sns_topic_arn: str) -> None:
    """Process SNS Message Batches for Publishing.

    Args:
        sns_messages: SNS messages to be batched.
        sns_topic_arn: SNS Topic ARN
    """
    message_batches = []
    for i in range(
        SNS_PUBLISH_BATCH_MAX,
        len(sns_messages) + SNS_PUBLISH_BATCH_MAX,
        SNS_PUBLISH_BATCH_MAX,
    ):
        message_batches.append(sns_messages[i - SNS_PUBLISH_BATCH_MAX : i])

    for batch in message_batches:
        publish_sns_message_batch(batch, sns_topic_arn)


def process_event_sns(event: dict) -> None:
    """Process SNS event to complete the setup process.

    Args:
        event: event data
    """
    params = get_validated_parameters({})
    scan_components = params["SCAN_COMPONENTS"].split(",")
    for record in event["Records"]:
        record["Sns"]["Message"] = json.loads(record["Sns"]["Message"])
        LOGGER.info({"SNS Record": record})
        message = record["Sns"]["Message"]
        if message["Action"] == "configure":
            LOGGER.info("Continuing process to enable Inspector (sns event)")

            setup_inspector_in_region(
                message["Region"],
                message["Accounts"],
                params["DELEGATED_ADMIN_ACCOUNT_ID"],
                params["MANAGEMENT_ACCOUNT_ID"],
                params["CONFIGURATION_ROLE_NAME"],
                scan_components,
                params["ECR_SCAN_DURATION"],
                params["EC2_SCAN_MODE"],
            )


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        if event.get("ResourceType") and event["ResourceType"] == "Terraform":
            LOGGER.info("...calling process_event from Terraform...")
            process_event(event)
        else:
            LOGGER.info("...calling helper...")
            helper(event, context)
    elif event.get("Records") and event["Records"][0]["EventSource"] == "aws:sns":
        LOGGER.info("...aws:sns record...")
        process_event_sns(event)
    else:
        LOGGER.info("...else...just calling process_event...")
        process_event(event)


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
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
    event_info = {"Event": event}
    LOGGER.info(event_info)
    try:
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None
