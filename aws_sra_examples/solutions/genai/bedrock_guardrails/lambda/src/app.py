"""This script performs operations to create, configure, and delete Bedrock guardrails.

Version: 1.0

Main app module for SRA GenAI Bedrock org safeguards solution in the repo,
https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
import cfnresponse
import sra_bedrock
import sra_dynamodb
import sra_kms
import sra_lambda
import sra_s3
import sra_sqs
import sra_ssm_params
import sra_sts

LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "INFO")
LOGGER.setLevel(log_level)


def load_kms_key_policies() -> dict:
    """Load KMS Key Policies from JSON file.

    Returns:
        dict: KMS Key Policies
    """
    LOGGER.info("...load_kms_key_policies")
    json_file_path = Path(__file__).parent / "sra_kms_keys.json"
    with json_file_path.open("r") as file:
        return json.load(file)


# Global vars
RESOURCE_TYPE: str = ""
SOLUTION_NAME: str = "sra-bedrock-guardrails"
BEDROCK_ORG_SOLUTION_NAME = "sra-bedrock-org"
GUARDRAIL_RULE_NAME = "sra-bedrock-check-guardrails"
ENCRYPTION_RULE_NAME = "sra-bedrock-check-guardrail-encryption"
GOVERNED_REGIONS = []
ORGANIZATION_ID = ""
SRA_ALARM_TOPIC_ARN: str = ""
STATE_TABLE: str = "sra_state"  # for saving resource info
CFN_CUSTOM_RESOURCE: str = "Custom::LambdaCustomResource"

LAMBDA_RECORD_ID: str = ""
LAMBDA_START: str = ""
LAMBDA_FINISH: str = ""

ACCOUNT: Optional[str] = boto3.client("sts").get_caller_identity().get("Account")
LOGGER.info(f"Account: {ACCOUNT}")
REGION: Optional[str] = os.environ.get("AWS_REGION")
LOGGER.info(f"Region: {REGION}")
CFN_RESOURCE_ID: str = "sra-bedrock-guardrails-function"
GUARDRAILS_KEY_ALIAS = "sra-bedrock-guardrails-key"

# CFN_RESPONSE_DATA definition:
#   dry_run: bool - type of run
#   deployment_info: dict - information about the deployment
#       action_count: int - number of actions taken
#       resources_deployed: int - number of resources deployed
#       configuration_changes: int - number of configuration changes
CFN_RESPONSE_DATA: dict = {"dry_run": True, "deployment_info": {"action_count": 0, "resources_deployed": 0, "configuration_changes": 0}}

# dry run global variables
DRY_RUN: bool = True
DRY_RUN_DATA: dict = {}

# other global variables
LIVE_RUN_DATA: dict = {}
KMS_KEY_POLICIES: dict = load_kms_key_policies()

# Parameter validation rules
PARAMETER_VALIDATION_RULES: dict = {  # noqa: ECE001
    "DRY_RUN": r"^true|false$",
    "EXECUTION_ROLE_NAME": r"^sra-execution$",
    "LOG_LEVEL": r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
    "SOLUTION_NAME": r"^sra-bedrock-guardrails$",
    "SOLUTION_VERSION": r"^[0-9]+\.[0-9]+\.[0-9]+$",
    "SRA_BEDROCK_ACCOUNTS": r"^(ALL|(\d{12})(,\s*\d{12})*)$",
    "SRA_BEDROCK_REGIONS": r"^((?:[a-z0-9-]+(?:\s*,\s*)?)*)$",
    "BEDROCK_GUARDRAIL_LAMBDA_ROLE_NAME": r"^[\w+=,.@-]{1,64}$",
    "BEDROCK_GUARDRAIL_NAME": r"^[0-9a-zA-Z-_]{1,50}$",
    "BLOCKED_INPUT_MESSAGING": r"^.{1,500}$",
    "BLOCKED_OUTPUTS_MESSAGING": r"^.{1,500}$",
    "DEPLOY_CONTEXTUAL_GROUNDING_POLICY": r"^true|false$",
    "DEPLOY_GUARDRAIL_CONTENT_POLICY": r"^true|false$",
    "DEPLOY_GUARDRAIL_TOPIC_POLICY": r"^true|false$",
    "DEPLOY_MANAGED_WORD_LISTS_CONFIG": r"^true|false$",
    "DEPLOY_SENSITIVE_INFORMATION_POLICY": r"^true|false$",
    "DEPLOY_WORD_POLICY": r"^true|false$",
    "GUARDRAIL_CONTENT_POLICY_CONFIG": (
        r'^\[\s*(?:{"type":"(SEXUAL|VIOLENCE|HATE|INSULTS|MISCONDUCT)",'
        + r'\s*"inputStrength":"(NONE|LOW|MEDIUM|HIGH)",'
        + r'\s*"outputStrength":"(NONE|LOW|MEDIUM|HIGH)"}(?:\s*,\s*{"type":"(?!\1)'
        + r'(SEXUAL|VIOLENCE|HATE|INSULTS|MISCONDUCT)",'
        + r'\s*"inputStrength":"(NONE|LOW|MEDIUM|HIGH)",'
        + r'\s*"outputStrength":"(NONE|LOW|MEDIUM|HIGH)"})*'
        + r'(?:\s*,\s*{"type":"PROMPT_ATTACK",'
        + r'\s*"inputStrength":"(NONE|LOW|MEDIUM|HIGH)",'
        + r'\s*"outputStrength":"NONE"})?\s*)]$'
    ),
    "GUARDRAIL_GROUNDING_POLICY_CONFIG": (
        r'^\[{"type":\s*"(GROUNDING|RELEVANCE)",'
        + r'\s*"threshold":\s*(0(\.\d{1,2})?|0\.99)}'
        + r'(\s*,\s*{"type":\s*"(GROUNDING|RELEVANCE)",'
        + r'\s*"threshold":\s*(0(\.\d{1,2})?|0\.99)})?\]$'
    ),
    "GUARDRAIL_PII_ENTITY": (
        r'^\[(?:\s*\{\s*"type"\s*:\s*"('
        + r"ADDRESS|AGE|AWS_ACCESS_KEY|AWS_SECRET_KEY|CA_HEALTH_NUMBER|CA_SOCIAL_INSURANCE_NUMBER|"
        + r"CREDIT_DEBIT_CARD_CVV|CREDIT_DEBIT_CARD_EXPIRY|CREDIT_DEBIT_CARD_NUMBER|DRIVER_ID|EMAIL|"
        + r"INTERNATIONAL_BANK_ACCOUNT_NUMBER|IP_ADDRESS|LICENSE_PLATE|MAC_ADDRESS|NAME|PASSWORD|PHONE|PIN|"
        + r"SWIFT_CODE|UK_NATIONAL_HEALTH_SERVICE_NUMBER|UK_NATIONAL_INSURANCE_NUMBER|"
        + r"UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER|URL|USERNAME|US_BANK_ACCOUNT_NUMBER|US_BANK_ROUTING_NUMBER|"
        + r"US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER|US_PASSPORT_NUMBER|US_SOCIAL_SECURITY_NUMBER|"
        + r'VEHICLE_IDENTIFICATION_NUMBER)"\s*,\s*"action"\s*:\s*"(BLOCK|ANONYMIZE)"\s*\})'
        + r'(?!.*"type"\s*:\s*"\1")'
        + r'(?:\s*,\s*\{\s*"type"\s*:\s*"('
        + r"ADDRESS|AGE|AWS_ACCESS_KEY|AWS_SECRET_KEY|CA_HEALTH_NUMBER|CA_SOCIAL_INSURANCE_NUMBER|"
        + r"CREDIT_DEBIT_CARD_CVV|CREDIT_DEBIT_CARD_EXPIRY|CREDIT_DEBIT_CARD_NUMBER|DRIVER_ID|EMAIL|"
        + r"INTERNATIONAL_BANK_ACCOUNT_NUMBER|IP_ADDRESS|LICENSE_PLATE|MAC_ADDRESS|NAME|PASSWORD|PHONE|PIN|"
        + r"SWIFT_CODE|UK_NATIONAL_HEALTH_SERVICE_NUMBER|UK_NATIONAL_INSURANCE_NUMBER|"
        + r"UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER|URL|USERNAME|US_BANK_ACCOUNT_NUMBER|US_BANK_ROUTING_NUMBER|"
        + r"US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER|US_PASSPORT_NUMBER|US_SOCIAL_SECURITY_NUMBER|"
        + r'VEHICLE_IDENTIFICATION_NUMBER)"\s*,\s*"action"\s*:\s*"(BLOCK|ANONYMIZE)"\s*\}'
        + r'(?!.*"type"\s*:\s*"\3"))*\s*\]$'
    ),
    "GUARDRAIL_TOPIC_POLICY_CONFIG": (
        r"^\[(\{"
        + r'"name":\s*"[0-9a-zA-Z\-_ !?\.]{1,100}",'
        + r'\s*"definition":\s*"[^"]{1,200}",'
        + r'\s*("examples":\s*\["[^"]{1,100}"'
        + r'(\s*,\s*"[^"]{1,100}"){0,4}\]\s*,\s*)?'
        + r'"type":\s*"DENY"\}'
        + r"(\s*,\s*\{"
        + r'"name":\s*"[A-Za-z0-9\-]{1,100}",'
        + r'\s*"definition":\s*"[^"]{1,200}",'
        + r'\s*("examples":\s*\["[^"]{1,100}"'
        + r'(\s*,\s*"[^"]{1,100}"){0,4}\]\s*,\s*)?'
        + r'"type":\s*"DENY"\}'
        + r"){0,29})\]$"
    ),
    "GUARDRAIL_WORD_CONFIG": r'^\[(?:{\s*"text":\s*"[^"]{1,100}"\s*}(?:,\s*{"text":\s*"[^"]{1,100}"}){0,99})\]$',
}


# Instantiate sra class objects
ssm_params = sra_ssm_params.SRASSMParams()
dynamodb = sra_dynamodb.SRADynamoDB()
sts = sra_sts.SRASTS()
s3 = sra_s3.SRAS3()
lambdas = sra_lambda.SRALambda()
kms = sra_kms.SRAKMS()
bedrock = sra_bedrock.SRABedrock()
sqs = sra_sqs.SRASQS()


def get_resource_parameters(event: dict) -> None:  # noqa: U100
    """Get resource parameters from event.

    Args:
        event: event from lambda handler

    Raises:
        ValueError: If the event is not valid
    """
    LOGGER.info("Getting resource parameters...")
    global DRY_RUN
    global GOVERNED_REGIONS
    global CFN_RESPONSE_DATA
    global ORGANIZATION_ID

    param_validation: dict = validate_parameters(event["ResourceProperties"], PARAMETER_VALIDATION_RULES)
    if param_validation["success"] is False:
        LOGGER.info(f"Parameter validation failed: {param_validation['errors']}")
        raise ValueError(f"Parameter validation failed: {param_validation['errors']}") from None
    else:
        LOGGER.info("Parameter validation succeeded")

    LOGGER.info("Getting resource params...")

    sts.CONFIGURATION_ROLE = "sra-execution"
    governed_regions_param = ssm_params.get_ssm_parameter(
        ssm_params.MANAGEMENT_ACCOUNT_SESSION, REGION, "/sra/regions/customer-control-tower-regions"
    )
    if governed_regions_param[0] is True:
        GOVERNED_REGIONS = governed_regions_param[1]
        LOGGER.info(f"Successfully retrieved the SRA governed regions parameter: {GOVERNED_REGIONS}")
    else:
        LOGGER.info("Error retrieving SRA governed regions ssm parameter.  Is the SRA common prerequisites solution deployed?")
        raise ValueError("Error retrieving SRA governed regions ssm parameter.  Is the SRA common prerequisites solution deployed?") from None

    security_acct_param = ssm_params.get_ssm_parameter(ssm_params.MANAGEMENT_ACCOUNT_SESSION, REGION, "/sra/control-tower/audit-account-id")
    if security_acct_param[0] is True:
        ssm_params.SRA_SECURITY_ACCT = security_acct_param[1]
        LOGGER.info(f"Successfully retrieved the SRA security account parameter: {ssm_params.SRA_SECURITY_ACCT}")
    else:
        LOGGER.info("Error retrieving SRA security account ssm parameter.  Is the SRA common prerequisites solution deployed?")
        raise ValueError("Error retrieving SRA security account ssm parameter.  Is the SRA common prerequisites solution deployed?") from None

    org_id_param = ssm_params.get_ssm_parameter(ssm_params.MANAGEMENT_ACCOUNT_SESSION, REGION, "/sra/control-tower/organization-id")
    if org_id_param[0] is True:
        ORGANIZATION_ID = org_id_param[1]
        LOGGER.info(f"Successfully retrieved the SRA organization id parameter: {ORGANIZATION_ID}")
    else:
        LOGGER.info("Error retrieving SRA organization id ssm parameter.  Is the SRA common prerequisites solution deployed?")
        raise ValueError("Error retrieving SRA organization id ssm parameter.  Is the SRA common prerequisites solution deployed?") from None

    staging_bucket_param = ssm_params.get_ssm_parameter(ssm_params.MANAGEMENT_ACCOUNT_SESSION, REGION, "/sra/staging-s3-bucket-name")
    if staging_bucket_param[0] is True:
        s3.STAGING_BUCKET = staging_bucket_param[1]
        LOGGER.info(f"Successfully retrieved the SRA staging bucket parameter: {s3.STAGING_BUCKET}")
    else:
        LOGGER.info("Error retrieving SRA staging bucket ssm parameter.  Is the SRA common prerequisites solution deployed?")
        raise ValueError("Error retrieving SRA staging bucket ssm parameter.  Is the SRA common prerequisites solution deployed?") from None

    if event["ResourceProperties"]["DRY_RUN"] == "true":
        # dry run
        LOGGER.info("Dry run enabled...")
        DRY_RUN = True
    else:
        # live run
        LOGGER.info("Dry run disabled...")
        DRY_RUN = False
    CFN_RESPONSE_DATA["dry_run"] = DRY_RUN


def validate_parameters(parameters: Dict[str, str], rules: Dict[str, str]) -> Dict[str, object]:
    """Validate parameters.

    Args:
        parameters (Dict[str, str]): Dictionary of parameters to validate
        rules (Dict[str, str]): Dictionary of parameter names and regex patterns

    Returns:
        Dict[str, object]: Dictionary with 'success' key (bool) and 'errors' key (list of error messages)
    """
    errors: List[str] = []
    for param, regex in rules.items():
        value = parameters.get(param)
        if value is None:
            errors.append(f"Parameter '{param}' is missing.")
        elif not re.match(regex, value):
            errors.append(f"Parameter '{param}' with value '{value}' does not match the expected pattern '{regex}'.")

    return {"success": len(errors) == 0, "errors": errors}


def get_accounts_and_regions(accounts: str, regions: str) -> tuple[list, list]:
    """Get accounts and regions from event and return them in a tuple.

    Args:
        accounts: AWS account ids
        regions: AWS regions

    Returns:
        tuple: (accounts, regions)
            accounts: list of accounts to deploy the guardrail to
            region: list of regions to deploy the guardrail to
    """
    if accounts.strip():
        LOGGER.info({"CUSTOMER PROVIDED BEDROCK ACCOUNTS": accounts})
        accounts_list = []
        for acct in accounts.split(","):
            if acct != "":
                accounts_list.append(acct.strip())
    LOGGER.info(f"SRA_BEDROCK_ACCOUNTS: {accounts_list}")

    if regions.strip():
        LOGGER.info({"CUSTOMER PROVIDED BEDROCK REGIONS": regions})
        regions_list = []
        for region in regions.split(","):
            if region != "":
                regions_list.append(region.strip())
    LOGGER.info(f"SRA_BEDROCK_REGIONS: {regions_list}")

    return accounts_list, regions_list


def deploy_state_table() -> None:
    """Deploy the state table to DynamoDB."""
    LOGGER.info("Deploying the state table to DynamoDB...")
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    if DRY_RUN is False:
        LOGGER.info("Live run: creating the state table...")
        dynamodb.DYNAMODB_CLIENT = sts.assume_role(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "dynamodb", sts.HOME_REGION)
        dynamodb.DYNAMODB_RESOURCE = sts.assume_role_resource(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "dynamodb", sts.HOME_REGION)

        if dynamodb.table_exists(STATE_TABLE) is False:
            dynamodb.create_table(STATE_TABLE)

        item_found, find_result = dynamodb.find_item(
            STATE_TABLE,
            "sra-common-prerequisites",
            {
                "arn": f"arn:aws:dynamodb:{sts.HOME_REGION}:{ssm_params.SRA_SECURITY_ACCT}:table/{STATE_TABLE}",
            },
        )
        if item_found is False:
            dynamodb_record_id, dynamodb_date_time = dynamodb.insert_item(STATE_TABLE, "sra-common-prerequisites")
        else:
            dynamodb_record_id = find_result["record_id"]
        dynamodb.update_item(
            STATE_TABLE,
            "sra-common-prerequisites",
            dynamodb_record_id,
            {
                "aws_service": "dynamodb",
                "component_state": "implemented",
                "account": ssm_params.SRA_SECURITY_ACCT,
                "description": "sra state table",
                "component_region": sts.HOME_REGION,
                "component_type": "table",
                "component_name": STATE_TABLE,
                "arn": f"arn:aws:dynamodb:{sts.HOME_REGION}:{ssm_params.SRA_SECURITY_ACCT}:table/{STATE_TABLE}",
                "date_time": dynamodb.get_date_time(),
            },
        )
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
        CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
        LIVE_RUN_DATA["StateTableCreate"] = "Created state table"
    else:
        LOGGER.info(f"DRY_RUN: Create the {STATE_TABLE} state table")
        DRY_RUN_DATA["StateTableCreate"] = f"DRY_RUN: Create the {STATE_TABLE} state table"


def add_state_table_record(  # noqa: CFQ002
    aws_service: str,
    component_state: str,
    description: str,
    component_type: str,
    resource_arn: str,
    account_id: Optional[str],
    region: str,
    component_name: str,
    key_id: str = "",
) -> str:
    """Add a record to the state table.

    Args:
        aws_service (str): aws service
        component_state (str): component state
        description (str): description of the component
        component_type (str): component type
        resource_arn (str): arn of the resource
        account_id (str): account id
        region (str): region
        component_name (str): component name
        key_id (str): key id

    Returns:
        None
    """
    LOGGER.info(f"Add a record to the state table for {component_name}")
    if account_id is None:
        account_id = "Unknown"
    dynamodb.DYNAMODB_RESOURCE = sts.assume_role_resource(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "dynamodb", sts.HOME_REGION)

    item_found, find_result = dynamodb.find_item(
        STATE_TABLE,
        SOLUTION_NAME,
        {
            "arn": resource_arn,
        },
    )
    if item_found is False:
        sra_resource_record_id, iam_date_time = dynamodb.insert_item(STATE_TABLE, SOLUTION_NAME)
    else:
        sra_resource_record_id = find_result["record_id"]

    dynamodb.update_item(
        STATE_TABLE,
        SOLUTION_NAME,
        sra_resource_record_id,
        {
            "aws_service": aws_service,
            "component_state": component_state,
            "account": account_id,
            "description": description,
            "component_region": region,
            "component_type": component_type,
            "component_name": component_name,
            "key_id": key_id,
            "arn": resource_arn,
            "date_time": dynamodb.get_date_time(),
        },
    )
    return sra_resource_record_id


def remove_state_table_record(resource_arn: str) -> Any:
    """Remove a record from the state table.

    Args:
        resource_arn (str): arn of the resource

    Returns:
        Any: response from the dynamodb delete_item function
    """
    dynamodb.DYNAMODB_RESOURCE = sts.assume_role_resource(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "dynamodb", sts.HOME_REGION)
    LOGGER.info(f"Searching for {resource_arn} in {STATE_TABLE} dynamodb table...")
    try:
        item_found, find_result = dynamodb.find_item(
            STATE_TABLE,
            SOLUTION_NAME,
            {
                "arn": resource_arn,
            },
        )
        if item_found is False:
            LOGGER.info(f"Record not found in {STATE_TABLE} dynamodb table")
            response = {}
        else:
            sra_resource_record_id = find_result["record_id"]
            LOGGER.info(f"Found record id {sra_resource_record_id}")
            LOGGER.info(f"Removing {sra_resource_record_id} from {STATE_TABLE} dynamodb table...")
            response = dynamodb.delete_item(STATE_TABLE, SOLUTION_NAME, sra_resource_record_id)
    except Exception as error:
        LOGGER.error(f"Error removing {resource_arn} record from {STATE_TABLE} dynamodb table: {error}")
        response = {}
    return response


def update_state_table_record(record_id: str, update_data: dict) -> None:
    """Update a record in the state table.

    Args:
        record_id (str): record id
        update_data (dict): data to update

    Returns:
        None
    """
    LOGGER.info(f"Updating {record_id} record in {STATE_TABLE} dynamodb table...")
    dynamodb.DYNAMODB_RESOURCE = sts.assume_role_resource(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "dynamodb", sts.HOME_REGION)

    try:
        dynamodb.update_item(
            STATE_TABLE,
            SOLUTION_NAME,
            record_id,
            update_data,
        )
    except Exception as error:
        LOGGER.error(f"Error updating {record_id} record in {STATE_TABLE} dynamodb table: {error}")
    return


def check_bedrock_org_config_rules(component_name: str, account: str, region: str) -> bool:
    """Check if sra-bedrock-org solution Bedrock Guardrail config rules are deployed.

    Args:
        component_name: component name
        account: AWS account id
        region: AWS region

    Returns:
        True or False
    """
    LOGGER.info("Checking if Bedrock org config rules are enabled...")
    item_found, _ = dynamodb.find_item(
        STATE_TABLE,
        BEDROCK_ORG_SOLUTION_NAME,
        {
            "component_name": component_name,
            "account": account,
            "component_region": region,
        },
    )
    return item_found


def build_role_arns(acct: str, region: str) -> list:
    """Build list of role ARNs based on enabled sra-bedrock-org solution config rules.

    Args:
        acct: AWS account id
        region: AWS region

    Returns:
        List of role arns or empty list
    """
    role_arns = []

    config_rules = [GUARDRAIL_RULE_NAME, ENCRYPTION_RULE_NAME]

    for rule in config_rules:
        if check_bedrock_org_config_rules(rule, acct, region):
            role_arn = f"arn:{sts.PARTITION}:iam::{acct}:role/{rule}"
            role_arns.append(role_arn)

    return role_arns


def update_kms_key_policy(acct: str, region: str) -> dict:
    """Update KMS key policy.

    Args:
        acct: AWS account id
        region: AWS region

    Returns:
        dict: KMS key policy
    """
    LOGGER.info("Customizing key policy...")
    kms_key_policy = json.loads(json.dumps(KMS_KEY_POLICIES[GUARDRAILS_KEY_ALIAS]))
    LOGGER.info(f"kms_key_policy: {kms_key_policy}")
    kms_key_policy["Statement"][0]["Principal"]["AWS"] = KMS_KEY_POLICIES[GUARDRAILS_KEY_ALIAS]["Statement"][0]["Principal"][  # noqa ECE001
        "AWS"
    ].replace("ACCOUNT_ID", acct)
    principal_arns = build_role_arns(acct, region)
    if principal_arns != []:
        if len(kms_key_policy["Statement"]) < 2:
            kms_key_policy["Statement"].append({})
        kms_key_policy["Statement"][1] = {
            "Principal": {"AWS": principal_arns},
            "Sid": "Allow IAM Role Access",
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": "*",
        }

    LOGGER.info(f"Customizing key policy...done: {kms_key_policy}")
    return kms_key_policy


def create_kms_key(acct: str, region: str) -> None:
    """Create a KMS key for the solution.

    Args:
        acct: AWS account id
        region: AWS region
    """
    LOGGER.info("Creating KMS key for the solution...")
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA
    lambdas.LAMBDA_CLIENT = sts.assume_role(sts.MANAGEMENT_ACCOUNT, sts.CONFIGURATION_ROLE, "lambda", sts.HOME_REGION)

    # Deploy KMS keys
    kms.KMS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "kms", region)
    search_bedrock_guardrails_kms_key, _, bedrock_guardrails_key_id, _ = kms.check_alias_exists(kms.KMS_CLIENT, f"alias/{GUARDRAILS_KEY_ALIAS}")
    if search_bedrock_guardrails_kms_key is False:
        LOGGER.info(f"alias/{GUARDRAILS_KEY_ALIAS} not found.")
        if DRY_RUN is False:
            LOGGER.info("Creating SRA Bedrock guardrails KMS key")
            LOGGER.info("Customizing key policy...")
            kms_key_policy = update_kms_key_policy(acct, region)
            LOGGER.info("Searching for existing keys with proper policy...")
            kms_search_result, kms_found_id = kms.search_key_policies(kms.KMS_CLIENT, json.dumps(kms_key_policy))
            if kms_search_result is True:
                LOGGER.info(f"Found existing key with proper policy: {kms_found_id}")
                bedrock_guardrails_key_id = kms_found_id
            else:
                LOGGER.info("No existing key found with proper policy. Creating new key...")
                bedrock_guardrails_key_id = kms.create_kms_key(
                    kms.KMS_CLIENT, json.dumps(kms_key_policy), SOLUTION_NAME, "Key for Bedrock Guardrails Encryption"
                )
                LOGGER.info(f"Created Bedrock Guardrails KMS key: {bedrock_guardrails_key_id}")
                kms.enable_key_rotation(kms.KMS_CLIENT, bedrock_guardrails_key_id)
                LOGGER.info(f"Enabled automatic rotation of: {bedrock_guardrails_key_id}")
                LIVE_RUN_DATA[f"KMSKeyCreate-{acct}-{region}"] = "Created SRA Bedrock Guardrails KMS key"
                CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            # Add KMS resource records to sra state table
            add_state_table_record(
                "kms",
                "implemented",
                "bedrock guardrails kms key",
                "key",
                f"arn:aws:kms:{region}:{acct}:key/{bedrock_guardrails_key_id}",
                acct,
                region,
                bedrock_guardrails_key_id,
                bedrock_guardrails_key_id,
            )
            # KMS alias for Bedrock Guardrails key
            LOGGER.info("Creating SRA Bedrock Guardrails key alias")
            kms.create_alias(kms.KMS_CLIENT, f"alias/{GUARDRAILS_KEY_ALIAS}", bedrock_guardrails_key_id)
            LIVE_RUN_DATA[f"KMSAliasCreate-{acct}-{region}"] = "Created SRABedrock Guardrails KMS key alias"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            # Add KMS resource records to sra state table
            add_state_table_record(
                "kms",
                "implemented",
                "bedrock guardrails kms alias",
                "alias",
                f"arn:aws:kms:{region}:{acct}:alias/{GUARDRAILS_KEY_ALIAS}",
                acct,
                region,
                GUARDRAILS_KEY_ALIAS,
                bedrock_guardrails_key_id,
            )

        else:
            LOGGER.info("DRY_RUN: Creating SRA Bedrock Guardrails KMS key")
            DRY_RUN_DATA[f"KMSKeyCreate-{acct}-{region}"] = "DRY_RUN: Create SRA Bedrock Guardrails KMS key"
            LOGGER.info("DRY_RUN: Creating SRA Bedrock Guardrails KMS key alias")
            DRY_RUN_DATA[f"KMSAliasCreate-{acct}-{region}"] = "DRY_RUN: Create SRA Bedrock Guardrails KMS key alias"
    else:
        LOGGER.info(f"Found SRA Bedrock Guardrails KMS key: {bedrock_guardrails_key_id}")
        if DRY_RUN is False:
            # Add KMS resource records to sra state table
            add_state_table_record(
                "kms",
                "implemented",
                "bedrock guardrails kms key",
                "key",
                f"arn:aws:kms:{region}:{acct}:key/{bedrock_guardrails_key_id}",
                acct,
                region,
                bedrock_guardrails_key_id,
                bedrock_guardrails_key_id,
            )
            add_state_table_record(
                "kms",
                "implemented",
                "bedrock guardrails kms alias",
                "alias",
                f"arn:aws:kms:{region}:{acct}:alias/{GUARDRAILS_KEY_ALIAS}",
                acct,
                region,
                GUARDRAILS_KEY_ALIAS,
                bedrock_guardrails_key_id,
            )


def check_sqs_queue() -> str:
    """Add sqs queue record if DLQ exists.

    Returns:
        str: sqs topic arn
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    sqs.SQS_CLIENT = sts.assume_role(sts.MANAGEMENT_ACCOUNT, sts.CONFIGURATION_ROLE, "sqs", sts.HOME_REGION)
    queue_search = sqs.find_sqs_queue(f"{SOLUTION_NAME}-DLQ")
    if queue_search is None:
        LOGGER.info(f"{SOLUTION_NAME}-DLQ doesn't exist")

    else:
        LOGGER.info(f"{SOLUTION_NAME}-DLQ sqs queue exists.")
        queue_arn = queue_search
        if DRY_RUN is False:
            # SQS State table record:
            add_state_table_record("sqs", "implemented", "sqs queue", "queue", queue_arn, ACCOUNT, sts.HOME_REGION, f"{SOLUTION_NAME}-DLQ")
        else:
            DRY_RUN_DATA["SQSCreate"] = f"DRY_RUN: {SOLUTION_NAME}-DLQ sqs queue exists"

    return queue_arn


def create_guardrail(acct: str, region: str, params: dict) -> None:
    """Deploy the Bedrock guardrail.

    Args:
        acct: AWS account id
        region: AWS region
        params: parameters
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    if DRY_RUN is False:
        LOGGER.info("Live run: creating Bedrock guardrail...")
        bedrock.BEDROCK_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "bedrock", region)
        LOGGER.info(f"Deploying Bedrock guardrail to {acct} in {region}...")
        key_arn = f"arn:{sts.PARTITION}:kms:{region}:{acct}:alias/{GUARDRAILS_KEY_ALIAS}"
        guardrail_params = set_guardrail_config(params, key_arn)
        guardrail_arn = bedrock.create_guardrail(guardrail_params)
        LIVE_RUN_DATA[f"Bedrock-guardrail-{acct}-{region}"] = f"Created Bedrock Guardrail in {acct} in {region}"
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
        CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
        add_state_table_record(
            "bedrock", "implemented", "bedrock guardrail", "guardrail", guardrail_arn, acct, region, params["BEDROCK_GUARDRAIL_NAME"]
        )
    else:
        LOGGER.info(f"DRY_RUN: Deploying Bedrock guardrail in {acct} in {region}")
        DRY_RUN_DATA[f"Bedrock-guardrail-{acct}-{region}"] = f"DRY_RUN: Deploy Bedrock guardrail '{params['BEDROCK_GUARDRAIL_NAME']}'"


def set_guardrail_config(params: dict, guardrail_key_id: str) -> Dict:
    """Set the guardrail configuration.

    Args:
        params: parameters
        guardrail_key_id: kms key id

    Returns:
        Dict: guardrail configuration parameters
    """
    guardrail_params = {
        "name": params["BEDROCK_GUARDRAIL_NAME"],
        "description": "sra bedrock guardrail",
        "blockedInputMessaging": params["BLOCKED_INPUT_MESSAGING"],
        "blockedOutputsMessaging": params["BLOCKED_OUTPUTS_MESSAGING"],
        "kmsKeyId": guardrail_key_id,
        "tags": [
            {"key": "sra-solution", "value": params["SOLUTION_NAME"]},
        ],
    }

    if params["DEPLOY_CONTEXTUAL_GROUNDING_POLICY"] == "true":
        guardrail_grounding_policy = json.loads(params["GUARDRAIL_GROUNDING_POLICY_CONFIG"].replace("'", '"'))
        contextual_grounding_policy = {"filtersConfig": guardrail_grounding_policy}
        guardrail_params["contextualGroundingPolicyConfig"] = contextual_grounding_policy
    if params["DEPLOY_SENSITIVE_INFORMATION_POLICY"] == "true":
        guardrail_pii = json.loads(params["GUARDRAIL_PII_ENTITY"].replace("'", '"'))
        sensitive_information_policy = {"piiEntitiesConfig": guardrail_pii}
        guardrail_params["sensitiveInformationPolicyConfig"] = sensitive_information_policy
    if params["DEPLOY_GUARDRAIL_CONTENT_POLICY"] == "true":
        guardrail_content_policy = json.loads(params["GUARDRAIL_CONTENT_POLICY_CONFIG"].replace("'", '"'))
        content_policy_config = {"filtersConfig": guardrail_content_policy}
        guardrail_params["contentPolicyConfig"] = content_policy_config
    if params["DEPLOY_WORD_POLICY"] == "true":
        guardrail_word_config = json.loads(params["GUARDRAIL_WORD_CONFIG"].replace("'", '"'))
        if "wordPolicyConfig" not in guardrail_params:
            guardrail_params["wordPolicyConfig"] = {}
        guardrail_params["wordPolicyConfig"] = {"wordsConfig": guardrail_word_config}
    if params["DEPLOY_MANAGED_WORD_LISTS_CONFIG"] == "true":
        managed_word_list = [
            {"type": "PROFANITY"},
        ]
        if "wordPolicyConfig" not in guardrail_params:
            guardrail_params["wordPolicyConfig"] = {}
        guardrail_params["wordPolicyConfig"].update({"managedWordListsConfig": managed_word_list})
    if params["DEPLOY_GUARDRAIL_TOPIC_POLICY"] == "true":
        guardrail_topic_policy = json.loads(params["GUARDRAIL_TOPIC_POLICY_CONFIG"].replace("'", '"'))
        guardrail_params["topicPolicyConfig"] = {"topicsConfig": guardrail_topic_policy}
    return guardrail_params


def delete_bedrock_guardrails_key(acct: str, region: str) -> None:
    """Delete KMS key.

    Args:
        acct (str): AWS account ID
        region (str): AWS region name
    """
    # Delete KMS key (schedule deletion) and delete kms alias
    kms.KMS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "kms", region)
    search_bedrock_guardrails_kms_key, bedrock_guardrails_key_alias, bedrock_guardrails_key_id, bedrock_guardrails_key_arn = kms.check_alias_exists(
        kms.KMS_CLIENT, f"alias/{GUARDRAILS_KEY_ALIAS}"
    )
    if search_bedrock_guardrails_kms_key is True:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {GUARDRAILS_KEY_ALIAS} KMS key")
            kms.delete_alias(kms.KMS_CLIENT, f"alias/{GUARDRAILS_KEY_ALIAS}")
            LIVE_RUN_DATA[f"KMSDeleteAlias-{acct}-{region}"] = f"Deleted {GUARDRAILS_KEY_ALIAS} KMS key alias"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info(f"Deleting {GUARDRAILS_KEY_ALIAS} KMS key ({bedrock_guardrails_key_id})")
            remove_state_table_record(bedrock_guardrails_key_arn)

            kms.schedule_key_deletion(kms.KMS_CLIENT, bedrock_guardrails_key_id)
            LIVE_RUN_DATA[f"KMSDelete-{acct}-{region}"] = f"Deleted {GUARDRAILS_KEY_ALIAS} KMS key ({bedrock_guardrails_key_id})"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info(f"Scheduled deletion of {GUARDRAILS_KEY_ALIAS} KMS key ({bedrock_guardrails_key_id})")
            kms_key_arn = f"arn:{sts.PARTITION}:kms:{region}:{acct}:key/{bedrock_guardrails_key_id}"
            remove_state_table_record(kms_key_arn)

        else:
            LOGGER.info(f"DRY_RUN: Deleting {GUARDRAILS_KEY_ALIAS} KMS key")
            DRY_RUN_DATA[f"KMSAliasDelete-{acct}-{region}"] = f"DRY_RUN: Delete {GUARDRAILS_KEY_ALIAS} KMS key"
            LOGGER.info(f"DRY_RUN: Deleting {GUARDRAILS_KEY_ALIAS} KMS key ({bedrock_guardrails_key_id})")
            DRY_RUN_DATA[f"KMSDelete-{acct}-{region}"] = f"DRY_RUN: Delete {GUARDRAILS_KEY_ALIAS} KMS key ({bedrock_guardrails_key_id})"
    else:
        LOGGER.info(f"{GUARDRAILS_KEY_ALIAS} KMS key does not exist.")


def delete_guardrails(account: str, region: str, guardrail_name: str) -> None:
    """Delete the Bedrock guardrails.

    Args:
        account: AWS account id
        region: AWS region
        guardrail_name: Name of the Bedrock guardrail to delete.
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    if DRY_RUN is False:
        bedrock.BEDROCK_CLIENT = sts.assume_role(account, sts.CONFIGURATION_ROLE, "bedrock", region)
        LOGGER.info(f"Deleting Bedrock guardrail in {account} in {region}...")
        guardrail_id = bedrock.get_guardrail_id(guardrail_name)
        if guardrail_id != "":
            bedrock.delete_guardrail(guardrail_id)
            LIVE_RUN_DATA[f"Bedrock-guardrail-{account}_{region}"] = f"Deleted Bedrock Guardrail ({guardrail_name}) in {account} in {region}"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            guardrail_arn = f"arn:aws:bedrock:{region}:{account}:guardrail/{guardrail_id}"
            remove_state_table_record(guardrail_arn)
        else:
            LOGGER.info(f"Guardrail {guardrail_name} does not exist in {account} in {region}")
    else:
        LOGGER.info(f"DRY_RUN: Delete Bedrock guardrail {guardrail_name} in {account} in {region}")
        DRY_RUN_DATA[f"Bedrock-guardrail-{account}_{region}"] = f"DRY_RUN: Delete Bedrock guardrail {guardrail_name}"


def create_event(event: dict, context: Any) -> str:  # noqa: U100
    """Create event.

    Args:
        event (dict): Lambda event data.
        context (Any): Lambda context data.

    Returns:
        str: CloudFormation response URL.
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA
    global LAMBDA_RECORD_ID
    global SRA_ALARM_TOPIC_ARN
    DRY_RUN_DATA = {}
    LIVE_RUN_DATA = {}

    LOGGER.info(f"CFN_RESPONSE_DATA START: {CFN_RESPONSE_DATA}")
    # Deploy state table
    deploy_state_table()
    LOGGER.info(f"CFN_RESPONSE_DATA POST deploy_state_table: {CFN_RESPONSE_DATA}")
    # add IAM state table record for the lambda execution role
    execution_role_arn = lambdas.get_lambda_execution_role(os.environ["AWS_LAMBDA_FUNCTION_NAME"])
    execution_role_name = execution_role_arn.split("/")[-1]
    LOGGER.info(f"Adding state table record for lambda IAM execution role: {execution_role_arn}")
    if DRY_RUN is False:
        # add lambda execution role state table record
        LOGGER.info(f"Adding state table record for lambda execution role: {execution_role_name}")
        add_state_table_record(
            "iam", "implemented", "lambda execution role", "role", execution_role_arn, sts.MANAGEMENT_ACCOUNT, sts.HOME_REGION, execution_role_name
        )
        # add lambda function state table record
        LOGGER.info(f"Adding state table record for lambda function: {context.invoked_function_arn}")
        LAMBDA_RECORD_ID = add_state_table_record(
            "lambda",
            "implemented",
            "lambda for bedrock guardrails",
            "lambda",
            context.invoked_function_arn,
            sts.MANAGEMENT_ACCOUNT,
            sts.HOME_REGION,
            context.function_name,
        )

    # Deploy kms cmk
    accounts, regions = get_accounts_and_regions(
        event["ResourceProperties"]["SRA_BEDROCK_ACCOUNTS"], event["ResourceProperties"]["SRA_BEDROCK_REGIONS"]
    )
    for acct in accounts:
        for region in regions:
            # if DRY_RUN is False:
            LOGGER.info(f"Live run: check if Bedrock guardrail exists in {acct} in {region}...")
            bedrock.BEDROCK_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "bedrock", region)
            guardrail_id = bedrock.get_guardrail_id(event["ResourceProperties"]["BEDROCK_GUARDRAIL_NAME"])
            if guardrail_id != "":
                LOGGER.info(f"Guardrail {event['ResourceProperties']['BEDROCK_GUARDRAIL_NAME']} exists in {acct} in {region}")
            else:
                LOGGER.info(f"Guardrail {event['ResourceProperties']['BEDROCK_GUARDRAIL_NAME']} does not exist in {acct} in {region}")
                create_kms_key(acct, region)
                create_guardrail(acct, region, event["ResourceProperties"])
    check_sqs_queue()
    # End
    if DRY_RUN is False:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": LIVE_RUN_DATA}))
    else:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": DRY_RUN_DATA}))
        create_json_file("dry_run_data.json", DRY_RUN_DATA)
        LOGGER.info("Dry run data saved to file")
        s3.upload_file_to_s3(
            "/tmp/dry_run_data.json", s3.STAGING_BUCKET, f"dry_run_data_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json"  # noqa: S108
        )
        LOGGER.info(f"Dry run data file uploaded to s3://{s3.STAGING_BUCKET}/dry_run_data_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json")

    if RESOURCE_TYPE == CFN_CUSTOM_RESOURCE:
        LOGGER.info("Resource type is a custom resource")
        cfnresponse.send(event, context, cfnresponse.SUCCESS, CFN_RESPONSE_DATA, CFN_RESOURCE_ID)
    else:
        LOGGER.info("Resource type is not a custom resource")
    return CFN_RESOURCE_ID


def update_event(event: dict, context: Any) -> str:  # noqa: U100
    """Update event.

    Args:
        event (dict): Lambda event data.
        context (Any): Lambda context data.

    Returns:
        str: CloudFormation response URL.
    """
    global CFN_RESPONSE_DATA
    CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
    global DRY_RUN_DATA
    LOGGER.info("update event function")
    create_event(event, context)

    return CFN_RESOURCE_ID


def delete_event(event: dict, context: Any) -> None:  # noqa: CFQ001, CCR001, C901
    """Delete event function.

    Args:
        event (dict): Lambda event object
        context (Any): Lambda context object
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA
    DRY_RUN_DATA = {}
    LIVE_RUN_DATA = {}
    LOGGER.info("Delete event function")

    # Delete Bedrock guardrails
    accounts, regions = get_accounts_and_regions(
        event["ResourceProperties"]["SRA_BEDROCK_ACCOUNTS"], event["ResourceProperties"]["SRA_BEDROCK_REGIONS"]
    )
    for acct in accounts:
        for region in regions:
            delete_guardrails(acct, region, event["ResourceProperties"]["BEDROCK_GUARDRAIL_NAME"])
            delete_bedrock_guardrails_key(acct, region)
    # Remove sqs queue record
    queue_arn = check_sqs_queue()
    if queue_arn is not None:
        remove_state_table_record(queue_arn)
    # Must infer the execution role arn because the function is being reported as non-existent at this point
    execution_role_arn = f"arn:aws:iam::{sts.MANAGEMENT_ACCOUNT}:role/{SOLUTION_NAME}-lambda"
    LOGGER.info(f"Removing state table record for lambda IAM execution role: {execution_role_arn}")
    remove_state_table_record(execution_role_arn)
    LOGGER.info(f"Removing state table record for lambda function: {context.invoked_function_arn}")
    remove_state_table_record(context.invoked_function_arn)

    if DRY_RUN is False:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": LIVE_RUN_DATA}))
    else:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": DRY_RUN_DATA}))

    if RESOURCE_TYPE != "Other":
        cfnresponse.send(event, context, cfnresponse.SUCCESS, CFN_RESPONSE_DATA, CFN_RESOURCE_ID)


def create_json_file(file_name: str, data: dict) -> None:
    """Create JSON file.

    Args:
        file_name: name of file to be created
        data: data to be written to file
    """
    with open(f"/tmp/{file_name}", "w", encoding="utf-8") as f:  # noqa: S108, PL123
        json.dump(data, f, ensure_ascii=False, indent=4)


def lambda_handler(event: dict, context: Any) -> dict:  # noqa: CCR001
    """Lambda handler.

    Args:
        event: Lambda event
        context: Lambda context

    Returns:
        Lambda response

    Raises:
        ValueError: If the event does not include Records or RequestType
    """
    LOGGER.info("Starting Lambda function...")
    global RESOURCE_TYPE
    global LAMBDA_START
    global LAMBDA_FINISH
    global LAMBDA_RECORD_ID
    global DRY_RUN

    LAMBDA_START = dynamodb.get_date_time()
    LOGGER.info(event)
    LOGGER.info({"boto3 version": boto3.__version__})
    try:
        if "ResourceType" in event:
            RESOURCE_TYPE = event["ResourceType"]
            LOGGER.info(f"ResourceType: {RESOURCE_TYPE}")
        else:
            LOGGER.info("ResourceType not found in event.")
            RESOURCE_TYPE = "Other"
        if "Records" not in event and "RequestType" not in event:
            raise ValueError(
                f"The event did not include Records or RequestType. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
        elif "RequestType" in event:
            get_resource_parameters(event)
            if event["RequestType"] == "Create":
                LOGGER.info("CREATE EVENT!!")
                create_event(event, context)
            elif event["RequestType"] == "Update":
                LOGGER.info("UPDATE EVENT!!")
                update_event(event, context)
            if event["RequestType"] == "Delete":
                LOGGER.info("DELETE EVENT!!")
                # Set DRY_RUN to False if we are deleting via CloudFormation (should do this with Terraform as well); stack will be gone.
                if RESOURCE_TYPE != "Other":
                    DRY_RUN = False
                delete_event(event, context)

    except Exception:
        LOGGER.exception("Unexpected!")
        reason = f"See the details in CloudWatch Log Stream: '{context.log_group_name}'"
        if RESOURCE_TYPE != "Other":
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, CFN_RESOURCE_ID, reason=reason)
        LAMBDA_FINISH = dynamodb.get_date_time()
        return {
            "statusCode": 500,
            "lambda_start": LAMBDA_START,
            "lambda_finish": LAMBDA_FINISH,
            "body": "ERROR",
            "dry_run": DRY_RUN,
            "dry_run_data": DRY_RUN_DATA,
        }
    LAMBDA_FINISH = dynamodb.get_date_time()

    lambda_data = {
        "start_time": LAMBDA_START,
        "end_time": LAMBDA_FINISH,
        "lambda_result": "SUCCESS",
    }
    if DRY_RUN is False:
        item_found, find_result = dynamodb.find_item(
            STATE_TABLE,
            SOLUTION_NAME,
            {
                "arn": context.invoked_function_arn,
            },
        )

        if item_found is True:
            sra_resource_record_id = find_result["record_id"]
            update_state_table_record(sra_resource_record_id, lambda_data)
        else:
            LOGGER.info(f"Lambda record not found in {STATE_TABLE} table so unable to update it.")

    return {
        "statusCode": 200,
        "lambda_start": LAMBDA_START,
        "lambda_finish": LAMBDA_FINISH,
        "body": "SUCCESS",
        "dry_run": DRY_RUN,
        "dry_run_data": DRY_RUN_DATA,
    }
