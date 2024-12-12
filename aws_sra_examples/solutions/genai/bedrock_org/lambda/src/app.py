"""This script performs operations to enable, configure, and disable Bedrock security controls.

Version: 1.0

Main app module for SRA GenAI Bedrock org security controls solution in the repo,
https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
from datetime import datetime
import json
import os
import logging
from pathlib import Path
import re
import boto3
import cfnresponse

import sra_s3
import sra_repo
import sra_ssm_params
import sra_iam
import sra_dynamodb
import sra_sts
import sra_lambda
import sra_sns
import sra_config
import sra_cloudwatch
import sra_kms

from typing import Dict, Any, List, Literal, Optional

# TODO(liamschn): deploy example bedrock guardrail
# TODO(liamschn): deploy example iam role(s) and policy(ies) - lower priority/not necessary?
# TODO(liamschn): deploy example bucket policy(ies) - lower priority/not necessary?
# TODO(liamschn): deal with linting failures in pipeline (and deal with typechecking/mypy)
# TODO(liamschn): check for unused parameters (in progress)
# TODO(liamschn): make sure things don't fail (create or delete) if the dynamodb table is deleted/doesn't exist (use case, maybe someone deletes it)

LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "INFO")
LOGGER.setLevel(log_level)


# TODO(liamschn): change this so that it downloads the sra_config_lambda_iam_permissions.json from the repo
# then loads into the IAM_POLICY_DOCUMENTS variable (make this step 2 in the create function below)
def load_iam_policy_documents() -> Dict[str, Any]:
    """Load IAM Policy Documents from JSON file.

    Returns:
        dict: IAM Policy Documents
    """
    LOGGER.info("...load_iam_policy_documents")
    json_file_path = Path(__file__).parent / "sra_config_lambda_iam_permissions.json"
    with json_file_path.open("r") as file:
        return json.load(file)


def load_cloudwatch_metric_filters() -> Dict[str, Any]:
    """Load CloudWatch Metric Filters from JSON file.

    Returns:
        dict: CloudWatch Metric Filters
    """
    LOGGER.info("...load_cloudwatch_metric_filters")
    json_file_path = Path(__file__).parent / "sra_cloudwatch_metric_filters.json"
    with json_file_path.open("r") as file:
        return json.load(file)


def load_kms_key_policies() -> dict:
    """Load KMS Key Policies from JSON file.

    Returns:
        dict: KMS Key Policies
    """
    LOGGER.info("...load_kms_key_policies")
    json_file_path = Path(__file__).parent / "sra_kms_keys.json"
    with json_file_path.open("r") as file:
        return json.load(file)


def load_cloudwatch_oam_sink_policy() -> dict:
    """Load CloudWatch OAM Sink Policy from JSON file.

    Returns:
        dict: CloudWatch OAM Sink Policy
    """
    LOGGER.info("...load_cloudwatch_oam_sink_policy")
    json_file_path = Path(__file__).parent / "sra_cloudwatch_oam_sink_policy.json"
    with json_file_path.open("r") as file:
        return json.load(file)


def load_sra_cloudwatch_oam_trust_policy() -> dict:
    """Load CloudWatch OAM Sink Policy from JSON file.

    Returns:
        dict: CloudWatch OAM Sink Policy
    """
    LOGGER.info("...load_sra_cloudwatch_oam_trust_policy")
    json_file_path = Path(__file__).parent / "sra_cloudwatch_oam_trust_policy.json"
    with json_file_path.open("r") as file:
        return json.load(file)


def load_sra_cloudwatch_dashboard() -> dict:
    """Load CloudWatch Dashboard from JSON file.

    Returns:
        dict: CloudWatch Dashboard
    """
    LOGGER.info("...load_sra_cloudwatch_dashboard")
    json_file_path = Path(__file__).parent / "sra_cloudwatch_dashboard.json"
    with json_file_path.open("r") as file:
        return json.load(file)


# Global vars
RESOURCE_TYPE: str = ""
SOLUTION_NAME: str = "sra-bedrock-org"
GOVERNED_REGIONS = []
ORGANIZATION_ID = ""
SRA_ALARM_EMAIL: str = ""
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
CFN_RESOURCE_ID: str = "sra-bedrock-org-function"
ALARM_SNS_KEY_ALIAS = "sra-alarm-sns-key"

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
IAM_POLICY_DOCUMENTS: Dict[str, Any] = load_iam_policy_documents()
CLOUDWATCH_METRIC_FILTERS: dict = load_cloudwatch_metric_filters()
KMS_KEY_POLICIES: dict = load_kms_key_policies()
CLOUDWATCH_OAM_SINK_POLICY: dict = load_cloudwatch_oam_sink_policy()
CLOUDWATCH_OAM_TRUST_POLICY: dict = load_sra_cloudwatch_oam_trust_policy()
CLOUDWATCH_DASHBOARD: dict = load_sra_cloudwatch_dashboard()

# Parameter validation rules
PARAMETER_VALIDATION_RULES: dict = {
    "SRA_REPO_ZIP_URL": r'^https://.*\.zip$',
    "DRY_RUN": r'^true|false$',
    "EXECUTION_ROLE_NAME": r'^sra-execution$',
    "LOG_GROUP_DEPLOY": r'^true|false$',
    "LOG_GROUP_RETENTION": r'^(1|3|5|7|14|30|60|90|120|150|180|365|400|545|731|1096|1827|2192|2557|2922|3288|3653)$',
    "LOG_LEVEL": r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$',
    "SOLUTION_NAME": r'^sra-bedrock-org$',
    "SOLUTION_VERSION": r'^[0-9]+\.[0-9]+\.[0-9]+$',
    "SRA_ALARM_EMAIL": r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    "SRA-BEDROCK-ACCOUNTS": r'^\[((?:"[0-9]+"(?:\s*,\s*)?)*)\]$',
    "SRA-BEDROCK-REGIONS": r'^\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\]$',
    "SRA-BEDROCK-CHECK-EVAL-JOB-BUCKET": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*(\{\s*(?:"BucketName"\s*:\s*"([a-zA-Z0-9-]*)"\s*)?})\}$',
    "SRA-BEDROCK-CHECK-IAM-USER-ACCESS": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*(\{\s*(?:"BucketName"\s*:\s*"([a-zA-Z0-9-]*)"\s*)?})\}$',
    "SRA-BEDROCK-CHECK-GUARDRAILS": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*\{(\s*"content_filters"\s*:\s*"(true|false)")?(\s*,\s*"denied_topics"\s*:\s*"(true|false)")?(\s*,\s*"word_filters"\s*:\s*"(true|false)")?(\s*,\s*"sensitive_info_filters"\s*:\s*"(true|false)")?(\s*,\s*"contextual_grounding"\s*:\s*"(true|false)")?\s*\}\}$',
    "SRA-BEDROCK-CHECK-VPC-ENDPOINTS": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*\{(\s*"check_bedrock"\s*:\s*"(true|false)")?(\s*,\s*"check_bedrock_agent"\s*:\s*"(true|false)")?(\s*,\s*"check_bedrock_agent_runtime"\s*:\s*"(true|false)")?(\s*,\s*"check_bedrock_runtime"\s*:\s*"(true|false)")?\s*\}\}$',
    "SRA-BEDROCK-CHECK-INVOCATION-LOG-CLOUDWATCH": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*\{(\s*"check_retention"\s*:\s*"(true|false)")?(\s*,\s*"check_encryption"\s*:\s*"(true|false)")?\}\}$',
    "SRA-BEDROCK-CHECK-INVOCATION-LOG-S3": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*\{(\s*"check_retention"\s*:\s*"(true|false)")?(\s*,\s*"check_encryption"\s*:\s*"(true|false)")?(\s*,\s*"check_access_logging"\s*:\s*"(true|false)")?(\s*,\s*"check_object_locking"\s*:\s*"(true|false)")?(\s*,\s*"check_versioning"\s*:\s*"(true|false)")?\s*\}\}$',
    "SRA-BEDROCK-CHECK-CLOUDWATCH-ENDPOINTS": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*(\{\})\}$',
    "SRA-BEDROCK-CHECK-S3-ENDPOINTS": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*(\{\})\}$',
    "SRA-BEDROCK-CHECK-GUARDRAIL-ENCRYPTION": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"input_params"\s*:\s*(\{\})\}$',
    "SRA-BEDROCK-FILTER-SERVICE-CHANGES": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"filter_params"\s*:\s*\{"log_group_name"\s*:\s*"[^"\s]+"\}\}$',
    "SRA-BEDROCK-FILTER-BUCKET-CHANGES": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"filter_params"\s*:\s*\{"log_group_name"\s*:\s*"[^"\s]+",\s*"bucket_names"\s*:\s*\[((?:"[^"\s]+"(?:\s*,\s*)?)+)\]\}\}$',
    "SRA-BEDROCK-FILTER-PROMPT-INJECTION": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"filter_params"\s*:\s*\{"log_group_name"\s*:\s*"[^"\s]+",\s*"input_path"\s*:\s*"[^"\s]+"\}\}$',
    "SRA-BEDROCK-FILTER-SENSITIVE-INFO": r'^\{"deploy"\s*:\s*"(true|false)",\s*"accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\],\s*"filter_params"\s*:\s*\{"log_group_name"\s*:\s*"[^"\s]+",\s*"input_path"\s*:\s*"[^"\s]+"\}\}$',
    "SRA-BEDROCK-CENTRAL-OBSERVABILITY": r'^\{"deploy"\s*:\s*"(true|false)",\s*"bedrock_accounts"\s*:\s*\[((?:"[0-9]+"(?:\s*,\s*)?)*)\],\s*"regions"\s*:\s*\[((?:"[a-z0-9-]+"(?:\s*,\s*)?)*)\]\}$',
}

# Instantiate sra class objects
# TODO(liamschn): can these files exist in some central location to be shared with other solutions?
ssm_params = sra_ssm_params.sra_ssm_params()
iam = sra_iam.SRAIAM()
dynamodb = sra_dynamodb.SRADynamoDB()
sts = sra_sts.sra_sts()
repo = sra_repo.SRARepo()
s3 = sra_s3.SRAS3()
lambdas = sra_lambda.SRALambda()
sns = sra_sns.sra_sns()
config = sra_config.SRAConfig()
cloudwatch = sra_cloudwatch.SRACloudWatch()
kms = sra_kms.SRAKMS()

# propagate solution name to class objects
cloudwatch.SOLUTION_NAME = SOLUTION_NAME


def get_resource_parameters(event: dict) -> None:
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
    global SRA_ALARM_EMAIL
    global ORGANIZATION_ID

    param_validation: dict = validate_parameters(event["ResourceProperties"], PARAMETER_VALIDATION_RULES)
    if param_validation["success"] is False:
        LOGGER.info(f"Parameter validation failed: {param_validation['errors']}")
        raise ValueError(f"Parameter validation failed: {param_validation['errors']}") from None
    else:
        LOGGER.info("Parameter validation succeeded")

    LOGGER.info("Getting resource params...")
    repo.REPO_ZIP_URL = event["ResourceProperties"]["SRA_REPO_ZIP_URL"]
    repo.REPO_BRANCH = repo.REPO_ZIP_URL.split(".")[1].split("/")[len(repo.REPO_ZIP_URL.split(".")[1].split("/")) - 1]  # noqa: ECE001
    repo.SOLUTIONS_DIR = f"/tmp/aws-security-reference-architecture-examples-{repo.REPO_BRANCH}/aws_sra_examples/solutions"  # noqa: S108

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

    if event["ResourceProperties"]["SRA_ALARM_EMAIL"] != "":
        SRA_ALARM_EMAIL = event["ResourceProperties"]["SRA_ALARM_EMAIL"]

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


def get_accounts_and_regions(resource_properties: dict) -> tuple[list, list]:
    """Get accounts and regions from event and return them in a tuple.

    Args:
        resource_properties (dict): lambda event resource properties

    Returns:
        tuple: (accounts, rule_regions)
            accounts (list): list of accounts to deploy the rule to
            regions (list): list of regions to deploy the rule to
    """
    accounts = []
    regions = []
    if "SRA-BEDROCK-ACCOUNTS" in resource_properties:
        LOGGER.info("SRA-BEDROCK-ACCOUNTS found in event ResourceProperties")
        accounts = json.loads(resource_properties["SRA-BEDROCK-ACCOUNTS"])
        LOGGER.info(f"SRA-BEDROCK-ACCOUNTS: {accounts}")
    else:
        LOGGER.info("SRA-BEDROCK-ACCOUNTS not found in event ResourceProperties; setting to None and deploy to False")
        accounts = []
    if "SRA-BEDROCK-REGIONS" in resource_properties:
        LOGGER.info("SRA-BEDROCK-REGIONS found in event ResourceProperties")
        regions = json.loads(resource_properties["SRA-BEDROCK-REGIONS"])
        LOGGER.info(f"SRA-BEDROCK-REGIONS: {regions}")
    else:
        LOGGER.info("SRA-BEDROCK-REGIONS not found in event ResourceProperties; setting to None and deploy to False")
        regions = []
    return accounts, regions


def get_rule_params(rule_name: str, resource_properties: dict) -> tuple[bool, list, list, dict]:  # noqa: CCR001
    """Get rule parameters from event and return them in a tuple.

    Args:
        rule_name (str): name of config rule
        resource_properties (dict): lambda event resource properties

    Returns:
        tuple: (rule_deploy, rule_accounts, rule_regions, rule_params)
            rule_deploy (bool): whether to deploy the rule
            rule_accounts (list): list of accounts to deploy the rule to
            rule_regions (list): list of regions to deploy the rule to
            rule_input_params (dict): dictionary of rule input parameters
    """
    if rule_name.upper() in resource_properties:
        LOGGER.info(f"{rule_name} parameter found in event ResourceProperties")
        rule_params = json.loads(resource_properties[rule_name.upper()])
        LOGGER.info(f"{rule_name.upper()} parameters: {rule_params}")
        if "deploy" in rule_params:
            LOGGER.info(f"{rule_name.upper()} 'deploy' parameter found in event ResourceProperties")
            if rule_params["deploy"] == "true":
                LOGGER.info(f"{rule_name.upper()} 'deploy' parameter set to 'true'")
                rule_deploy = True
            else:
                LOGGER.info(f"{rule_name.upper()} 'deploy' parameter set to 'false'")
                rule_deploy = False
        else:
            LOGGER.info(f"{rule_name.upper()} 'deploy' parameter not found in event ResourceProperties; setting to False")
            rule_deploy = False
        if "accounts" in rule_params:
            LOGGER.info(f"{rule_name.upper()} 'accounts' parameter found in event ResourceProperties")
            rule_accounts = rule_params["accounts"]
            LOGGER.info(f"{rule_name.upper()} accounts: {rule_accounts}")
        else:
            LOGGER.info(f"{rule_name.upper()} 'accounts' parameter not found in event ResourceProperties; setting to None and deploy to False")
            rule_accounts = []
            rule_deploy = False
        if "regions" in rule_params:
            LOGGER.info(f"{rule_name.upper()} 'regions' parameter found in event ResourceProperties")
            rule_regions = rule_params["regions"]
            LOGGER.info(f"{rule_name.upper()} regions: {rule_regions}")
        else:
            LOGGER.info(f"{rule_name.upper()} 'regions' parameter not found in event ResourceProperties; setting to None and deploy to False")
            rule_regions = []
            rule_deploy = False
        if "input_params" in rule_params:
            LOGGER.info(f"{rule_name.upper()} 'input_params' parameter found in event ResourceProperties")
            rule_input_params = rule_params["input_params"]
            LOGGER.info(f"{rule_name.upper()} input_params: {rule_input_params}")
        else:
            LOGGER.info(f"{rule_name.upper()} 'input_params' parameter not found in event ResourceProperties; setting to None")
            rule_input_params = {}
        return rule_deploy, rule_accounts, rule_regions, rule_input_params
    LOGGER.info(f"{rule_name.upper()} config rule parameter not found in event ResourceProperties; skipping...")
    return False, [], [], {}


def get_filter_params(filter_name: str, resource_properties: dict) -> tuple[bool, list, list, dict]:  # noqa: CCR001
    """Get filter parameters from event resource_properties and return them in a tuple.

    Args:
        filter_name (str): name of cloudwatch filter
        resource_properties (dict): lambda event ResourceProperties

    Returns:
        tuple: (filter_deploy, filter_pattern)
            filter_deploy (bool): whether to deploy the filter
            filter_accounts (list): list of accounts to deploy the filter to
            filter_regions (list): list of regions to deploy the filter to
            filter_params (dict): dictionary of filter parameters
    """
    if filter_name.upper() in resource_properties:
        LOGGER.info(f"{filter_name} parameter found in event ResourceProperties")
        metric_filter_params = json.loads(resource_properties[filter_name.upper()])
        LOGGER.info(f"{filter_name.upper()} metric filter parameters: {metric_filter_params}")
        if "deploy" in metric_filter_params:
            LOGGER.info(f"{filter_name.upper()} 'deploy' parameter found in event ResourceProperties")
            if metric_filter_params["deploy"] == "true":
                LOGGER.info(f"{filter_name.upper()} 'deploy' parameter set to 'true'")
                filter_deploy = True
            else:
                LOGGER.info(f"{filter_name.upper()} 'deploy' parameter set to 'false'")
                filter_deploy = False
        else:
            LOGGER.info(f"{filter_name.upper()} 'deploy' parameter not found in event ResourceProperties; setting to False")
            filter_deploy = False
        if "accounts" in metric_filter_params:
            LOGGER.info(f"{filter_name.upper()} 'accounts' parameter found in event ResourceProperties")
            filter_accounts = metric_filter_params["accounts"]
            LOGGER.info(f"{filter_name.upper()} accounts: {filter_accounts}")
        else:
            LOGGER.info(f"{filter_name.upper()} 'accounts' parameter not found in event ResourceProperties")
            filter_accounts = []
        if "regions" in metric_filter_params:
            LOGGER.info(f"{filter_name.upper()} 'regions' parameter found in event ResourceProperties")
            filter_regions = metric_filter_params["regions"]
            LOGGER.info(f"{filter_name.upper()} regions: {filter_regions}")
        else:
            LOGGER.info(f"{filter_name.upper()} 'regions' parameter not found in event ResourceProperties")
            filter_regions = []
        if "filter_params" in metric_filter_params:
            LOGGER.info(f"{filter_name.upper()} 'filter_params' parameter found in event ResourceProperties")
            filter_params = metric_filter_params["filter_params"]
            LOGGER.info(f"{filter_name.upper()} filter_params: {filter_params}")
        else:
            LOGGER.info(f"{filter_name.upper()} 'filter_params' parameter not found in event ResourceProperties")
            filter_params = {}
    else:
        LOGGER.info(f"{filter_name.upper()} filter parameter not found in event ResourceProperties; skipping...")
        return False, [], [], {}
    return filter_deploy, filter_accounts, filter_regions, filter_params


def build_s3_metric_filter_pattern(bucket_names: list, filter_pattern_template: str) -> str:
    """Build the S3 filter pattern.

    Args:
        bucket_names (list): list of bucket names to build the filter pattern for
        filter_pattern_template (str): filter pattern template

    Returns:
        str: filter pattern
    """
    LOGGER.info("Building S3 filter pattern...")
    # Get the S3 filter
    s3_filter = filter_pattern_template

    # If multiple bucket names are provided, create an OR condition
    if len(bucket_names) > 1:
        bucket_condition = " || ".join([f'$.requestParameters.bucketName = "{bucket}"' for bucket in bucket_names])
        s3_filter = s3_filter.replace('($.requestParameters.bucketName = "<BUCKET_NAME_PLACEHOLDER>")', f"({bucket_condition})")
    elif len(bucket_names) == 1:
        s3_filter = s3_filter.replace("<BUCKET_NAME_PLACEHOLDER>", bucket_names[0])
    else:
        # If no bucket names are provided, remove the bucket condition entirely
        return s3_filter.replace('&& ($.requestParameters.bucketName = "<BUCKET_NAME_PLACEHOLDER>")', "")
    return s3_filter


def build_cloudwatch_dashboard(dashboard_template: dict, solution: str, bedrock_accounts: list, regions: list) -> dict:
    """Build the CloudWatch dashboard template.

    Args:
        dashboard_template (dict): CloudWatch dashboard template
        solution (str): name of solution
        bedrock_accounts (list): list of accounts to build the dashboard for
        regions (list): list of regions to build the dashboard for

    Returns:
        dict: CloudWatch dashboard template
    """
    LOGGER.info("Building CloudWatch dashboard template...")
    i = 0
    for bedrock_account in bedrock_accounts:
        for region in regions:
            if i == 0:
                injection_template = copy.deepcopy(dashboard_template[solution]["widgets"][0]["properties"]["metrics"][2])  # noqa: ECE001
                sensitive_info_template = copy.deepcopy(dashboard_template[solution]["widgets"][0]["properties"]["metrics"][3])  # noqa: ECE001
            else:
                dashboard_template[solution]["widgets"][0]["properties"]["metrics"].append(copy.deepcopy(injection_template))
                dashboard_template[solution]["widgets"][0]["properties"]["metrics"].append(copy.deepcopy(sensitive_info_template))
            dashboard_template[solution]["widgets"][0]["properties"]["metrics"][2 + i][2]["accountId"] = bedrock_account  # noqa: ECE001
            dashboard_template[solution]["widgets"][0]["properties"]["metrics"][2 + i][2]["region"] = region  # noqa: ECE001
            dashboard_template[solution]["widgets"][0]["properties"]["metrics"][3 + i][2]["accountId"] = bedrock_account  # noqa: ECE001
            dashboard_template[solution]["widgets"][0]["properties"]["metrics"][3 + i][2]["region"] = region  # noqa: ECE001
            i += 2
    dashboard_template[solution]["widgets"][0]["properties"]["metrics"][0][2]["accountId"] = sts.MANAGEMENT_ACCOUNT  # noqa: ECE001
    dashboard_template[solution]["widgets"][0]["properties"]["metrics"][0][2]["region"] = sts.HOME_REGION  # noqa: ECE001
    dashboard_template[solution]["widgets"][0]["properties"]["metrics"][1][2]["accountId"] = sts.MANAGEMENT_ACCOUNT  # noqa: ECE001
    dashboard_template[solution]["widgets"][0]["properties"]["metrics"][1][2]["region"] = sts.HOME_REGION  # noqa: ECE001
    dashboard_template[solution]["widgets"][0]["properties"]["region"] = sts.HOME_REGION
    return dashboard_template[solution]


def deploy_state_table() -> None:
    """Deploy the state table to DynamoDB."""
    LOGGER.info("Deploying the state table to DynamoDB...")
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    if DRY_RUN is False:
        LOGGER.info("Live run: creating the state table...")
        # TODO(liamschn): move the deploy state table function to the dynamo class object/module?
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
    # TODO(liamschn): check to ensure we got a 200 back from the service API call before inserting the dynamodb records
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


def deploy_stage_config_rule_lambda_code() -> None:
    """Deploy the config rule lambda code to the staging s3 bucket."""
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    if DRY_RUN is False:
        LOGGER.info("Live run: downloading and staging the config rule code...")
        repo.download_code_library(repo.REPO_ZIP_URL)
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
        LIVE_RUN_DATA["CodeDownload"] = "Downloaded code library"
        repo.prepare_config_rules_for_staging(repo.STAGING_UPLOAD_FOLDER, repo.STAGING_TEMP_FOLDER, repo.SOLUTIONS_DIR)
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
        LIVE_RUN_DATA["CodePrep"] = "Prepared config rule code for staging"
        s3.stage_code_to_s3(repo.STAGING_UPLOAD_FOLDER, s3.STAGING_BUCKET)
        LIVE_RUN_DATA["CodeStaging"] = "Staged config rule code to staging s3 bucket"
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
    else:
        LOGGER.info(f"DRY_RUN: Downloading code library from {repo.REPO_ZIP_URL}")
        LOGGER.info(f"DRY_RUN: Preparing config rules for staging in the {repo.STAGING_UPLOAD_FOLDER} folder")
        LOGGER.info(f"DRY_RUN: Staging config rule code to the {s3.STAGING_BUCKET} staging bucket")


def deploy_sns_configuration_topics(context: Any) -> str:
    """Deploy sns configuration topics.

    Args:
        context (Any): lambda context object

    Returns:
        str: sns topic arn
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    sns.SNS_CLIENT = sts.assume_role(sts.MANAGEMENT_ACCOUNT, sts.CONFIGURATION_ROLE, "sns", sts.HOME_REGION)
    topic_search = sns.find_sns_topic(f"{SOLUTION_NAME}-configuration")
    if topic_search is None:
        LOGGER.info(f"Creating {SOLUTION_NAME}-configuration SNS topic")
        topic_arn = sns.create_sns_topic(f"{SOLUTION_NAME}-configuration", SOLUTION_NAME)
        LIVE_RUN_DATA["SNSCreate"] = f"Created {SOLUTION_NAME}-configuration SNS topic"
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
        CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1

        LOGGER.info(f"Creating SNS topic policy permissions for {topic_arn} on {context.function_name} lambda function")
        statement_name = "sra-sns-invoke"
        if lambdas.find_permission(context.function_name, statement_name) is False:
            LOGGER.info(f"Adding lambda {statement_name} permissions for SNS topic")
            lambdas.put_permissions(context.function_name, statement_name, "sns.amazonaws.com", "lambda:InvokeFunction", topic_arn)
        else:
            LOGGER.info(f"Lambda {statement_name} permissions already exist for SNS topic")
        LIVE_RUN_DATA["SNSPermissions"] = "Added lambda sns-invoke permissions for SNS topic"
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
        CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1

        LOGGER.info(f"Subscribing {context.invoked_function_arn} to {topic_arn}")
        sns.create_sns_subscription(topic_arn, "lambda", context.invoked_function_arn)
        LIVE_RUN_DATA["SNSSubscription"] = f"Subscribed {context.invoked_function_arn} lambda to {SOLUTION_NAME}-configuration SNS topic"
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
        CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
        if DRY_RUN is False:
            # SNS State table record:
            add_state_table_record(
                "sns", "implemented", "configuration topic", "topic", topic_arn, ACCOUNT, sts.HOME_REGION, f"{SOLUTION_NAME}-configuration"
            )
        else:
            DRY_RUN_DATA["SNSCreate"] = f"DRY_RUN: Created {SOLUTION_NAME}-configuration SNS topic"
            DRY_RUN_DATA["SNSPermissions"] = "DRY_RUN: Added lambda sns-invoke permissions for SNS topic"
            DRY_RUN_DATA["SNSSubscription"] = f"DRY_RUN: Subscribed {context.invoked_function_arn} lambda to {SOLUTION_NAME}-configuration SNS topic"
    else:
        LOGGER.info(f"{SOLUTION_NAME}-configuration SNS topic already exists.")
        topic_arn = topic_search
        if DRY_RUN is False:
            # SNS State table record:
            add_state_table_record(
                "sns", "implemented", "configuration topic", "topic", topic_arn, ACCOUNT, sts.HOME_REGION, f"{SOLUTION_NAME}-configuration"
            )
        else:
            DRY_RUN_DATA["SNSCreate"] = f"DRY_RUN: {SOLUTION_NAME}-configuration SNS topic already exists"

    return topic_arn


def deploy_config_rules(region: str, accounts: list, resource_properties: dict) -> None:  # noqa: CCR001
    """Deploy config rules.

    Args:
        region (str): aws region
        accounts (list): aws accounts
        resource_properties (dict): event resource properties
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA
    for prop in resource_properties:
        if prop.startswith("SRA-BEDROCK-CHECK-"):
            rule_name: str = prop
            LOGGER.info(f"Create operation: retrieving {rule_name} parameters...")
            rule_deploy, rule_accounts, rule_regions, rule_input_params = get_rule_params(rule_name, resource_properties)
            rule_name = rule_name.lower()
            LOGGER.info(f"Create operation: examining {rule_name} resources...")
            if rule_regions:
                LOGGER.info(f"{rule_name} regions: {rule_regions}")
                if region not in rule_regions:
                    LOGGER.info(f"{rule_name} does not apply to {region}; skipping...")
                    continue

            for acct in accounts:

                if rule_deploy is False:
                    LOGGER.info(f"{rule_name} is not to be deployed.  Checking to see if it needs to be removed...")
                    delete_custom_config_rule(rule_name, acct, region)
                    delete_custom_config_iam_role(rule_name, acct)
                    continue
                if rule_accounts:
                    LOGGER.info(f"{rule_name} accounts: {rule_accounts}")
                    if acct not in rule_accounts:
                        LOGGER.info(f"{rule_name} does not apply to {acct}; skipping...")
                        continue
                if DRY_RUN is False:
                    # 3a) Deploy IAM role for custom config rule lambda
                    LOGGER.info(f"Deploying IAM role for custom config rule lambda in {acct}")
                    role_arn = deploy_iam_role(acct, rule_name)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_IAMRole"] = "Deployed IAM role for custom config rule lambda"

                else:
                    LOGGER.info(f"DRY_RUN: Deploying IAM role for custom config rule lambda in {acct}")
                    DRY_RUN_DATA[f"{rule_name}_{acct}_IAMRole"] = "DRY_RUN: Deploy IAM role for custom config rule lambda"
                # 3b) Deploy lambda for custom config rule
                if DRY_RUN is False:
                    # download rule zip file
                    s3_key = f"{SOLUTION_NAME}/rules/{rule_name}/{rule_name}.zip"
                    local_base_path = "/tmp/sra_staging_upload"  # noqa: S108
                    local_file_path = os.path.join(local_base_path, f"{SOLUTION_NAME}", "rules", rule_name, f"{rule_name}.zip")  # noqa: PL118
                    s3.download_s3_file(local_file_path, s3_key, s3.STAGING_BUCKET)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_LambdaCode"] = "Downloaded custom config rule lambda code"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1

                    LOGGER.info(f"Deploying lambda for custom config rule in {acct} in {region}")
                    lambda_arn = deploy_lambda_function(acct, rule_name, role_arn, region)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Lambda"] = "Deployed custom config lambda function"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
                else:
                    LOGGER.info(f"DRY_RUN: Deploying lambda for custom config rule in {acct} in {region}")
                    DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Lambda"] = "DRY_RUN: Deploy custom config lambda function"

                # 3c) Deploy the config rule (requires config_org [non-CT] or config_mgmt [CT] solution)
                if DRY_RUN is False:
                    deploy_config_rule(acct, rule_name, lambda_arn, region, rule_input_params)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Config"] = "Deployed custom config rule"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
                else:
                    LOGGER.info(f"DRY_RUN: Deploying custom config rule in {acct} in {region}")
                    DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Config"] = "DRY_RUN: Deploy custom config rule"


def deploy_metric_filters_and_alarms(region: str, accounts: list, resource_properties: dict) -> None:  # noqa: CCR001, CFQ001, C901
    """Deploy metric filters and alarms.

    Args:
        region (str): aws region
        accounts (list): aws accounts
        resource_properties (dict): event resource properties
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA
    LOGGER.info(f"CloudWatch Metric Filters: {CLOUDWATCH_METRIC_FILTERS}")
    lambdas.LAMBDA_CLIENT = sts.assume_role(sts.MANAGEMENT_ACCOUNT, sts.CONFIGURATION_ROLE, "lambda", sts.HOME_REGION)
    execution_role_arn = lambdas.get_lambda_execution_role(os.environ["AWS_LAMBDA_FUNCTION_NAME"])

    for filter_name in CLOUDWATCH_METRIC_FILTERS:
        filter_deploy, filter_accounts, filter_regions, filter_params = get_filter_params(filter_name, resource_properties)
        LOGGER.info(f"{filter_name} parameters: {filter_params}")
        if filter_deploy is False:
            LOGGER.info(f"{filter_name} filter not requested (deploy set to false). Checking to see if any need to be removed...")
            if filter_regions:
                LOGGER.info(f"Checking {filter_name} filter in regions: {filter_regions}...")
                if region not in filter_regions:
                    LOGGER.info(f"Check found that {filter_name} filter was not requested for {region}. Skipping region...")
                else:
                    for acct in accounts:
                        if filter_accounts:
                            LOGGER.info(f"Checking filter_accounts: {filter_accounts}")
                            if acct not in filter_accounts:
                                LOGGER.info(f"Check found that {filter_name} filter not requested for {acct}. Skipping account...")
                            else:
                                LOGGER.info(
                                    f"Check found that {filter_name} filter was defined for {acct} in {region}; Checking for need to be removed..."
                                )
                                delete_metric_filter_and_alarm(filter_name, acct, region, filter_params)
            continue
        if filter_regions:
            LOGGER.info(f"{filter_name} filter regions: {filter_regions}")
            if region not in filter_regions:
                LOGGER.info(f"{filter_name} filter not requested for {region}. Skipping...")
                continue
        LOGGER.info(f"Raw filter pattern: {CLOUDWATCH_METRIC_FILTERS[filter_name]}")
        if "BUCKET_NAME_PLACEHOLDER" in CLOUDWATCH_METRIC_FILTERS[filter_name]:
            LOGGER.info(f"{filter_name} filter parameter: 'BUCKET_NAME_PLACEHOLDER' found. Updating with bucket info...")
            filter_pattern = build_s3_metric_filter_pattern(filter_params["bucket_names"], CLOUDWATCH_METRIC_FILTERS[filter_name])
        elif "INPUT_PATH" in CLOUDWATCH_METRIC_FILTERS[filter_name]:
            filter_pattern = CLOUDWATCH_METRIC_FILTERS[filter_name].replace("<INPUT_PATH>", filter_params["input_path"])
        else:
            filter_pattern = CLOUDWATCH_METRIC_FILTERS[filter_name]
        LOGGER.info(f"{filter_name} filter pattern: {filter_pattern}")

        for acct in accounts:
            # for region in regions:
            # 4a) Deploy KMS keys
            # 4ai) KMS key for SNS topic used by CloudWatch alarms
            if filter_accounts:
                LOGGER.info(f"filter_accounts: {filter_accounts}")
                if acct not in filter_accounts:
                    LOGGER.info(f"{filter_name} filter not requested for {acct}. Skipping...")
                    continue
            kms.KMS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "kms", region)
            search_alarm_kms_key, alarm_key_alias, alarm_key_id, alarm_key_arn = kms.check_alias_exists(
                kms.KMS_CLIENT, f"alias/{ALARM_SNS_KEY_ALIAS}"
            )
            if search_alarm_kms_key is False:
                LOGGER.info(f"alias/{ALARM_SNS_KEY_ALIAS} not found.")
                if DRY_RUN is False:
                    LOGGER.info("Creating SRA alarm KMS key")
                    LOGGER.info("Customizing key policy...")
                    kms_key_policy = json.loads(json.dumps(KMS_KEY_POLICIES[ALARM_SNS_KEY_ALIAS]))
                    LOGGER.info(f"kms_key_policy: {kms_key_policy}")
                    kms_key_policy["Statement"][0]["Principal"]["AWS"] = KMS_KEY_POLICIES[ALARM_SNS_KEY_ALIAS]["Statement"][0]["Principal"][  # noqa ECE001
                        "AWS"
                    ].replace("ACCOUNT_ID", acct)

                    kms_key_policy["Statement"][2]["Principal"]["AWS"] = execution_role_arn
                    LOGGER.info(f"Customizing key policy...done: {kms_key_policy}")
                    LOGGER.info("Searching for existing keys with proper policy...")
                    kms_search_result, kms_found_id = kms.search_key_policies(kms.KMS_CLIENT, json.dumps(kms_key_policy))
                    if kms_search_result is True:
                        LOGGER.info(f"Found existing key with proper policy: {kms_found_id}")
                        alarm_key_id = kms_found_id
                    else:
                        LOGGER.info("No existing key found with proper policy. Creating new key...")
                        alarm_key_id = kms.create_kms_key(kms.KMS_CLIENT, json.dumps(kms_key_policy), "Key for CloudWatch Alarm SNS Topic Encryption")
                        LOGGER.info(f"Created SRA alarm KMS key: {alarm_key_id}")
                        LIVE_RUN_DATA["KMSKeyCreate"] = "Created SRA alarm KMS key"
                        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                        CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
                    # Add KMS resource records to sra state table
                    add_state_table_record(
                        "kms",
                        "implemented",
                        "alarms sns kms key",
                        "key",
                        f"arn:aws:kms:{region}:{acct}:key/{alarm_key_id}",
                        acct,
                        region,
                        alarm_key_id,
                        alarm_key_id,
                    )

                    # 4aii KMS alias for SNS topic used by CloudWatch alarms
                    LOGGER.info("Creating SRA alarm KMS key alias")
                    kms.create_alias(kms.KMS_CLIENT, f"alias/{ALARM_SNS_KEY_ALIAS}", alarm_key_id)
                    LIVE_RUN_DATA["KMSAliasCreate"] = "Created SRA alarm KMS key alias"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
                    # Add KMS resource records to sra state table
                    add_state_table_record(
                        "kms",
                        "implemented",
                        "alarms sns kms alias",
                        "alias",
                        f"arn:aws:kms:{region}:{acct}:alias/{ALARM_SNS_KEY_ALIAS}",
                        acct,
                        region,
                        ALARM_SNS_KEY_ALIAS,
                        alarm_key_id,
                    )

                else:
                    LOGGER.info("DRY_RUN: Creating SRA alarm KMS key")
                    DRY_RUN_DATA["KMSKeyCreate"] = "DRY_RUN: Create SRA alarm KMS key"
                    LOGGER.info("DRY_RUN: Creating SRA alarm KMS key alias")
                    DRY_RUN_DATA["KMSAliasCreate"] = "DRY_RUN: Create SRA alarm KMS key alias"
            else:
                LOGGER.info(f"Found SRA alarm KMS key: {alarm_key_id}")
                # Add KMS resource records to sra state table
                add_state_table_record(
                    "kms",
                    "implemented",
                    "alarms sns kms key",
                    "key",
                    f"arn:aws:kms:{region}:{acct}:key/{alarm_key_id}",
                    acct,
                    region,
                    alarm_key_id,
                    alarm_key_id,
                )
                add_state_table_record(
                    "kms",
                    "implemented",
                    "alarms sns kms alias",
                    "alias",
                    f"arn:aws:kms:{region}:{acct}:alias/{ALARM_SNS_KEY_ALIAS}",
                    acct,
                    region,
                    ALARM_SNS_KEY_ALIAS,
                    alarm_key_id,
                )

            # 4b) SNS topics for alarms
            sns.SNS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "sns", region)
            topic_search = sns.find_sns_topic(f"{SOLUTION_NAME}-alarms", region, acct)
            if topic_search is None:
                if DRY_RUN is False:
                    LOGGER.info(f"Creating {SOLUTION_NAME}-alarms SNS topic")
                    alarm_topic_arn = sns.create_sns_topic(f"{SOLUTION_NAME}-alarms", SOLUTION_NAME, kms_key=alarm_key_id)
                    LIVE_RUN_DATA["SNSAlarmTopic"] = f"Created {SOLUTION_NAME}-alarms SNS topic (ARN: {alarm_topic_arn})"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1

                    LOGGER.info(f"Setting access for CloudWatch alarms in {acct} to publish to {SOLUTION_NAME}-alarms SNS topic")
                    # TODO(liamschn): search for policy on SNS topic before adding the policy
                    sns.set_topic_access_for_alarms(alarm_topic_arn, acct)
                    LIVE_RUN_DATA["SNSAlarmPolicy"] = "Added policy for CloudWatch alarms to publish to SNS topic"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1

                    LOGGER.info(f"Subscribing {SRA_ALARM_EMAIL} to {alarm_topic_arn}")
                    sns.create_sns_subscription(alarm_topic_arn, "email", SRA_ALARM_EMAIL)
                    LIVE_RUN_DATA["SNSAlarmSubscription"] = f"Subscribed {SRA_ALARM_EMAIL} lambda to {SOLUTION_NAME}-alarms SNS topic"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
                    # add SNS state table record
                    add_state_table_record(
                        "sns", "implemented", "sns topic for alarms", "topic", alarm_topic_arn, acct, region, f"{SOLUTION_NAME}-alarms"
                    )

                else:
                    LOGGER.info(f"DRY_RUN: Create {SOLUTION_NAME}-alarms SNS topic")
                    DRY_RUN_DATA["SNSAlarmCreate"] = f"DRY_RUN: Create {SOLUTION_NAME}-alarms SNS topic"

                    LOGGER.info(
                        f"DRY_RUN: Create SNS topic policy for {SOLUTION_NAME}-alarms SNS topic to allow "
                        + f"CloudWatch alarm access from {sts.MANAGEMENT_ACCOUNT} account"
                    )
                    DRY_RUN_DATA["SNSAlarmPermissions"] = (
                        f"DRY_RUN: Create SNS topic policy for {SOLUTION_NAME}-alarms SNS topic to allow "
                        + f"CloudWatch alarm access from {sts.MANAGEMENT_ACCOUNT} account"
                    )
                    LOGGER.info(f"DRY_RUN: Subscribe {SRA_ALARM_EMAIL} lambda to {SOLUTION_NAME}-alarms SNS topic")
                    DRY_RUN_DATA["SNSAlarmSubscription"] = f"DRY_RUN: Subscribe {SRA_ALARM_EMAIL} lambda to {SOLUTION_NAME}-alarms SNS topic"
            else:
                LOGGER.info(f"{SOLUTION_NAME}-alarms SNS topic already exists.")
                alarm_topic_arn = topic_search
                # add SNS state table record
                add_state_table_record(
                    "sns", "implemented", "sns topic for alarms", "topic", alarm_topic_arn, acct, region, f"{SOLUTION_NAME}-alarms"
                )

            # 4c) Cloudwatch metric filters and alarms
            if DRY_RUN is False:
                if filter_deploy is True:
                    cloudwatch.CWLOGS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "logs", region)
                    cloudwatch.CLOUDWATCH_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "cloudwatch", region)
                    LOGGER.info(f"Filter deploy parameter is 'true'; deploying {filter_name} CloudWatch metric filter...")
                    deploy_metric_filter(
                        region, acct, filter_params["log_group_name"], filter_name, filter_pattern, f"{filter_name}-metric", "sra-bedrock", "1"
                    )
                    LIVE_RUN_DATA[f"{filter_name}_CloudWatch"] = "Deployed CloudWatch metric filter"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
                    LOGGER.info(f"DEBUG: Alarm topic ARN: {alarm_topic_arn}")
                    deploy_metric_alarm(
                        region,
                        acct,
                        f"{filter_name}-alarm",
                        f"{filter_name}-metric alarm",
                        f"{filter_name}-metric",
                        "sra-bedrock",
                        "Sum",
                        10,
                        1,
                        0,
                        "GreaterThanThreshold",
                        "missing",
                        [alarm_topic_arn],
                    )
                    LIVE_RUN_DATA[f"{filter_name}_CloudWatch_Alarm"] = "Deployed CloudWatch metric alarm"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1

                else:
                    LOGGER.info(f"Filter deploy parameter is 'false'; skipping {filter_name} CloudWatch metric filter deployment")
                    LIVE_RUN_DATA[f"{filter_name}_CloudWatch"] = "Filter deploy parameter is 'false'; Skipped CloudWatch metric filter deployment"
            else:
                if filter_deploy is True:
                    LOGGER.info(f"DRY_RUN: Filter deploy parameter is 'true'; Deploy {filter_name} CloudWatch metric filter...")
                    DRY_RUN_DATA[f"{filter_name}_CloudWatch"] = "DRY_RUN: Filter deploy parameter is 'true'; Deploy CloudWatch metric filter"
                    LOGGER.info(f"DRY_RUN: Filter deploy parameter is 'true'; Deploy {filter_name} CloudWatch metric alarm...")
                    DRY_RUN_DATA[f"{filter_name}_CloudWatch_Alarm"] = "DRY_RUN: Deploy CloudWatch metric alarm"
                else:
                    LOGGER.info(f"DRY_RUN: Filter deploy parameter is 'false'; Skip {filter_name} CloudWatch metric filter deployment")
                    DRY_RUN_DATA[f"{filter_name}_CloudWatch"] = (
                        "DRY_RUN: Filter deploy parameter is 'false'; Skip CloudWatch metric filter deployment"
                    )


def deploy_central_cloudwatch_observability(event: dict) -> None:  # noqa: CCR001, CFQ001, C901
    """
    Deploy central cloudwatch observability.

    Args:
        event: Lambda event object.
    """
    LOGGER.info("Deploying central cloudwatch observability...")
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    central_observability_params = json.loads(event["ResourceProperties"]["SRA-BEDROCK-CENTRAL-OBSERVABILITY"])
    # TODO(liamschn): create a parameter to choose to deploy central observability or not: deploy_central_observability = true/false
    # 5a) OAM Sink in security account
    cloudwatch.CWOAM_CLIENT = sts.assume_role(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "oam", sts.HOME_REGION)
    search_oam_sink = cloudwatch.find_oam_sink()
    if search_oam_sink[0] is False:
        if DRY_RUN is False:
            LOGGER.info("CloudWatch observability access manager sink not found, creating...")
            oam_sink_arn = cloudwatch.create_oam_sink(cloudwatch.SINK_NAME)
            LOGGER.info(f"CloudWatch observability access manager sink created: {oam_sink_arn}")
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            LIVE_RUN_DATA["OAMSinkCreate"] = "Created CloudWatch observability access manager sink"
            # add OAM sink state table record
            add_state_table_record("oam", "implemented", "oam sink", "sink", oam_sink_arn, ssm_params.SRA_SECURITY_ACCT, sts.HOME_REGION, "oam_sink")
        else:
            LOGGER.info("DRY_RUN: CloudWatch observability access manager sink not found, creating...")
            DRY_RUN_DATA["OAMSinkCreate"] = "DRY_RUN: Create CloudWatch observability access manager sink"
            # set default value for an oam sink arn (for dry run)
            oam_sink_arn = f"arn:aws:cloudwatch::{ssm_params.SRA_SECURITY_ACCT}:sink/arn"
    else:
        oam_sink_arn = search_oam_sink[1]
        LOGGER.info(f"CloudWatch observability access manager sink found: {oam_sink_arn}")
        # add OAM sink state table record
        add_state_table_record("oam", "implemented", "oam sink", "sink", oam_sink_arn, ssm_params.SRA_SECURITY_ACCT, sts.HOME_REGION, "oam_sink")

    # 5b) OAM Sink policy in security account
    cloudwatch.SINK_POLICY = CLOUDWATCH_OAM_SINK_POLICY["sra-oam-sink-policy"]
    cloudwatch.SINK_POLICY["Statement"][0]["Condition"]["ForAnyValue:StringEquals"]["aws:PrincipalOrgID"] = ORGANIZATION_ID
    if search_oam_sink[0] is False and DRY_RUN is True:
        LOGGER.info("DRY_RUN: CloudWatch observability access manager sink doesn't exist; skip search for sink policy...")
        search_oam_sink_policy: tuple[bool, dict] = False, {}
    else:
        search_oam_sink_policy = cloudwatch.find_oam_sink_policy(oam_sink_arn)
    if search_oam_sink_policy[0] is False:
        if DRY_RUN is False:
            LOGGER.info("CloudWatch observability access manager sink policy not found, creating...")
            cloudwatch.put_oam_sink_policy(oam_sink_arn, cloudwatch.SINK_POLICY)
            LOGGER.info("CloudWatch observability access manager sink policy created")
            LIVE_RUN_DATA["OAMSinkPolicyCreate"] = "Created CloudWatch observability access manager sink policy"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
        else:
            LOGGER.info("DRY_RUN: CloudWatch observability access manager sink policy not found, creating...")
            DRY_RUN_DATA["OAMSinkPolicyCreate"] = "DRY_RUN: Create CloudWatch observability access manager sink policy"
    else:
        check_oam_sink_policy = cloudwatch.compare_oam_sink_policy(search_oam_sink_policy[1], cloudwatch.SINK_POLICY)
        if check_oam_sink_policy is False:
            if DRY_RUN is False:
                LOGGER.info("CloudWatch observability access manager sink policy needs updating...")
                cloudwatch.put_oam_sink_policy(oam_sink_arn, cloudwatch.SINK_POLICY)
                LOGGER.info("CloudWatch observability access manager sink policy updated")
                LIVE_RUN_DATA["OAMSinkPolicyUpdate"] = "Updated CloudWatch observability access manager sink policy"
                CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
            else:
                LOGGER.info("DRY_RUN: CloudWatch observability access manager sink policy needs updating...")
                DRY_RUN_DATA["OAMSinkPolicyUpdate"] = "DRY_RUN: Update CloudWatch observability access manager sink policy"
        else:
            LOGGER.info("CloudWatch observability access manager sink policy is correct")

    # 5c) OAM CloudWatch-CrossAccountSharingRole IAM role
    # Add management account to the bedrock accounts list
    bedrock_and_mgmt_accounts = copy.deepcopy(central_observability_params["bedrock_accounts"])
    bedrock_and_mgmt_accounts.append(sts.MANAGEMENT_ACCOUNT)
    for bedrock_account in bedrock_and_mgmt_accounts:
        for bedrock_region in central_observability_params["regions"]:
            iam.IAM_CLIENT = sts.assume_role(bedrock_account, sts.CONFIGURATION_ROLE, "iam", iam.get_iam_global_region())
            cloudwatch.CROSS_ACCOUNT_TRUST_POLICY = CLOUDWATCH_OAM_TRUST_POLICY[cloudwatch.CROSS_ACCOUNT_ROLE_NAME]
            cloudwatch.CROSS_ACCOUNT_TRUST_POLICY["Statement"][0]["Principal"]["AWS"] = cloudwatch.CROSS_ACCOUNT_TRUST_POLICY[  # noqa: ECE001
                "Statement"][0]["Principal"]["AWS"].replace("<SECURITY_ACCOUNT>", ssm_params.SRA_SECURITY_ACCT)
            search_iam_role = iam.check_iam_role_exists(cloudwatch.CROSS_ACCOUNT_ROLE_NAME)
            if search_iam_role[0] is False:
                LOGGER.info(
                    f"CloudWatch observability access manager cross-account role not found, creating {cloudwatch.CROSS_ACCOUNT_ROLE_NAME}"
                    + f" IAM role in {bedrock_account}..."
                )
                if DRY_RUN is False:
                    xacct_role = iam.create_role(cloudwatch.CROSS_ACCOUNT_ROLE_NAME, cloudwatch.CROSS_ACCOUNT_TRUST_POLICY, SOLUTION_NAME)
                    xacct_role_arn = xacct_role["Role"]["Arn"]
                    LIVE_RUN_DATA[f"OAMCrossAccountRoleCreate_{bedrock_account}"] = (
                        f"Created {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role in {bedrock_account}"
                    )
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
                    LOGGER.info(f"Created {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role")
                    # add cross account role state table record
                    add_state_table_record(
                        "iam",
                        "implemented",
                        "cross account sharing role",
                        "role",
                        xacct_role_arn,
                        bedrock_account,
                        iam.get_iam_global_region(),
                        cloudwatch.CROSS_ACCOUNT_ROLE_NAME,
                    )
                else:
                    DRY_RUN_DATA[f"OAMCrossAccountRoleCreate_{bedrock_account}"] = (
                        f"DRY_RUN: Create {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role in {bedrock_account}"
                    )
            else:
                LOGGER.info(
                    f"CloudWatch observability access manager {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} cross-account role found in {bedrock_account}"
                )
                xacct_role_arn = search_iam_role[1]
                # add cross account role state table record
                add_state_table_record(
                    "iam",
                    "implemented",
                    "cross account sharing role",
                    "role",
                    xacct_role_arn,
                    bedrock_account,
                    iam.get_iam_global_region(),
                    cloudwatch.CROSS_ACCOUNT_ROLE_NAME,
                )

            # 5d) Attach managed policies to CloudWatch-CrossAccountSharingRole IAM role
            cross_account_policies = [
                "arn:aws:iam::aws:policy/AWSXrayReadOnlyAccess",
                "arn:aws:iam::aws:policy/CloudWatchAutomaticDashboardsAccess",
                "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
            ]
            for policy_arn in cross_account_policies:
                search_attached_policies = iam.check_iam_policy_attached(cloudwatch.CROSS_ACCOUNT_ROLE_NAME, policy_arn)
                if search_attached_policies is False:
                    LOGGER.info(f"Attaching {policy_arn} policy to {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role in {bedrock_account}...")
                    if DRY_RUN is False:
                        iam.attach_policy(cloudwatch.CROSS_ACCOUNT_ROLE_NAME, policy_arn)
                        LIVE_RUN_DATA[f"OamXacctRolePolicyAttach_{policy_arn.split('/')[1]}_{bedrock_account}"] = (
                            f"Attached {policy_arn} policy to {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role"
                        )
                        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1

                        CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
                        LOGGER.info(f"Attached {policy_arn} policy to {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role in {bedrock_account}")
                    else:
                        DRY_RUN_DATA[f"OAMCrossAccountRolePolicyAttach_{policy_arn.split('/')[1]}_{bedrock_account}"] = (
                            f"DRY_RUN: Attach {policy_arn} policy to {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role in {bedrock_account}"
                        )

            # 5e) OAM link in bedrock account
            cloudwatch.CWOAM_CLIENT = sts.assume_role(bedrock_account, sts.CONFIGURATION_ROLE, "oam", bedrock_region)
            search_oam_link = cloudwatch.find_oam_link(oam_sink_arn)
            if search_oam_link[0] is False:
                if DRY_RUN is False:
                    LOGGER.info("CloudWatch observability access manager link not found, creating...")
                    oam_link_arn = cloudwatch.create_oam_link(oam_sink_arn)
                    LIVE_RUN_DATA[f"OAMLinkCreate_{bedrock_account}_{bedrock_region}"] = (
                        f"Created CloudWatch observability access manager link in {bedrock_account} in {bedrock_region}"
                    )
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1

                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
                    LOGGER.info("Created CloudWatch observability access manager link")
                    # add OAM link state table record
                    add_state_table_record("oam", "implemented", "oam link", "link", oam_link_arn, bedrock_account, bedrock_region, "oam_link")
                else:
                    LOGGER.info("DRY_RUN: CloudWatch observability access manager link not found, creating...")
                    DRY_RUN_DATA[f"OAMLinkCreate_{bedrock_account}"] = (
                        f"DRY_RUN: Create CloudWatch observability access manager link in {bedrock_account} in {bedrock_region}"
                    )
                    # Set link arn to default value (for dry run)
                    oam_link_arn = f"arn:aws:cloudwatch::{bedrock_account}:link/arn"
            else:
                LOGGER.info(f"CloudWatch observability access manager link found in {bedrock_account} in {bedrock_region}")
                oam_link_arn = search_oam_link[1]
                # add OAM link state table record
                add_state_table_record("oam", "implemented", "oam link", "link", oam_link_arn, bedrock_account, bedrock_region, "oam_link")


def deploy_cloudwatch_dashboard(event: dict) -> None:
    """Deploy CloudWatch dashboard.

    Args:
        event (dict): Lambda event data.
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    central_observability_params = json.loads(event["ResourceProperties"]["SRA-BEDROCK-CENTRAL-OBSERVABILITY"])

    cloudwatch_dashboard = build_cloudwatch_dashboard(
        CLOUDWATCH_DASHBOARD, SOLUTION_NAME, central_observability_params["bedrock_accounts"], central_observability_params["regions"]
    )
    cloudwatch.CLOUDWATCH_CLIENT = sts.assume_role(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "cloudwatch", sts.HOME_REGION)

    search_dashboard = cloudwatch.find_dashboard(SOLUTION_NAME)
    if search_dashboard[0] is False:
        if DRY_RUN is False:
            LOGGER.info("CloudWatch observability dashboard not found, creating...")
            cloudwatch.create_dashboard(cloudwatch.SOLUTION_NAME, cloudwatch_dashboard)
            search_dashboard = cloudwatch.find_dashboard(SOLUTION_NAME)
            LIVE_RUN_DATA["CloudWatchDashboardCreate"] = "Created CloudWatch observability dashboard"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            LOGGER.info("Created CloudWatch observability dashboard")
            # add dashboard state table record
            add_state_table_record(
                "cloudwatch",
                "implemented",
                "cloudwatch dashboard",
                "dashboard",
                search_dashboard[1],
                ssm_params.SRA_SECURITY_ACCT,
                sts.HOME_REGION,
                SOLUTION_NAME,
            )
        else:
            LOGGER.info("DRY_RUN: CloudWatch observability dashboard not found, creating...")
            DRY_RUN_DATA["CloudWatchDashboardCreate"] = "DRY_RUN: Create CloudWatch observability dashboard"
    else:
        LOGGER.info(f"Cloudwatch dashboard already exists: {search_dashboard[1]}")
        add_state_table_record(
            "cloudwatch",
            "implemented",
            "cloudwatch dashboard",
            "dashboard",
            search_dashboard[1],
            ssm_params.SRA_SECURITY_ACCT,
            sts.HOME_REGION,
            SOLUTION_NAME,
        )


def remove_cloudwatch_dashboard() -> None:
    """Remove cloudwatch dashboard."""
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    cloudwatch.CLOUDWATCH_CLIENT = sts.assume_role(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "cloudwatch", sts.HOME_REGION)

    search_dashboard = cloudwatch.find_dashboard(SOLUTION_NAME)
    if search_dashboard[0] is True:
        if DRY_RUN is False:
            LOGGER.info(f"CloudWatch observability dashboard found: {search_dashboard[1]}, deleting...")
            cloudwatch.delete_dashboard(SOLUTION_NAME)
            LIVE_RUN_DATA["CloudWatchDashboardCreate"] = "Created CloudWatch observability dashboard"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info("Deleted CloudWatch observability dashboard")
            remove_state_table_record(search_dashboard[1])
        else:
            LOGGER.info("DRY_RUN: CloudWatch observability dashboard found, needs to be deleted...")
            DRY_RUN_DATA["CloudWatchDashboardDelete"] = "DRY_RUN: Delete CloudWatch observability dashboard"
    else:
        LOGGER.info(f"{SOLUTION_NAME} cloudwatch dashboard not found...")
        remove_state_table_record(f"arn:aws:cloudwatch::{ssm_params.SRA_SECURITY_ACCT}:dashboard/{SOLUTION_NAME}")


def create_event(event: dict, context: Any) -> str:
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

    event_info = {"Event": event}
    LOGGER.info(event_info)
    LOGGER.info(f"CFN_RESPONSE_DATA START: {CFN_RESPONSE_DATA}")
    # Deploy state table
    deploy_state_table()
    LOGGER.info(f"CFN_RESPONSE_DATA POST deploy_state_table: {CFN_RESPONSE_DATA}")
    # add IAM state table record for the lambda execution role
    execution_role_arn = lambdas.get_lambda_execution_role(os.environ["AWS_LAMBDA_FUNCTION_NAME"])
    execution_role_name = execution_role_arn.split("/")[-1]
    LOGGER.info(f"Adding state table record for lambda IAM execution role: {execution_role_arn}")
    add_state_table_record(
        "iam", "implemented", "lambda execution role", "role", execution_role_arn, sts.MANAGEMENT_ACCOUNT, sts.HOME_REGION, execution_role_name
    )
    # add lambda function state table record
    LOGGER.info(f"Adding state table record for lambda function: {context.invoked_function_arn}")
    LAMBDA_RECORD_ID = add_state_table_record(
        "lambda",
        "implemented",
        "bedrock solution function",
        "lambda",
        context.invoked_function_arn,
        sts.MANAGEMENT_ACCOUNT,
        sts.HOME_REGION,
        context.function_name,
    )

    # 1) Stage config rule lambda code (global/home region)
    deploy_stage_config_rule_lambda_code()
    LOGGER.info(f"CFN_RESPONSE_DATA POST deploy_stage_config_rule_lambda_code: {CFN_RESPONSE_DATA}")

    # 2) SNS topics for fanout configuration operations (global/home region)
    topic_arn = deploy_sns_configuration_topics(context)
    LOGGER.info(f"CFN_RESPONSE_DATA POST deploy_sns_configuration_topics: {CFN_RESPONSE_DATA}")

    # 3 & 4) Deploy config rules, kms cmk, cloudwatch metric filters, and SNS topics for alarms (regional SNS fanout)
    accounts, regions = get_accounts_and_regions(event["ResourceProperties"])
    create_sns_messages(accounts, regions, topic_arn, event["ResourceProperties"], "configure")
    LOGGER.info(f"CFN_RESPONSE_DATA POST create_sns_messages: {CFN_RESPONSE_DATA}")

    # 5) Central CloudWatch Observability (regional)
    deploy_central_cloudwatch_observability(event)
    LOGGER.info(f"CFN_RESPONSE_DATA POST deploy_central_cloudwatch_observability: {CFN_RESPONSE_DATA}")

    # 6) Cloudwatch dashboard in security account (home region, security account)
    deploy_cloudwatch_dashboard(event)
    LOGGER.info(f"CFN_RESPONSE_DATA POST deploy_cloudwatch_dashboard: {CFN_RESPONSE_DATA}")

    # End
    # TODO(liamschn): Consider the 256 KB limit for any cloudwatch log message
    if DRY_RUN is False:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": LIVE_RUN_DATA}))
    else:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": DRY_RUN_DATA}))
        create_json_file("dry_run_data.json", DRY_RUN_DATA)
        LOGGER.info("Dry run data saved to file")
        s3.upload_file_to_s3("/tmp/dry_run_data.json", s3.STAGING_BUCKET,  # noqa: S108
                             f"dry_run_data_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json")
        LOGGER.info(f"Dry run data file uploaded to s3://{s3.STAGING_BUCKET}/dry_run_data_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json")

    if RESOURCE_TYPE == CFN_CUSTOM_RESOURCE:
        LOGGER.info("Resource type is a custom resource")
        cfnresponse.send(event, context, cfnresponse.SUCCESS, CFN_RESPONSE_DATA, CFN_RESOURCE_ID)
    else:
        LOGGER.info("Resource type is not a custom resource")
    return CFN_RESOURCE_ID


def update_event(event: dict, context: Any) -> str:
    """Update event.

    Args:
        event (dict): Lambda event data.
        context (Any): Lambda context data.

    Returns:
        str: CloudFormation response URL.
    """
    global CFN_RESPONSE_DATA
    CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
    # TODO(liamschn): handle CFN update events; use case: add additional config rules via new rules in code (i.e. ...\rules\new_rule\app.py)
    # TODO(liamschn): handle CFN update events; use case: changing config rule parameters (i.e. deploy, accounts, regions, input_params)
    global DRY_RUN_DATA
    LOGGER.info("update event function")
    create_event(event, context)
    return CFN_RESOURCE_ID


def delete_custom_config_rule(rule_name: str, acct: str, region: str) -> None:
    """Delete custom config rule.

    Args:
        rule_name (str): Config rule name
        acct (str): AWS account number
        region (str): AWS region name
    """
    # Delete the config rule
    config.CONFIG_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "config", region)
    config_rule_search = config.find_config_rule(rule_name)
    if config_rule_search[0] is True:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {rule_name} config rule for account {acct} in {region}")
            config.delete_config_rule(rule_name)
            LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} custom config rule"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            remove_state_table_record(config_rule_search[1]["ConfigRules"][0]["ConfigRuleArn"])
        else:
            LOGGER.info(f"DRY_RUN: Deleting {rule_name} config rule for account {acct} in {region}")
            DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"DRY_RUN: Delete {rule_name} custom config rule"
    else:
        LOGGER.info(f"{rule_name} config rule for account {acct} in {region} does not exist.")

    # Delete lambda for custom config rule
    lambdas.LAMBDA_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "lambda", region)
    lambda_search = lambdas.find_lambda_function(rule_name)
    if lambda_search != "None":
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {rule_name} lambda function for account {acct} in {region}")
            lambdas.delete_lambda_function(rule_name)
            LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} lambda function"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            remove_state_table_record(lambda_search)
        else:
            LOGGER.info(f"DRY_RUN: Deleting {rule_name} lambda function for account {acct} in {region}")
            DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"DRY_RUN: Delete {rule_name} lambda function"
    else:
        LOGGER.info(f"{rule_name} lambda function for account {acct} in {region} does not exist.")


def delete_custom_config_iam_role(rule_name: str, acct: str) -> None:  # noqa: CCR001
    """Delete custom config IAM role.

    Args:
        rule_name (str): config rule name
        acct (str): AWS account ID
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    region = iam.get_iam_global_region()
    # Detach IAM policies
    iam.IAM_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "iam", region)
    attached_policies = iam.list_attached_iam_policies(rule_name)
    if attached_policies is not None:
        for policy in attached_policies:
            if DRY_RUN is False:
                LOGGER.info(f"Detaching {policy['PolicyName']} IAM policy from account {acct} in {region}")
                iam.detach_policy(rule_name, policy["PolicyArn"])
                LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_PolicyDetach"] = (
                    f"Detached {policy['PolicyName']} IAM policy from account {acct} in {region}"
                )
                CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            else:
                LOGGER.info(f"DRY_RUN: Detach {policy['PolicyName']} IAM policy from account {acct} in {region}")
                DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = (
                    f"DRY_RUN: Detach {policy['PolicyName']} IAM policy from account {acct} in {region}"
                )
    else:
        LOGGER.info(f"No IAM policies attached to {rule_name} for account {acct} in {region}")

    # Delete IAM policy
    policy_arn = f"arn:{sts.PARTITION}:iam::{acct}:policy/{rule_name}-lamdba-basic-execution"
    LOGGER.info(f"Policy ARN: {policy_arn}")
    policy_search = iam.check_iam_policy_exists(policy_arn)
    if policy_search is True:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {rule_name}-lamdba-basic-execution IAM policy for account {acct} in {region}")
            iam.delete_policy(policy_arn)
            LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} IAM policy"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            remove_state_table_record(policy_arn)
        else:
            LOGGER.info(f"DRY_RUN: Delete {rule_name}-lamdba-basic-execution IAM policy for account {acct} in {region}")
            DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_PolicyDelete"] = (
                f"DRY_RUN: Delete {rule_name}-lamdba-basic-execution IAM policy for account {acct} in {region}"
            )
    else:
        LOGGER.info(f"{rule_name}-lamdba-basic-execution IAM policy for account {acct} in {region} does not exist.")

    policy_arn2 = f"arn:{sts.PARTITION}:iam::{acct}:policy/{rule_name}"
    LOGGER.info(f"Policy ARN: {policy_arn2}")
    policy_search = iam.check_iam_policy_exists(policy_arn2)
    if policy_search is True:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {rule_name} IAM policy for account {acct} in {region}")
            iam.delete_policy(policy_arn2)
            LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} IAM policy"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            remove_state_table_record(policy_arn2)
        else:
            LOGGER.info(f"DRY_RUN: Delete {rule_name} IAM policy for account {acct} in {region}")
            DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_PolicyDelete"] = f"DRY_RUN: Delete {rule_name} IAM policy for account {acct} in {region}"
    else:
        LOGGER.info(f"{rule_name} IAM policy for account {acct} in {region} does not exist.")

    # Delete IAM execution role for custom config rule lambda
    role_search = iam.check_iam_role_exists(rule_name)
    if role_search[0] is True:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {rule_name} IAM role for account {acct} in {region}")
            iam.delete_role(rule_name)
            LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} IAM role"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            remove_state_table_record(role_search[1])
        else:
            LOGGER.info(f"DRY_RUN: Delete {rule_name} IAM role for account {acct} in {region}")
            DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_RoleDelete"] = f"DRY_RUN: Delete {rule_name} IAM role for account {acct} in {region}"
    else:
        LOGGER.info(f"{rule_name} IAM role for account {acct} in {region} does not exist.")


def delete_sns_topic_and_key(acct: str, region: str) -> None:
    """Delete SNS topic and key.

    Args:
        acct (str): AWS account ID
        region (str): AWS region name
    """
    # Delete the alarm topic
    sns.SNS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "sns", region)
    alarm_topic_search = sns.find_sns_topic(f"{SOLUTION_NAME}-alarms", region, acct)
    if alarm_topic_search is not None:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {SOLUTION_NAME}-alarms SNS topic")
            LIVE_RUN_DATA["SNSDelete"] = f"Deleted {SOLUTION_NAME}-alarms SNS topic"
            sns.delete_sns_topic(alarm_topic_search)
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info(f"Deleted {SOLUTION_NAME}-alarms SNS topic")
            remove_state_table_record(alarm_topic_search)
        else:
            LOGGER.info(f"DRY_RUN: Delete {SOLUTION_NAME}-alarms SNS topic")
            DRY_RUN_DATA["SNSDelete"] = f"DRY_RUN: Delete {SOLUTION_NAME}-alarms SNS topic"
    else:
        LOGGER.info(f"{SOLUTION_NAME}-alarms SNS topic does not exist.")

    # Delete KMS key (schedule deletion) and delete kms alias
    kms.KMS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "kms", region)
    search_alarm_kms_key, alarm_key_alias, alarm_key_id, alarm_key_arn = kms.check_alias_exists(kms.KMS_CLIENT, f"alias/{ALARM_SNS_KEY_ALIAS}")
    if search_alarm_kms_key is True:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {ALARM_SNS_KEY_ALIAS} KMS key")
            kms.delete_alias(kms.KMS_CLIENT, f"alias/{ALARM_SNS_KEY_ALIAS}")
            LIVE_RUN_DATA["KMSDelete"] = f"Deleted {ALARM_SNS_KEY_ALIAS} KMS key"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info(f"Deleting {ALARM_SNS_KEY_ALIAS} KMS key ({alarm_key_id})")
            remove_state_table_record(alarm_key_arn)

            kms.schedule_key_deletion(kms.KMS_CLIENT, alarm_key_id)
            LIVE_RUN_DATA["KMSDelete"] = f"Deleted {ALARM_SNS_KEY_ALIAS} KMS key ({alarm_key_id})"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info(f"Scheduled deletion of {ALARM_SNS_KEY_ALIAS} KMS key ({alarm_key_id})")
            kms_key_arn = f"arn:{sts.PARTITION}:kms:{region}:{acct}:key/{alarm_key_id}"
            remove_state_table_record(kms_key_arn)

        else:
            LOGGER.info(f"DRY_RUN: Deleting {ALARM_SNS_KEY_ALIAS} KMS key")
            DRY_RUN_DATA["KMSDelete"] = f"DRY_RUN: Delete {ALARM_SNS_KEY_ALIAS} KMS key"
            LOGGER.info(f"DRY_RUN: Deleting {ALARM_SNS_KEY_ALIAS} KMS key ({alarm_key_id})")
            DRY_RUN_DATA["KMSDelete"] = f"DRY_RUN: Delete {ALARM_SNS_KEY_ALIAS} KMS key ({alarm_key_id})"
    else:
        LOGGER.info(f"{ALARM_SNS_KEY_ALIAS} KMS key does not exist.")


def delete_metric_filter_and_alarm(filter_name: str, acct: str, region: str, filter_params: dict) -> None:
    """Delete CloudWatch metric filter and alarm.

    Args:
        filter_name (str): CloudWatch metric filter name
        acct (str): AWS account ID
        region (str): AWS region name
        filter_params (dict): CloudWatch metric filter parameters
    """
    cloudwatch.CWLOGS_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "logs", region)
    cloudwatch.CLOUDWATCH_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "cloudwatch", region)
    if DRY_RUN is False:
        # Delete the CloudWatch metric alarm
        LOGGER.info(f"Deleting {filter_name}-alarm CloudWatch metric alarm")
        LIVE_RUN_DATA[f"{filter_name}-alarm_CloudWatchDelete"] = f"Deleted {filter_name}-alarm CloudWatch metric alarm"
        search_metric_alarm = cloudwatch.find_metric_alarm(f"{filter_name}-alarm")
        if search_metric_alarm is True:
            cloudwatch.delete_metric_alarm(f"{filter_name}-alarm")
            LIVE_RUN_DATA[f"{filter_name}-alarm_CloudWatchDelete"] = f"Deleted {filter_name}-alarm CloudWatch metric alarm"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info(f"Deleted {filter_name}-alarm CloudWatch metric alarm")
            metric_alarm_arn = f"arn:{sts.PARTITION}:cloudwatch:{region}:{acct}:alarm:{filter_name}-alarm"
            remove_state_table_record(metric_alarm_arn)
        else:
            LOGGER.info(f"{filter_name}-alarm CloudWatch metric alarm does not exist.")

        # Delete the CloudWatch metric filter
        LOGGER.info(f"Deleting {filter_name} CloudWatch metric filter")
        LIVE_RUN_DATA[f"{filter_name}_CloudWatchDelete"] = f"Deleted {filter_name} CloudWatch metric filter"
        search_metric_filter = cloudwatch.find_metric_filter(filter_params["log_group_name"], filter_name)
        if search_metric_filter is True:
            cloudwatch.delete_metric_filter(filter_params["log_group_name"], filter_name)
            LIVE_RUN_DATA[f"{filter_name}_CloudWatchDelete"] = f"Deleted {filter_name} CloudWatch metric filter"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info(f"Deleted {filter_name} CloudWatch metric filter")
            metric_filter_arn = f"arn:{sts.PARTITION}:logs:{region}:{acct}:metric-filter:{filter_name}"
            remove_state_table_record(metric_filter_arn)

        else:
            LOGGER.info(f"{filter_name} CloudWatch metric filter does not exist.")

    else:
        LOGGER.info(f"DRY_RUN: Delete {filter_name} CloudWatch metric filter")
        DRY_RUN_DATA[f"{filter_name}_CloudWatchDelete"] = f"DRY_RUN: Delete {filter_name} CloudWatch metric filter"


def delete_event(event: dict, context: Any) -> None:  # noqa: CFQ001, CCR001, C901
    """Delete event function.

    Args:
        event (dict): Lambda event object
        context (Any): Lambda context object
    """
    # TODO(liamschn): handle delete error if IAM policy is updated out-of-band - botocore.errorfactory.DeleteConflictException:
    #   An error occurred (DeleteConflict) when calling the DeletePolicy operation: This policy has more than one version.
    #   Before you delete a policy, you must delete the policy's versions. The default version is deleted with the policy.
    # TODO(liamschn): move re-used delete event operation code to separate functions
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA
    DRY_RUN_DATA = {}
    LIVE_RUN_DATA = {}
    LOGGER.info("Delete event function")

    # 0) Delete cloudwatch dashboard
    remove_cloudwatch_dashboard()

    # 1) Delete SNS topic
    # 1a) Delete configuration topic
    sns.SNS_CLIENT = sts.assume_role(sts.MANAGEMENT_ACCOUNT, sts.CONFIGURATION_ROLE, "sns", sts.HOME_REGION)
    topic_search = sns.find_sns_topic(f"{SOLUTION_NAME}-configuration")
    if topic_search is not None:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {SOLUTION_NAME}-configuration SNS topic")
            LIVE_RUN_DATA["SNSDelete"] = f"Deleted {SOLUTION_NAME}-configuration SNS topic"
            sns.delete_sns_topic(topic_search)
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            remove_state_table_record(topic_search)
        else:
            LOGGER.info(f"DRY_RUN: Deleting {SOLUTION_NAME}-configuration SNS topic")
            DRY_RUN_DATA["SNSDelete"] = f"DRY_RUN: Delete {SOLUTION_NAME}-configuration SNS topic"
    else:
        LOGGER.info(f"{SOLUTION_NAME}-configuration SNS topic does not exist.")

    # 2) Delete Central CloudWatch Observability
    central_observability_params = json.loads(event["ResourceProperties"]["SRA-BEDROCK-CENTRAL-OBSERVABILITY"])

    cloudwatch.CWOAM_CLIENT = sts.assume_role(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "oam", sts.HOME_REGION)
    search_oam_sink = cloudwatch.find_oam_sink()
    if search_oam_sink[0] is True:
        oam_sink_arn = search_oam_sink[1]
    else:
        LOGGER.info("Error deleting: CloudWatch observability access manager sink not found; may have to manually delete OAM links")
        oam_sink_arn = "Error:Sink:Arn:Not:Found"

    # Add management account to the bedrock accounts list
    central_observability_params["bedrock_accounts"].append(sts.MANAGEMENT_ACCOUNT)
    for bedrock_account in central_observability_params["bedrock_accounts"]:
        for bedrock_region in central_observability_params["regions"]:
            # 2a) OAM link in bedrock account
            cloudwatch.CWOAM_CLIENT = sts.assume_role(bedrock_account, sts.CONFIGURATION_ROLE, "oam", bedrock_region)
            search_oam_link = cloudwatch.find_oam_link(oam_sink_arn)
            if search_oam_link[0] is True:
                if DRY_RUN is False:
                    LOGGER.info(f"CloudWatch observability access manager link ({search_oam_link[1]}) found, deleting...")
                    cloudwatch.delete_oam_link(search_oam_link[1])
                    LIVE_RUN_DATA["OAMLinkDelete"] = "Deleted CloudWatch observability access manager link"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
                    LOGGER.info("Deleted CloudWatch observability access manager link")
                    remove_state_table_record(search_oam_link[1])
                else:
                    LOGGER.info("DRY_RUN: CloudWatch observability access manager link found, deleting...")
                    DRY_RUN_DATA["OAMLinkDelete"] = "DRY_RUN: Delete CloudWatch observability access manager link"
            else:
                LOGGER.info(f"CloudWatch observability access manager link ({oam_sink_arn}) not found")

            iam.IAM_CLIENT = sts.assume_role(bedrock_account, sts.CONFIGURATION_ROLE, "iam", iam.get_iam_global_region())

            # 2b) Detach managed policies to CloudWatch-CrossAccountSharingRole IAM role
            cross_account_policies = iam.list_attached_iam_policies(cloudwatch.CROSS_ACCOUNT_ROLE_NAME)
            if cross_account_policies is not None:
                if DRY_RUN is False:
                    for policy in cross_account_policies:
                        LOGGER.info(f"Detaching {policy['PolicyArn']} policy from {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role...")
                        iam.detach_policy(cloudwatch.CROSS_ACCOUNT_ROLE_NAME, policy["PolicyArn"])
                        LIVE_RUN_DATA["OAMCrossAccountRolePolicyDetach"] = (
                            f"Detached {policy['PolicyArn']} policy from {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role"
                        )
                        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                        CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
                        LOGGER.info(f"Detached {policy['PolicyArn']} policy from {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role")
                else:
                    for policy in cross_account_policies:
                        LOGGER.info(f"DRY_RUN: Detaching {policy['PolicyArn']} policy from {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role...")
                        DRY_RUN_DATA["OAMCrossAccountRolePolicyDetach"] = (
                            f"DRY_RUN: Detach {policy['PolicyArn']} policy from {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role"
                        )
            else:
                LOGGER.info(f"No policies attached to {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role")

            # 2c) Delete CloudWatch-CrossAccountSharingRole IAM role
            search_iam_role = iam.check_iam_role_exists(cloudwatch.CROSS_ACCOUNT_ROLE_NAME)
            if search_iam_role[0] is True:
                if DRY_RUN is False:
                    LOGGER.info(f"Deleting {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role...")
                    iam.delete_role(cloudwatch.CROSS_ACCOUNT_ROLE_NAME)
                    LIVE_RUN_DATA["OAMCrossAccountRoleDelete"] = f"Deleted {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role"
                    CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
                    CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
                    LOGGER.info(f"Deleted {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role")
                    remove_state_table_record(search_iam_role[1])
                else:
                    LOGGER.info(f"DRY_RUN: Deleting {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role...")
                    DRY_RUN_DATA["OAMCrossAccountRoleDelete"] = f"DRY_RUN: Delete {cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role"
            else:
                LOGGER.info(f"{cloudwatch.CROSS_ACCOUNT_ROLE_NAME} IAM role does not exist")

    # 2d) Delete OAM Sink in security account
    cloudwatch.CWOAM_CLIENT = sts.assume_role(ssm_params.SRA_SECURITY_ACCT, sts.CONFIGURATION_ROLE, "oam", sts.HOME_REGION)
    if search_oam_sink[0] is True:
        if DRY_RUN is False:
            LOGGER.info("CloudWatch observability access manager sink found, deleting...")
            cloudwatch.delete_oam_sink(oam_sink_arn)
            LIVE_RUN_DATA["OAMSinkDelete"] = "Deleted CloudWatch observability access manager sink"
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] -= 1
            LOGGER.info("Deleted CloudWatch observability access manager sink")
            remove_state_table_record(search_oam_sink[1])
        else:
            LOGGER.info("DRY_RUN: CloudWatch observability access manager sink found, deleting...")
            DRY_RUN_DATA["OAMSinkDelete"] = "DRY_RUN: Delete CloudWatch observability access manager sink"
    else:
        LOGGER.info("CloudWatch observability access manager sink not found")

    # 3) Delete metric alarms and filters
    for filter_name in CLOUDWATCH_METRIC_FILTERS:
        filter_deploy, filter_accounts, filter_regions, filter_params = get_filter_params(filter_name, event["ResourceProperties"])
        for acct in filter_accounts:
            for region in filter_regions:
                delete_metric_filter_and_alarm(filter_name, acct, region, filter_params)
                delete_sns_topic_and_key(acct, region)

    # 4) Delete config rules
    # TODO(liamschn): deal with invalid rule names?
    # TODO(liamschn): deal with invalid account IDs?
    accounts, regions = get_accounts_and_regions(event["ResourceProperties"])
    for prop in event["ResourceProperties"]:
        if prop.startswith("SRA-BEDROCK-CHECK-"):
            rule_name: str = prop
            LOGGER.info(f"Delete operation: retrieving {rule_name} parameters...")
            rule_name = rule_name.lower()
            LOGGER.info(f"Delete operation: examining {rule_name} resources...")

            for acct in accounts:
                for region in regions:
                    delete_custom_config_rule(rule_name, acct, region)

            # 5, 6, & 7) Detach IAM policies, delete IAM policy, delete IAM execution role for custom config rule lambda
            delete_custom_config_iam_role(rule_name, acct)
    # Must infer the execution role arn because the function is being reported as non-existent at this point
    execution_role_arn = f"arn:aws:iam::{sts.MANAGEMENT_ACCOUNT}:role/{SOLUTION_NAME}-lambda"
    LOGGER.info(f"Removing state table record for lambda IAM execution role: {execution_role_arn}")
    remove_state_table_record(execution_role_arn)
    LOGGER.info(f"Removing state table record for lambda function: {context.invoked_function_arn}")
    remove_state_table_record(context.invoked_function_arn)

    # TODO(liamschn): Consider the 256 KB limit for any cloudwatch log message
    if DRY_RUN is False:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": LIVE_RUN_DATA}))
    else:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": DRY_RUN_DATA}))

    if RESOURCE_TYPE != "Other":
        cfnresponse.send(event, context, cfnresponse.SUCCESS, CFN_RESPONSE_DATA, CFN_RESOURCE_ID)


def create_sns_messages(
    accounts: list,
    regions: list,
    sns_topic_arn: str,
    resource_properties: dict,
    action: str,
) -> None:
    """Create SNS Message.

    Args:
        accounts: Account List
        regions: list of AWS regions
        sns_topic_arn: SNS Topic ARN
        resource_properties: Resource Properties
        action: action
    """
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    global CFN_RESPONSE_DATA

    LOGGER.info("Creating SNS Messages...")
    sns_messages = []
    LOGGER.info("ResourceProperties found in event")

    for region in regions:
        sns_message = {"Accounts": accounts, "Region": region, "ResourceProperties": resource_properties, "Action": action}
        sns_messages.append(
            {
                "Id": region,
                "Message": json.dumps(sns_message),
                "Subject": "SRA Bedrock Configuration",
            }
        )
    sns.process_sns_message_batches(sns_messages, sns_topic_arn)
    if DRY_RUN is False:
        LIVE_RUN_DATA["SNSFanout"] = "Published SNS messages for regional fanout configuration"
        CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
    else:
        DRY_RUN_DATA["SNSFanout"] = "DRY_RUN: Published SNS messages for regional fanout configuration. More dry run data in subsequent log streams."


def process_sns_records(event: dict) -> None:
    """Process SNS records.

    Args:
        event: SNS event
    """
    LOGGER.info("Processing SNS records...")
    for record in event["Records"]:
        record["Sns"]["Message"] = json.loads(record["Sns"]["Message"])
        LOGGER.info({"SNS Record": record})
        message = record["Sns"]["Message"]
        if message["Action"] == "configure":
            LOGGER.info("Continuing process to enable SRA security controls for Bedrock (sns event)")

            # 3) Deploy config rules (regional)
            message["Accounts"].append(sts.MANAGEMENT_ACCOUNT)
            deploy_config_rules(
                message["Region"],
                message["Accounts"],
                message["ResourceProperties"],
            )

            # 4) deploy kms cmk, cloudwatch metric filters, and SNS topics for alarms (regional)
            deploy_metric_filters_and_alarms(
                message["Region"],
                message["Accounts"],
                message["ResourceProperties"],
            )

        else:
            LOGGER.info(f"Action specified is {message['Action']}")
    LOGGER.info("SNS records processed.")
    if DRY_RUN is False:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": LIVE_RUN_DATA}))
    else:
        LOGGER.info(json.dumps({"RUN STATS": CFN_RESPONSE_DATA, "RUN DATA": DRY_RUN_DATA}))
        create_json_file("dry_run_data.json", DRY_RUN_DATA)
        LOGGER.info("Dry run data saved to file")
        s3.upload_file_to_s3("/tmp/dry_run_data.json", s3.STAGING_BUCKET,  # noqa: S108
                             f"dry_run_data_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json")
        LOGGER.info(f"Dry run data file uploaded to s3://{s3.STAGING_BUCKET}/dry_run_data_{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json")


def create_json_file(file_name: str, data: dict) -> None:
    """Create JSON file.

    Args:
        file_name: name of file to be created
        data: data to be written to file
    """
    with open(f"/tmp/{file_name}", "w", encoding="utf-8") as f:  # noqa: S108, PL123
        json.dump(data, f, ensure_ascii=False, indent=4)


def deploy_iam_role(account_id: str, rule_name: str) -> str:  # noqa: CFQ001, CCR001, C901
    """Deploy IAM role.

    Args:
        account_id: AWS account ID
        rule_name: config rule name

    Returns:
        IAM role ARN
    """
    global CFN_RESPONSE_DATA
    iam.IAM_CLIENT = sts.assume_role(account_id, sts.CONFIGURATION_ROLE, "iam", REGION)
    LOGGER.info(f"Deploying IAM {rule_name} execution role for rule lambda in {account_id}...")
    role_arn = ""
    iam_role_search = iam.check_iam_role_exists(rule_name)
    if iam_role_search[0] is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating {rule_name} IAM role")
            role_arn = iam.create_role(rule_name, iam.SRA_TRUST_DOCUMENTS["sra-config-rule"], SOLUTION_NAME)["Role"]["Arn"]
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            # add IAM role state table record
            add_state_table_record("iam", "implemented", "role for config rule", "role", role_arn, account_id, "Global", rule_name)

        else:
            LOGGER.info(f"DRY_RUN: Creating {rule_name} IAM role")
    else:
        LOGGER.info(f"{rule_name} IAM role already exists.")
        role_arn = iam_role_search[1]
        if role_arn is None:
            role_arn = ""
        # add IAM role state table record
        add_state_table_record("iam", "implemented", "role for config rule", "role", role_arn, account_id, "Global", rule_name)

    iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"] = iam.SRA_POLICY_DOCUMENTS[  # noqa: ECE001
        "sra-lambda-basic-execution"]["Statement"][0]["Resource"].replace("ACCOUNT_ID", account_id)
    iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS[  # noqa: ECE001
        "sra-lambda-basic-execution"]["Statement"][1]["Resource"].replace("ACCOUNT_ID", account_id)
    iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS[  # noqa: ECE001
        "sra-lambda-basic-execution"]["Statement"][1]["Resource"].replace("CONFIG_RULE_NAME", rule_name)
    LOGGER.info(f"Policy document: {iam.SRA_POLICY_DOCUMENTS['sra-lambda-basic-execution']}")
    policy_arn = f"arn:{sts.PARTITION}:iam::{account_id}:policy/{rule_name}-lamdba-basic-execution"
    iam_policy_search = iam.check_iam_policy_exists(policy_arn)
    if iam_policy_search is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating {rule_name}-lamdba-basic-execution IAM policy in {account_id}...")
            iam.create_policy(f"{rule_name}-lamdba-basic-execution", iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"], SOLUTION_NAME)
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            # add IAM policy state table record
            add_state_table_record(
                "iam", "implemented", "policy for config rule role", "policy", policy_arn, account_id, "Global", f"{rule_name}-lamdba-basic-execution"
            )
        else:
            LOGGER.info(f"DRY _RUN: Creating {rule_name}-lamdba-basic-execution IAM policy in {account_id}...")
    else:
        LOGGER.info(f"{rule_name}-lamdba-basic-execution IAM policy already exists")
        # add IAM policy state table record
        add_state_table_record(
            "iam", "implemented", "policy for config rule role", "policy", policy_arn, account_id, "Global", f"{rule_name}-lamdba-basic-execution"
        )

    policy_arn2 = f"arn:{sts.PARTITION}:iam::{account_id}:policy/{rule_name}"
    iam_policy_search2 = iam.check_iam_policy_exists(policy_arn2)
    if iam_policy_search2 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating {rule_name} IAM policy in {account_id}...")
            iam.create_policy(f"{rule_name}", IAM_POLICY_DOCUMENTS[rule_name], SOLUTION_NAME)
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            # add IAM policy state table record
            add_state_table_record("iam", "implemented", "policy for config rule", "policy", policy_arn2, account_id, "Global", rule_name)
        else:
            LOGGER.info(f"DRY _RUN: Creating {rule_name} IAM policy in {account_id}...")
    else:
        LOGGER.info(f"{rule_name} IAM policy already exists")
        # add IAM policy state table record
        add_state_table_record("iam", "implemented", "policy for config rule", "policy", policy_arn2, account_id, "Global", rule_name)

    policy_attach_search1 = iam.check_iam_policy_attached(rule_name, policy_arn)
    if policy_attach_search1 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching {rule_name}-lamdba-basic-execution policy to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, policy_arn)
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
        else:
            LOGGER.info(f"DRY_RUN: attaching {rule_name}-lamdba-basic-execution policy to {rule_name} IAM role in {account_id}...")

    policy_attach_search2 = iam.check_iam_policy_attached(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSConfigRulesExecutionRole")
    if policy_attach_search2 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching AWSConfigRulesExecutionRole policy to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSConfigRulesExecutionRole")
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
        else:
            LOGGER.info(f"DRY_RUN: Attaching AWSConfigRulesExecutionRole policy to {rule_name} IAM role in {account_id}...")

    policy_attach_search3 = iam.check_iam_policy_attached(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    if policy_attach_search3 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching AWSConfigRulesExecutionRole policy to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
        else:
            LOGGER.info(f"DRY_RUN: Attaching AWSLambdaBasicExecutionRole policy to {rule_name} IAM role in {account_id}...")

    policy_attach_search4 = iam.check_iam_policy_attached(rule_name, policy_arn2)
    if policy_attach_search4 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching {rule_name} to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, policy_arn2)
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["configuration_changes"] += 1
        else:
            LOGGER.info(f"DRY_RUN: attaching {rule_name} to {rule_name} IAM role in {account_id}...")

    return role_arn


def deploy_lambda_function(account_id: str, rule_name: str, role_arn: str, region: str) -> str:
    """Deploy lambda function.

    Args:
        account_id: AWS account ID
        rule_name: config rule name
        role_arn: IAM role ARN
        region: AWS region

    Returns:
        Lambda function ARN
    """
    lambdas.LAMBDA_CLIENT = sts.assume_role(account_id, sts.CONFIGURATION_ROLE, "lambda", region)
    LOGGER.info(f"Deploying lambda function for {rule_name} config rule to {account_id} in {region}...")
    lambda_function_search = lambdas.find_lambda_function(rule_name)
    if lambda_function_search == "None":
        LOGGER.info(f"{rule_name} lambda function not found in {account_id}.  Creating...")
        lambda_source_zip = f"/tmp/sra_staging_upload/{SOLUTION_NAME}/rules/{rule_name}/{rule_name}.zip"  # noqa: S108
        LOGGER.info(f"Lambda zip file: {lambda_source_zip}")
        lambda_create = lambdas.create_lambda_function(
            lambda_source_zip,
            role_arn,
            rule_name,
            "app.lambda_handler",
            "python3.12",
            900,
            512,
            SOLUTION_NAME,
        )
        lambda_arn = lambda_create
        # add Lambda state table record
        add_state_table_record("lambda", "implemented", "lambda for config rule", "lambda", lambda_arn, account_id, region, rule_name)
    else:
        LOGGER.info(f"{rule_name} already exists in {account_id}.  Search result: {lambda_function_search}")
        lambda_arn = lambda_function_search
        # add Lambda state table record
        add_state_table_record("lambda", "implemented", "lambda for config rule", "lambda", lambda_arn, account_id, region, rule_name)

    return lambda_arn


def deploy_config_rule(account_id: str, rule_name: str, lambda_arn: str, region: str, input_params: dict) -> None:
    """Deploy config rule.

    Args:
        account_id: AWS account ID
        rule_name: config rule name
        lambda_arn: lambda function ARN
        region: AWS region
        input_params: input parameters for the config rule
    """
    LOGGER.info(f"Deploying {rule_name} config rule to {account_id} in {region}...")
    config.CONFIG_CLIENT = sts.assume_role(account_id, sts.CONFIGURATION_ROLE, "config", region)
    config_rule_search = config.find_config_rule(rule_name)
    if config_rule_search[0] is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating Config policy permissions for {rule_name} lambda function in {account_id} in {region}...")
            statement_id = "sra-config-invoke"
            if lambdas.find_permission(rule_name, statement_id) is False:
                LOGGER.info(f"Adding {statement_id} to {rule_name} lambda function in {account_id} in {region}...")
                lambdas.put_permissions_acct(rule_name, "config-invoke", "config.amazonaws.com", "lambda:InvokeFunction", account_id)
            else:
                LOGGER.info(f"{statement_id} already exists on {rule_name} lambda function in {account_id} in {region}...")
            LOGGER.info(f"Creating {rule_name} config rule in {account_id} in {region}...")
            config.create_config_rule(
                rule_name,
                lambda_arn,
                "One_Hour",
                "CUSTOM_LAMBDA",
                f"{rule_name} custom config rule for the {SOLUTION_NAME} solution.",
                input_params,
                "DETECTIVE",
                SOLUTION_NAME,
            )
            config_rule_search = config.find_config_rule(rule_name)
            config_rule_arn = config_rule_search[1]["ConfigRules"][0]["ConfigRuleArn"]
            CFN_RESPONSE_DATA["deployment_info"]["action_count"] += 1
            CFN_RESPONSE_DATA["deployment_info"]["resources_deployed"] += 1
            # add Config rule state table record
            add_state_table_record("config", "implemented", "config rule", "rule", config_rule_arn, account_id, region, rule_name)
        else:
            LOGGER.info(f"DRY_RUN: Creating Config policy permissions for {rule_name} lambda function in {account_id} in {region}...")
            LOGGER.info(f"DRY_RUN: Creating {rule_name} config rule in {account_id} in {region}...")
    else:
        LOGGER.info(f"{rule_name} config rule already exists.")
        config_rule_arn = config_rule_search[1]["ConfigRules"][0]["ConfigRuleArn"]
        # add Config rule state table record
        add_state_table_record("config", "implemented", "config rule", "rule", config_rule_arn, account_id, region, rule_name)


def deploy_metric_filter(
    region: str, acct: str, log_group_name: str, filter_name: str, filter_pattern: str, metric_name: str, metric_namespace: str, metric_value: str
) -> None:
    """Deploy metric filter.

    Args:
        region: region
        acct: account ID
        log_group_name: log group name
        filter_name: filter name
        filter_pattern: filter pattern
        metric_name: metric name
        metric_namespace: metric namespace
        metric_value: metric value
    """
    metric_filter_arn = f"arn:{sts.PARTITION}:logs:{region}:{acct}:metric-filter:{filter_name}"
    search_metric_filter = cloudwatch.find_metric_filter(log_group_name, filter_name)
    if search_metric_filter is False:
        if DRY_RUN is False:
            LOGGER.info(f"Deploying metric filter {filter_name} to {log_group_name}...")
            cloudwatch.create_metric_filter(log_group_name, filter_name, filter_pattern, metric_name, metric_namespace, metric_value)
            # add metric filter state table record
            add_state_table_record("cloudwatch", "implemented", "log metric filter", "filter", metric_filter_arn, acct, region, filter_name)

        else:
            LOGGER.info(f"DRY_RUN: Deploy metric filter {filter_name} to {log_group_name}...")
    else:
        LOGGER.info(f"Metric filter {filter_name} already exists.")
        # add metric filter state table record
        add_state_table_record("cloudwatch", "implemented", "log metric filter", "filter", metric_filter_arn, acct, region, filter_name)


def deploy_metric_alarm(  # noqa: CFQ002
    region: str,
    acct: str,
    alarm_name: str,
    alarm_description: str,
    metric_name: str,
    metric_namespace: str,
    metric_statistic: Literal["Average", "Maximum", "Minimum", "SampleCount", "Sum"],
    metric_period: int,
    metric_evaluation_periods: int,
    metric_threshold: float,
    metric_comparison_operator: Literal[
        "GreaterThanOrEqualToThreshold",
        "GreaterThanThreshold",
        "GreaterThanUpperThreshold",
        "LessThanLowerOrGreaterThanUpperThreshold",
        "LessThanLowerThreshold",
        "LessThanOrEqualToThreshold",
        "LessThanThreshold",
    ],
    metric_treat_missing_data: str,
    alarm_actions: list,
) -> None:
    """Deploy metric alarm.

    Args:
        region: region
        acct: account ID
        alarm_name: alarm name
        alarm_description: alarm description
        metric_name: metric name
        metric_namespace: metric namespace
        metric_statistic: metric statistic
        metric_period: metric period
        metric_evaluation_periods: metric evaluation periods
        metric_threshold: metric threshold
        metric_comparison_operator: metric comparison operator
        metric_treat_missing_data: metric treat missing data
        alarm_actions: alarm actions
    """
    alarm_arn = f"arn:{sts.PARTITION}:cloudwatch:{region}:{acct}:alarm:{alarm_name}"
    search_metric_alarm = cloudwatch.find_metric_alarm(alarm_name)
    if search_metric_alarm is False:
        LOGGER.info(f"Deploying metric alarm {alarm_name}...")
        if DRY_RUN is False:
            cloudwatch.create_metric_alarm(
                alarm_name,
                alarm_description,
                metric_name,
                metric_namespace,
                metric_statistic,
                metric_period,
                metric_threshold,
                metric_comparison_operator,
                metric_evaluation_periods,
                metric_treat_missing_data,
                alarm_actions,
            )
            # add metric alarm state table record
            add_state_table_record("cloudwatch", "implemented", "cloudwatch metric alarm", "alarm", alarm_arn, acct, region, alarm_name)
        else:
            LOGGER.info(f"DRY_RUN: Deploying metric alarm {alarm_name}...")
    else:
        LOGGER.info(f"Metric alarm {alarm_name} already exists.")
        # add metric alarm state table record
        add_state_table_record("cloudwatch", "implemented", "cloudwatch metric alarm", "alarm", alarm_arn, acct, region, alarm_name)


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
        elif "Records" in event and event["Records"][0]["EventSource"] == "aws:sns":
            get_resource_parameters(json.loads(event["Records"][0]["Sns"]["Message"]))
            process_sns_records(event)
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
                    global DRY_RUN
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
