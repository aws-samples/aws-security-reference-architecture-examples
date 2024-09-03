import json
import os
import logging
import boto3
import cfnresponse
from botocore.exceptions import ClientError

import sra_s3
import sra_repo
import sra_ssm_params
import sra_iam
import sra_dynamodb
import sra_sts
import sra_lambda
import sra_sns
import sra_config

# import sra_lambda

# TODO(liamschn): Need to test with (and create) a CFN template
# TODO(liamschn): If dynamoDB sra_state table exists, use it
# TODO(liamschn): Where do we see dry-run data?  Maybe S3 staging bucket file?  The sra_state table? Another DynamoDB table?
# TODO(liamschn): add parameter validation

from typing import TYPE_CHECKING, Sequence  # , Union, Literal, Optional

if TYPE_CHECKING:
    from mypy_boto3_ssm.type_defs import TagTypeDef

LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "INFO")
LOGGER.setLevel(log_level)

# Global vars
# STAGING_BUCKET: str = ""
RESOURCE_TYPE: str = ""
STATE_TABLE: str = "sra_state"
SOLUTION_NAME: str = "sra-bedrock-org"
# SOLUTION_DIR: str = "bedrock_org"
RULE_REGIONS_ACCOUNTS = {}
GOVERNED_REGIONS = []
BEDROCK_MODEL_EVAL_BUCKET: str = ""

LAMBDA_START: str = ""
LAMBDA_FINISH: str = ""

ACCOUNT: str = boto3.client("sts").get_caller_identity().get("Account")
REGION: str = os.environ.get("AWS_REGION")
CFN_RESOURCE_ID: str = "sra-bedrock-org-function"

# dry run global variables
DRY_RUN: bool = True
DRY_RUN_DATA: dict = {}

# other global variables
LIVE_RUN_DATA: dict = {}
IAM_POLICY_DOCUMENTS: dict = {
    "sra-bedrock-check-iam-user-access": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReadIAM",
                "Effect": "Allow",
                "Action": ["iam:Get*", "iam:List*"],
                "Resource": "*",
            },
        ],
    },
    "sra-bedrock-check-eval-job-bucket": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReadS3",
                "Effect": "Allow",
                "Action": [
                    "s3:GetLifecycleConfiguration",
                    "s3:GetEncryptionConfiguration",
                    "s3:GetBucketLogging",
                    "s3:GetBucketObjectLockConfiguration",
                    "s3:GetBucketVersioning",
                    "s3:ListBucket",
                    "s3:ListAllMyBuckets",
                ],
                "Resource": "arn:aws:s3:::*",
            },
        ],
    },
}

# Instantiate sra class objects
# todo(liamschn): can these files exist in some central location to be shared with other solutions?
ssm_params = sra_ssm_params.sra_ssm_params()
iam = sra_iam.sra_iam()
dynamodb = sra_dynamodb.sra_dynamodb()
sts = sra_sts.sra_sts()
repo = sra_repo.sra_repo()
s3 = sra_s3.sra_s3()
lambdas = sra_lambda.sra_lambda()
sns = sra_sns.sra_sns()
config = sra_config.sra_config()


def get_resource_parameters(event):
    global DRY_RUN
    global RULE_REGIONS_ACCOUNTS
    global GOVERNED_REGIONS
    global BEDROCK_MODEL_EVAL_BUCKET

    LOGGER.info("Getting resource params...")
    # TODO(liamschn): what parameters do we need for this solution?
    # event["ResourceProperties"]["CONTROL_TOWER"]
    repo.REPO_ZIP_URL = event["ResourceProperties"]["SRA_REPO_ZIP_URL"]
    repo.REPO_BRANCH = repo.REPO_ZIP_URL.split(".")[1].split("/")[len(repo.REPO_ZIP_URL.split(".")[1].split("/")) - 1]
    repo.SOLUTIONS_DIR = f"/tmp/aws-security-reference-architecture-examples-{repo.REPO_BRANCH}/aws_sra_examples/solutions"

    sts.CONFIGURATION_ROLE = "sra-execution"

    GOVERNED_REGIONS = ssm_params.get_ssm_parameter(ssm_params.MANAGEMENT_ACCOUNT_SESSION, REGION, "/sra/regions/customer-control-tower-regions")

    staging_bucket_param = ssm_params.get_ssm_parameter(ssm_params.MANAGEMENT_ACCOUNT_SESSION, REGION, "/sra/staging-s3-bucket-name")
    if staging_bucket_param[0] is True:
        s3.STAGING_BUCKET = staging_bucket_param[1]
        LOGGER.info(f"Successfully retrieved the SRA staging bucket parameter: {s3.STAGING_BUCKET}")
    else:
        LOGGER.info("Error retrieving SRA staging bucket ssm parameter.  Is the SRA common prerequisites solution deployed?")
        raise ValueError("Error retrieving SRA staging bucket ssm parameter.  Is the SRA common prerequisites solution deployed?") from None
    # TODO(liamschn): continue working on getting this parameter. see test_even_bedrock_org.txt (or lambda) for test event; need to test in CFN too
    if "RULE_REGIONS_ACCOUNTS" in event["ResourceProperties"]:
        RULE_REGIONS_ACCOUNTS = json.loads(event["ResourceProperties"]["RULE_REGIONS_ACCOUNTS"].replace("'", '"'))

    if "BEDROCK_MODEL_EVAL_BUCKET" in event["ResourceProperties"]:
        BEDROCK_MODEL_EVAL_BUCKET = event["ResourceProperties"]["BEDROCK_MODEL_EVAL_BUCKET"]

    if event["ResourceProperties"]["DRY_RUN"] == "true":
        # dry run
        LOGGER.info("Dry run enabled...")
        DRY_RUN = True
    else:
        # live run
        LOGGER.info("Dry run disabled...")
        DRY_RUN = False


def get_rule_params(rule_name, event):
    """_summary_

    Args:
        rule_name (str): name of config rule
        event (dict): lambda event

    Returns:
        tuple: (rule_deploy, rule_accounts, rule_regions, rule_params)
            rule_deploy (bool): whether to deploy the rule
            rule_accounts (list): list of accounts to deploy the rule to
            rule_regions (list): list of regions to deploy the rule to
            rule_input_params (dict): dictionary of rule input parameters
    """
    if rule_name.upper() in event["ResourceProperties"]:
        LOGGER.info(f"{rule_name} parameter found in event ResourceProperties")
        rule_params = json.loads(event["ResourceProperties"][rule_name.upper()])
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
    else:
        LOGGER.info(f"{rule_name.upper()} config rule parameter not found in event ResourceProperties; skipping...")
        return False, [], [], {}


def create_event(event, context):
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    DRY_RUN_DATA = {}
    LIVE_RUN_DATA = {}

    event_info = {"Event": event}
    LOGGER.info(event_info)

    # 1) Stage config rule lambda code
    if DRY_RUN is False:
        LOGGER.info("Live run: downloading and staging the config rule code...")
        repo.download_code_library(repo.REPO_ZIP_URL)
        LIVE_RUN_DATA["CodeDownload"] = "Downloaded code library"
        repo.prepare_config_rules_for_staging(repo.STAGING_UPLOAD_FOLDER, repo.STAGING_TEMP_FOLDER, repo.SOLUTIONS_DIR)
        LIVE_RUN_DATA["CodePrep"] = "Prepared config rule code for staging"
        s3.stage_code_to_s3(repo.STAGING_UPLOAD_FOLDER, s3.STAGING_BUCKET, "/")
        LIVE_RUN_DATA["CodeStaging"] = "Staged config rule code to staging s3 bucket"
    else:
        LOGGER.info(f"DRY_RUN: Downloading code library from {repo.REPO_ZIP_URL}")
        LOGGER.info(f"DRY_RUN: Preparing config rules for staging in the {repo.STAGING_UPLOAD_FOLDER} folder")
        LOGGER.info(f"DRY_RUN: Staging config rule code to the {s3.STAGING_BUCKET} staging bucket")

    # 2) Deploy SNS topic for fanout configuration operations
    # TODO(liamschn): analyze again if sns is needed for this solution
    topic_search = sns.find_sns_topic(f"{SOLUTION_NAME}-configuration")
    if topic_search is None:
        if DRY_RUN is False:
            LOGGER.info(f"Creating {SOLUTION_NAME}-configuration SNS topic")
            topic_arn = sns.create_sns_topic(f"{SOLUTION_NAME}-configuration", SOLUTION_NAME)
            LIVE_RUN_DATA["SNSCreate"] = f"Created {SOLUTION_NAME}-configuration SNS topic"
            LOGGER.info(f"Creating SNS topic policy permissions for {topic_arn} on {context.function_name} lambda function")
            # TODO(liamschn): search for permissions on lambda before adding the policy
            lambdas.put_permissions(context.function_name, "sns-invoke", "sns.amazonaws.com", "lambda:InvokeFunction", topic_arn)
            LIVE_RUN_DATA["SNSPermissions"] = "Added lambda sns-invoke permissions for SNS topic"
            LOGGER.info(f"Subscribing {context.invoked_function_arn} to {topic_arn}")
            sns.create_sns_subscription(topic_arn, "lambda", context.invoked_function_arn)
            LIVE_RUN_DATA["SNSSubscription"] = f"Subscribed {context.invoked_function_arn} lambda to {SOLUTION_NAME}-configuration SNS topic"
        else:
            LOGGER.info(f"DRY_RUN: Creating {SOLUTION_NAME}-configuration SNS topic")
            DRY_RUN_DATA["SNSCreate"] = f"DRY_RUN: Create {SOLUTION_NAME}-configuration SNS topic"

            LOGGER.info(f"DRY_RUN: Creating SNS topic policy permissions for {topic_arn} on {context.function_name} lambda function")
            DRY_RUN_DATA["SNSPermissions"] = "DRY_RUN: Add lambda sns-invoke permissions for SNS topic"

            LOGGER.info(f"DRY_RUN: Subscribing {context.invoked_function_arn} to {topic_arn}")
            DRY_RUN_DATA["SNSSubscription"] = f"DRY_RUN: Subscribe {context.invoked_function_arn} lambda to {SOLUTION_NAME}-configuration SNS topic"
    else:
        LOGGER.info(f"{SOLUTION_NAME}-configuration SNS topic already exists.")

    # 3) Deploy config rules
    for rule in repo.CONFIG_RULES[SOLUTION_NAME]:
        rule_name = rule.replace("_", "-")
        # Get bedrock solution rule accounts and regions
        rule_deploy, rule_accounts, rule_regions, rule_input_params = get_rule_params(rule_name, event)
        if rule_deploy is False:
            continue

            # return {"statusCode": 400, "body": f"{rule_name} parameter not found in event ResourceProperties"}
        # if rule_name in RULE_REGIONS_ACCOUNTS:
        #     if "accounts" in RULE_REGIONS_ACCOUNTS[rule_name]:
        #         rule_accounts = RULE_REGIONS_ACCOUNTS[rule_name]["accounts"]
        #     else:
        #         rule_accounts = []
        #     if "regions" in RULE_REGIONS_ACCOUNTS[rule_name]:
        #         rule_regions = RULE_REGIONS_ACCOUNTS[rule_name]["regions"]
        #     else:
        #         rule_regions = []
        # else:
        #     LOGGER.info(f"No {rule_name} accounts or regions found in RULE_REGIONS_ACCOUNTS dictionary.  Dictionary: {RULE_REGIONS_ACCOUNTS}")
        #     # TODO(liamschn): setup default for org accounts and governed regions
        #     LOGGER.info(f"Defaulting to all organization accounts and governed regions for {rule_name}")
        # 3a) Deploy IAM execution role for custom config rule lambda
        for acct in rule_accounts:
            if DRY_RUN is False:
                role_arn = deploy_iam_role(acct, rule_name)
                LIVE_RUN_DATA[f"{rule_name}_{acct}_IAMRole"] = "Deployed IAM role for custom config rule lambda"
            else:
                LOGGER.info(f"DRY_RUN: Deploying IAM role for custom config rule lambda in {acct}")
                DRY_RUN_DATA[f"{rule_name}_{acct}_IAMRole"] = "DRY_RUN: Deploy IAM role for custom config rule lambda"

        for acct in rule_accounts:
            for region in rule_regions:
                # 3b) Deploy lambda for custom config rule
                if DRY_RUN is False:
                    lambda_arn = deploy_lambda_function(acct, rule_name, role_arn, region)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Lambda"] = "Deployed custom config lambda function"
                else:
                    LOGGER.info(f"DRY_RUN: Deploying lambda for custom config rule in {acct} in {region}")
                    DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Lambda"] = "DRY_RUN: Deploy custom config lambda function"

                # 3c) Deploy the config rule (requires config_org [non-CT] or config_mgmt [CT] solution)
                if DRY_RUN is False:
                    config_rule_arn = deploy_config_rule(acct, rule_name, lambda_arn, region, rule_input_params)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Config"] = "Deployed custom config rule"
                else:
                    LOGGER.info(f"DRY_RUN: Deploying custom config rule in {acct} in {region}")
                    DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Config"] = "DRY_RUN: Deploy custom config rule"

    # End
    if RESOURCE_TYPE == iam.CFN_CUSTOM_RESOURCE:
        LOGGER.info("Resource type is a custom resource")
        if DRY_RUN is False:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, LIVE_RUN_DATA, CFN_RESOURCE_ID)
        else:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, DRY_RUN_DATA, CFN_RESOURCE_ID)
    else:
        LOGGER.info("Resource type is not a custom resource")
    return CFN_RESOURCE_ID


def update_event(event, context):
    # TODO(liamschn): handle CFN update events; use case: change from DRY_RUN = False to DRY_RUN = True or vice versa
    # TODO(liamschn): handle CFN update events; use case: add additional config rules via new rules in code (i.e. ...\rules\new_rule\app.py)
    # TODO(liamschn): handle CFN update events; use case: changing config rule parameters (i.e. deploy, accounts, regions, input_params)
    # TODO(liamschn): handle CFN update events; use case: setting deploy = false should remove the config rule
    global DRY_RUN_DATA
    LOGGER.info("update event function")
    # Temp calling create_event so that an update will actually do something; need to determine if this is the best way or not.
    create_event(event, context)
    # data = sra_s3.s3_resource_check()
    # TODO(liamschn): update data dictionary
    # data = {"data": "no info"}
    # if RESOURCE_TYPE != "Other":
    #     cfnresponse.send(event, context, cfnresponse.SUCCESS, data, CFN_RESOURCE_ID)
    return CFN_RESOURCE_ID


def delete_event(event, context):
    global DRY_RUN_DATA
    global LIVE_RUN_DATA
    DRY_RUN_DATA = {}
    LIVE_RUN_DATA = {}
    LOGGER.info("delete event function")
    # 1) Delete SNS topic
    topic_search = sns.find_sns_topic(f"{SOLUTION_NAME}-configuration")
    if topic_search is not None:
        if DRY_RUN is False:
            LOGGER.info(f"Deleting {SOLUTION_NAME}-configuration SNS topic")
            LIVE_RUN_DATA["SNSDelete"] = f"Deleted {SOLUTION_NAME}-configuration SNS topic"
            sns.delete_sns_topic(topic_search)
        else:
            LOGGER.info(f"DRY_RUN: Deleting {SOLUTION_NAME}-configuration SNS topic")
            DRY_RUN_DATA["SNSDelete"] = f"DRY_RUN: Delete {SOLUTION_NAME}-configuration SNS topic"

    # 2) Delete config rules
    # TODO(liamschn): deal with invalid rule names
    # TODO(liamschn): deal with invalid account IDs
    for rule in RULE_REGIONS_ACCOUNTS:
        rule_name: str = rule.replace("_", "-")
        # Get bedrock solution rule accounts and regions
        if rule_name in RULE_REGIONS_ACCOUNTS:
            if "accounts" in RULE_REGIONS_ACCOUNTS[rule_name]:
                rule_accounts = RULE_REGIONS_ACCOUNTS[rule_name]["accounts"]
            else:
                rule_accounts = []
            if "regions" in RULE_REGIONS_ACCOUNTS[rule_name]:
                rule_regions = RULE_REGIONS_ACCOUNTS[rule_name]["regions"]
            else:
                rule_regions = []
        else:
            LOGGER.info(f"No {rule_name} accounts or regions found in RULE_REGIONS_ACCOUNTS dictionary.  Dictionary: {RULE_REGIONS_ACCOUNTS}")
            LOGGER.info(f"Defaulting to all organization accounts and governed regions for {rule_name}")
        for acct in rule_accounts:
            for region in rule_regions:
                # 3) Delete the config rule
                config.CONFIG_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "config", region)
                config_rule_search = config.find_config_rule(rule_name)
                if config_rule_search[0] is True:
                    if DRY_RUN is False:
                        LOGGER.info(f"Deleting {rule_name} config rule for account {acct} in {region}")
                        config.delete_config_rule(rule_name)
                        LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} custom config rule"
                    else:
                        LOGGER.info(f"DRY_RUN: Deleting {rule_name} config rule for account {acct} in {region}")
                else:
                    LOGGER.info(f"{rule_name} config rule for account {acct} in {region} does not exist.")
                    DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"DRY_RUN: Delete {rule_name} custom config rule"

                # 4) Delete lambda for custom config rule
                lambdas.LAMBDA_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "lambda", region)
                lambda_search = lambdas.find_lambda_function(rule_name)
                if lambda_search is not None:
                    if DRY_RUN is False:
                        LOGGER.info(f"Deleting {rule_name} lambda function for account {acct} in {region}")
                        lambdas.delete_lambda_function(rule_name)
                        LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} lambda function"
                    else:
                        LOGGER.info(f"DRY_RUN: Deleting {rule_name} lambda function for account {acct} in {region}")
                        DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"DRY_RUN: Delete {rule_name} lambda function"
                else:
                    LOGGER.info(f"{rule_name} lambda function for account {acct} in {region} does not exist.")

            # 5) Detach IAM policies
            # TODO(liamschn): handle case where policy is not found attached_policies = None
            iam.IAM_CLIENT = sts.assume_role(acct, sts.CONFIGURATION_ROLE, "iam", REGION)
            attached_policies = iam.list_attached_iam_policies(rule_name)
            if attached_policies is not None:
                if DRY_RUN is False:
                    for policy in attached_policies:
                        LOGGER.info(f"Detaching {policy['PolicyName']} IAM policy from account {acct} in {region}")
                        iam.detach_policy(rule_name, policy["PolicyArn"])
                        LIVE_RUN_DATA[
                            f"{rule_name}_{acct}_{region}_PolicyDetach"
                        ] = f"Detached {policy['PolicyName']} IAM policy from account {acct} in {region}"
                else:
                    LOGGER.info(f"DRY_RUN: Detach {policy['PolicyName']} IAM policy from account {acct} in {region}")
                    DRY_RUN_DATA[
                        f"{rule_name}_{acct}_{region}_Delete"
                    ] = f"DRY_RUN: Detach {policy['PolicyName']} IAM policy from account {acct} in {region}"

            # 6) Delete IAM policy
            policy_arn = f"arn:{sts.PARTITION}:iam::{acct}:policy/{rule_name}-lamdba-basic-execution"
            LOGGER.info(f"Policy ARN: {policy_arn}")
            policy_search = iam.check_iam_policy_exists(policy_arn)
            if policy_search is True:
                if DRY_RUN is False:
                    LOGGER.info(f"Deleting {rule_name}-lamdba-basic-execution IAM policy for account {acct} in {region}")
                    iam.delete_policy(policy_arn)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} IAM policy"
                else:
                    LOGGER.info(f"DRY_RUN: Delete {rule_name}-lamdba-basic-execution IAM policy for account {acct} in {region}")
                    DRY_RUN_DATA[
                        f"{rule_name}_{acct}_{region}_PolicyDelete"
                    ] = f"DRY_RUN: Delete {rule_name}-lamdba-basic-execution IAM policy for account {acct} in {region}"

            policy_arn2 = f"arn:{sts.PARTITION}:iam::{acct}:policy/{rule_name}"
            LOGGER.info(f"Policy ARN: {policy_arn2}")
            policy_search = iam.check_iam_policy_exists(policy_arn2)
            if policy_search is True:
                if DRY_RUN is False:
                    LOGGER.info(f"Deleting {rule_name} IAM policy for account {acct} in {region}")
                    iam.delete_policy(policy_arn2)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} IAM policy"
                else:
                    LOGGER.info(f"DRY_RUN: Delete {rule_name} IAM policy for account {acct} in {region}")
                    DRY_RUN_DATA[
                        f"{rule_name}_{acct}_{region}_PolicyDelete"
                    ] = f"DRY_RUN: Delete {rule_name} IAM policy for account {acct} in {region}"

            # 7) Delete IAM execution role for custom config rule lambda
            role_search = iam.check_iam_role_exists(rule_name)
            if role_search[0] is True:
                if DRY_RUN is False:
                    LOGGER.info(f"Deleting {rule_name} IAM role for account {acct} in {region}")
                    iam.delete_role(rule_name)
                    LIVE_RUN_DATA[f"{rule_name}_{acct}_{region}_Delete"] = f"Deleted {rule_name} IAM role"
                else:
                    LOGGER.info(f"DRY_RUN: Delete {rule_name} IAM role for account {acct} in {region}")
                    DRY_RUN_DATA[f"{rule_name}_{acct}_{region}_RoleDelete"] = f"DRY_RUN: Delete {rule_name} IAM role for account {acct} in {region}"
            else:
                LOGGER.info(f"{rule_name} IAM role for account {acct} in {region} does not exist.")

    if RESOURCE_TYPE != "Other":
        if DRY_RUN is False:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, LIVE_RUN_DATA, CFN_RESOURCE_ID)
        else:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, DRY_RUN_DATA, CFN_RESOURCE_ID)


def process_sns_records(records: list) -> None:
    """Process SNS records.

    Args:
        records: list of SNS event records
    """
    for record in records:
        sns_info = record["Sns"]
        LOGGER.info(f"SNS INFO: {sns_info}")
        message = json.loads(sns_info["Message"])
        # deploy_config_rule(message["AccountId"], message["ConfigRuleName"], message["Regions"])


def deploy_iam_role(account_id: str, rule_name: str) -> str:
    """Deploy IAM role.

    Args:
        account_id: AWS account ID
        rule_name: config rule name
    """
    iam.IAM_CLIENT = sts.assume_role(account_id, sts.CONFIGURATION_ROLE, "iam", REGION)
    LOGGER.info(f"Deploying IAM {rule_name} execution role for rule lambda in {account_id}...")
    iam_role_search = iam.check_iam_role_exists(rule_name)
    if iam_role_search[0] is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating {rule_name} IAM role")
            role_arn = iam.create_role(rule_name, iam.SRA_TRUST_DOCUMENTS["sra-config-rule"], SOLUTION_NAME)["Role"]["Arn"]
        else:
            LOGGER.info(f"DRY_RUN: Creating {rule_name} IAM role")
    else:
        LOGGER.info(f"{rule_name} IAM role already exists.")
        role_arn = iam_role_search[1]

    iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"][
        "Statement"
    ][0]["Resource"].replace("ACCOUNT_ID", account_id)
    # iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"][
    #     "Statement"
    # ][0]["Resource"].replace("REGION", sts.HOME_REGION)
    iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"][
        "Statement"
    ][1]["Resource"].replace("ACCOUNT_ID", account_id)
    # iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"][
    #     "Statement"
    # ][1]["Resource"].replace("REGION", sts.HOME_REGION)
    iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"][
        "Statement"
    ][1]["Resource"].replace("CONFIG_RULE_NAME", rule_name)
    LOGGER.info(f"Policy document: {iam.SRA_POLICY_DOCUMENTS['sra-lambda-basic-execution']}")
    # TODO(liamschn): change the rule execution role to be specific permissions needed (i.e. read access to IAM, or S3)
    policy_arn = f"arn:{sts.PARTITION}:iam::{account_id}:policy/{rule_name}-lamdba-basic-execution"
    iam_policy_search = iam.check_iam_policy_exists(policy_arn)
    if iam_policy_search is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating {rule_name}-lamdba-basic-execution IAM policy in {account_id}...")
            iam.create_policy(f"{rule_name}-lamdba-basic-execution", iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"], SOLUTION_NAME)
        else:
            LOGGER.info(f"DRY _RUN: Creating {rule_name}-lamdba-basic-execution IAM policy in {account_id}...")
    else:
        LOGGER.info(f"{rule_name}-lamdba-basic-execution IAM policy already exists")

    policy_arn2 = f"arn:{sts.PARTITION}:iam::{account_id}:policy/{rule_name}"
    iam_policy_search2 = iam.check_iam_policy_exists(policy_arn2)
    if iam_policy_search2 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating {rule_name} IAM policy in {account_id}...")
            iam.create_policy(f"{rule_name}", IAM_POLICY_DOCUMENTS[rule_name], SOLUTION_NAME)
        else:
            LOGGER.info(f"DRY _RUN: Creating {rule_name} IAM policy in {account_id}...")
    else:
        LOGGER.info(f"{rule_name} IAM policy already exists")

    policy_attach_search1 = iam.check_iam_policy_attached(rule_name, policy_arn)
    if policy_attach_search1 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching {rule_name}-lamdba-basic-execution policy to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, policy_arn)
        else:
            LOGGER.info(f"DRY_RUN: attaching {rule_name}-lamdba-basic-execution policy to {rule_name} IAM role in {account_id}...")

    policy_attach_search2 = iam.check_iam_policy_attached(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSConfigRulesExecutionRole")
    if policy_attach_search2 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching AWSConfigRulesExecutionRole policy to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSConfigRulesExecutionRole")
        else:
            LOGGER.info(f"DRY_RUN: Attaching AWSConfigRulesExecutionRole policy to {rule_name} IAM role in {account_id}...")

    policy_attach_search3 = iam.check_iam_policy_attached(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    if policy_attach_search3 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching AWSConfigRulesExecutionRole policy to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, f"arn:{sts.PARTITION}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
        else:
            LOGGER.info(f"DRY_RUN: Attaching AWSLambdaBasicExecutionRole policy to {rule_name} IAM role in {account_id}...")

    policy_attach_search4 = iam.check_iam_policy_attached(rule_name, policy_arn2)
    if policy_attach_search4 is False:
        if DRY_RUN is False:
            LOGGER.info(f"Attaching {rule_name} to {rule_name} IAM role in {account_id}...")
            iam.attach_policy(rule_name, policy_arn2)
        else:
            LOGGER.info(f"DRY_RUN: attaching {rule_name} to {rule_name} IAM role in {account_id}...")

    return role_arn


def deploy_lambda_function(account_id: str, rule_name: str, role_arn: str, region: str) -> str:
    """Deploy lambda function.

    Args:
        account_id: AWS account ID
        config_rule_name: config rule name
        role_arn: IAM role ARN
        regions: list of regions to deploy the lambda function
    """
    lambdas.LAMBDA_CLIENT = sts.assume_role(account_id, sts.CONFIGURATION_ROLE, "lambda", region)
    LOGGER.info(f"Deploying lambda function for {rule_name} config rule to {account_id} in {region}...")
    lambda_function_search = lambdas.find_lambda_function(rule_name)
    if lambda_function_search == None:
        LOGGER.info(f"{rule_name} lambda function not found in {account_id}.  Creating...")
        lambda_source_zip = f"/tmp/sra_staging_upload/{SOLUTION_NAME}/rules/{rule_name}/{rule_name}.zip"
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
        lambda_arn = lambda_create["Configuration"]["FunctionArn"]
    else:
        LOGGER.info(f"{rule_name} already exists in {account_id}.  Search result: {lambda_function_search}")
        lambda_arn = lambda_function_search["Configuration"]["FunctionArn"]
    return lambda_arn


def deploy_config_rule(account_id: str, rule_name: str, lambda_arn: str, region: str, input_params: dict) -> None:
    """Deploy config rule.

    Args:
        account_id: AWS account ID
        rule_name: config rule name
        lambda_arn: lambda function ARN
        regions: list of regions to deploy the config rule
        input_params: input parameters for the config rule
    """
    LOGGER.info(f"Deploying {rule_name} config rule to {account_id} in {region}...")
    config.CONFIG_CLIENT = sts.assume_role(account_id, sts.CONFIGURATION_ROLE, "config", region)
    config_rule_search = config.find_config_rule(rule_name)
    if config_rule_search[0] is False:
        if DRY_RUN is False:
            LOGGER.info(f"Creating Config policy permissions for {rule_name} lambda function in {account_id} in {region}...")
            # TODO(liamschn): search for permissions on lambda before adding the policy
            lambdas.put_permissions_acct(rule_name, "config-invoke", "config.amazonaws.com", "lambda:InvokeFunction", account_id)
            LOGGER.info(f"Creating {rule_name} config rule in {account_id} in {region}...")
            # TODO(liamschn): Determine if we need to add a description for the config rules
            # TODO(liamschn): Determine what we will do for input parameters variable in the config rule create function;need an s3 bucket currently
            config.create_config_rule(
                rule_name,
                lambda_arn,
                "One_Hour",
                "CUSTOM_LAMBDA",
                rule_name,
                # {"BucketName": BEDROCK_MODEL_EVAL_BUCKET},
                input_params,
                "DETECTIVE",
                SOLUTION_NAME,
            )
        else:
            LOGGER.info(f"DRY_RUN: Creating Config policy permissions for {rule_name} lambda function in {account_id} in {region}...")
            LOGGER.info(f"DRY_RUN: Creating {rule_name} config rule in {account_id} in {region}...")
    else:
        LOGGER.info(f"{rule_name} config rule already exists.")


def lambda_handler(event, context):
    global RESOURCE_TYPE
    global LAMBDA_START
    global LAMBDA_FINISH
    LAMBDA_START = dynamodb.get_date_time()
    LOGGER.info(event)
    LOGGER.info({"boto3 version": boto3.__version__})
    try:
        if "ResourceType" in event:
            RESOURCE_TYPE = event["ResourceType"]
            LOGGER.info(f"ResourceType: {RESOURCE_TYPE}")
        else:
            LOGGER.info("ResourceType not found in event.")
        get_resource_parameters(event)
        if "Records" not in event and "RequestType" not in event:
            raise ValueError(
                f"The event did not include Records or RequestType. Review CloudWatch logs '{context.log_group_name}' for details."
            ) from None
        elif "Records" in event and event["Records"][0]["EventSource"] == "aws:sns":
            process_sns_records(event["Records"])
        elif "RequestType" in event:
            if event["RequestType"] == "Create":
                LOGGER.info("CREATE EVENT!!")
                create_event(event, context)
            elif event["RequestType"] == "Update":
                LOGGER.info("UPDATE EVENT!!")
                update_event(event, context)
            if event["RequestType"] == "Delete":
                LOGGER.info("DELETE EVENT!!")
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
    return {
        "statusCode": 200,
        "lambda_start": LAMBDA_START,
        "lambda_finish": LAMBDA_FINISH,
        "body": "SUCCESS",
        "dry_run": DRY_RUN,
        "dry_run_data": DRY_RUN_DATA,
    }
