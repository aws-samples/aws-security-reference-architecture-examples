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

# import sra_lambda

# TODO(liamschn): Need to test with (and create) a CFN template
# TODO(liamschn): If dynamoDB sra_state table exists, use it
# TODO(liamschn): Where do we see dry-run data?  Maybe S3 staging bucket file?  The sra_state table? Another DynamoDB table?

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

LAMBDA_START: str = ""
LAMBDA_FINISH: str = ""

ACCOUNT: str = boto3.client("sts").get_caller_identity().get("Account")
REGION: str = os.environ.get("AWS_REGION")
CFN_RESOURCE_ID: str = "sra-s3-function"

# dry run global variables
DRY_RUN: bool = True
DRY_RUN_DATA: dict = {}

# Instantiate sra class objects
# todo(liamschn): can these files exist in some central location to be shared with other solutions?
ssm_params = sra_ssm_params.sra_ssm_params()
iam = sra_iam.sra_iam()
dynamodb = sra_dynamodb.sra_dynamodb()
sts = sra_sts.sra_sts()
repo = sra_repo.sra_repo()
s3 = sra_s3.sra_s3()
lambdas = sra_lambda.sra_lambda()

def get_resource_parameters(event):
    global DRY_RUN

    LOGGER.info("Getting resource params...")
    # TODO(liamschn): what parameters do we need for this solution?
    # event["ResourceProperties"]["CONTROL_TOWER"]
    repo.REPO_ZIP_URL = event["ResourceProperties"]["SRA_REPO_ZIP_URL"]
    repo.REPO_BRANCH = repo.REPO_ZIP_URL.split(".")[1].split("/")[len(repo.REPO_ZIP_URL.split(".")[1].split("/")) - 1]
    repo.SOLUTIONS_DIR = f"/tmp/aws-security-reference-architecture-examples-{repo.REPO_BRANCH}/aws_sra_examples/solutions"

    sts.CONFIGURATION_ROLE = "sra-execution"
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


def create_event(event, context):
    event_info = {"Event": event}
    LOGGER.info(event_info)

    # 1) Stage config rule lambda code
    if DRY_RUN is False:
        LOGGER.info("Live run: downloading and staging the config rule code...")
        repo.download_code_library(repo.REPO_ZIP_URL)
        repo.prepare_config_rules_for_staging(repo.STAGING_UPLOAD_FOLDER, repo.STAGING_TEMP_FOLDER, repo.SOLUTIONS_DIR)
        s3.stage_code_to_s3(repo.STAGING_UPLOAD_FOLDER, s3.STAGING_BUCKET, "/")

    # TODO(liamschn): move deployment code to another function
    # TODO(liamschn): use STS to assume in to the delegated admin account for config
    # TODO(liamschn): ensure ACCOUNT id is the delegated admin account id
    # 2) Deploy config rules
    for rule in repo.CONFIG_RULES[SOLUTION_NAME]:
        # 2a) Deploy execution role for custom config rule lambda
        rule_lambda_name = rule.replace("_", "-")
        LOGGER.info(f"Deploying execution role for {rule_lambda_name} rule lambda")
        iam_role_search = iam.check_iam_role_exists(rule_lambda_name)
        if iam_role_search is False:
            if DRY_RUN is False:
                LOGGER.info(f"Creating {rule_lambda_name} IAM role")
                iam.create_role(rule_lambda_name, iam.SRA_TRUST_DOCUMENTS["sra-config-rule"])
            else:
                LOGGER.info(f"DRY_RUN: Creating {rule} IAM role")
        else:
            LOGGER.info(f"{rule_lambda_name} IAM role already exists.")

        iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"].replace("ACCOUNT_ID", ACCOUNT)
        iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"].replace("PARTITION", sts.PARTITION)
        iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][0]["Resource"].replace("REGION", sts.HOME_REGION)
        iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"].replace("ACCOUNT_ID", ACCOUNT)
        iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"].replace("PARTITION", sts.PARTITION)
        iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"].replace("REGION", sts.HOME_REGION)
        iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"] = iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]["Statement"][1]["Resource"].replace("CONFIG_RULE_NAME", rule)
        LOGGER.info(f"Policy document: {iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"]}")

        policy_arn = f"arn:aws:iam::{ACCOUNT}:policy/{rule_lambda_name}-lamdba-basic-execution"
        iam_policy_search = iam.check_iam_policy_exists(policy_arn)
        if iam_policy_search is False:
            if DRY_RUN is False:
                LOGGER.info(f"Creating {rule_lambda_name}-lamdba-basic-execution IAM policy")
                iam.create_policy(f"{rule_lambda_name}-lamdba-basic-execution", iam.SRA_POLICY_DOCUMENTS["sra-lambda-basic-execution"])
            else:
                LOGGER.info(f"DRY _RUN: Creating {rule_lambda_name}-lamdba-basic-execution IAM policy")
        else:
            LOGGER.info(f"{rule_lambda_name}-lamdba-basic-execution IAM policy already exists")

        policy_attach_search1 = iam.check_iam_policy_attached(rule_lambda_name, policy_arn)
        if  policy_attach_search1 is False:
            if DRY_RUN is False:
                LOGGER.info(f"Attaching {rule_lambda_name}-lamdba-basic-execution policy to {rule_lambda_name} IAM role")
                iam.attach_policy(rule_lambda_name, policy_arn)
            else:
                LOGGER.info(f"DRY_RUN: attaching {rule_lambda_name}-lamdba-basic-execution policy to {rule_lambda_name} IAM role")

        policy_attach_search1 = iam.check_iam_policy_attached(rule_lambda_name, "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole")
        if  policy_attach_search1 is False:
            if DRY_RUN is False:
                LOGGER.info(f"Attaching AWSConfigRulesExecutionRole policy to {rule_lambda_name} IAM role")
                iam.attach_policy(rule_lambda_name, "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole")
            else:
                LOGGER.info(f"DRY_RUN: Attaching AWSConfigRulesExecutionRole policy to {rule_lambda_name} IAM role")

        # 2b) Deploy lambda for custom config rule
        LOGGER.info(f"Deploying lambda function for {rule} config rule...")
        lambda_function_search = lambdas.find_lambda_function(rule)
        if lambda_function_search == None:
            LOGGER.info(f"{rule} lambda function not found.  Creating...")
            # https://sra-staging-891377138368-us-west-2.s3.us-west-2.amazonaws.com/sra-bedrock-org/rules/sra-check-iam-users/sra-check-iam-users.zip
            lambda_file_url = f"https://{s3.STAGING_BUCKET}.{iam.S3_HOST_NAME}/{SOLUTION_NAME}/rules/{rule}/{rule}.zip"
            LOGGER.info(f"Lambda file URL: {lambda_file_url}")
            # lambdas.create_lambda_function(lambda_file_url, )
        else:
            LOGGER.info(f"{rule} already exists.  Search result: {lambda_function_search}")
    # 3) Deploy IAM user config rule (requires config solution [config_org for orgs or config_mgmt for ct])


    # End
    if RESOURCE_TYPE == iam.CFN_CUSTOM_RESOURCE:
        cfnresponse.send(event, context, cfnresponse.SUCCESS, data, CFN_RESOURCE_ID)
    return CFN_RESOURCE_ID


def update_event(event, context):
    # TODO(liamschn): handle CFN update events; maybe unnecessary
    LOGGER.info("update event function")
    # data = sra_s3.s3_resource_check()
    # TODO(liamschn): update data dictionary
    data = {"data": "no info"}
    if RESOURCE_TYPE != "Other":
        cfnresponse.send(event, context, cfnresponse.SUCCESS, data, CFN_RESOURCE_ID)


def delete_event(event, context):
    LOGGER.info("delete event function")
    if RESOURCE_TYPE != "Other":
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {"delete_operation": "succeeded deleting"}, CFN_RESOURCE_ID)


def lambda_handler(event, context):
    global RESOURCE_TYPE
    global LAMBDA_START
    global LAMBDA_FINISH
    LAMBDA_START = dynamodb.get_date_time()
    LOGGER.info(event)
    LOGGER.info({"boto3 version": boto3.__version__})
    try:
        RESOURCE_TYPE = event["ResourceType"]
        LOGGER.info(f"ResourceType: {RESOURCE_TYPE}")
        get_resource_parameters(event)
        if event["RequestType"] == "Create":
            LOGGER.info("CREATE EVENT!!")
            create_event(event, context)
        if event["RequestType"] == "Update":
            LOGGER.info("UPDATE EVENT!!")
            update_event(event, context)
        if event["RequestType"] == "Delete":
            LOGGER.info("DELETE EVENT!!")
            delete_event(event, context)

    except Exception:
        LOGGER.exception("Unexpected!")
        reason = f"See the details in CloudWatch Log Stream: '{context.log_group_name}'"
        if RESOURCE_TYPE != "Other":
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, "sra-s3-lambda", reason=reason)
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
