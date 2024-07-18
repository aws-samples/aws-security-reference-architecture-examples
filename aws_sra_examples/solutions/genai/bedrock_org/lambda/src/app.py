import json
import os
import logging
import boto3
import cfnresponse
from botocore.exceptions import ClientError
import sra_s3
import sra_staging
import sra_ssm_params
import sra_iam
import sra_kms
import sra_dynamodb
import sra_sts
import sra_cfn

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
STAGING_BUCKET: str = ""
RESOURCE_TYPE: str = ""
STATE_TABLE: str = "sra_state"
SOLUTION_NAME: str = "sra-common-prerequisites"

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
# kms = sra_kms.sra_kms()
# dynamodb = sra_dynamodb.sra_dynamodb()
sts = sra_sts.sra_sts()
# cfn = sra_cfn.sra_cfn()


def get_resource_parameters(event):
    global DRY_RUN
    global staging

    LOGGER.info("Getting resource params...")
    # TODO(liamschn): what parameters do we need for this solution?
    ssm_params.CONTROL_TOWER = event["ResourceProperties"]["CONTROL_TOWER"]
    ssm_params.OTHER_REGIONS = event["ResourceProperties"]["OTHER_REGIONS"]
    ssm_params.OTHER_SECURITY_ACCT = event["ResourceProperties"]["OTHER_SECURITY_ACCT"]
    ssm_params.OTHER_LOG_ARCHIVE_ACCT = event["ResourceProperties"]["OTHER_LOG_ARCHIVE_ACCT"]
    ssm_params.SRA_STAGING_BUCKET = event["ResourceProperties"]["SRA_STAGING_BUCKET"] + "-" + ACCOUNT + "-" + REGION

    sts.CONFIGURATION_ROLE = event["ResourceProperties"]["CONFIGURATION_ROLE"]

    # dry run parameter
    if event["ResourceProperties"]["DRY_RUN"] == "true":
        LOGGER.info("Dry run enabled...")
        DRY_RUN = True
    else:
        LOGGER.info("Dry run disabled...")
        DRY_RUN = False


def create_event(event, context):
    event_info = {"Event": event}
    LOGGER.info(event_info)

    # 0) Deploy IAM user config rule (requires config solution [config_org for orgs or config_mgmt for ct])

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
