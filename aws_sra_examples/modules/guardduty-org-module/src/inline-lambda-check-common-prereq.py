# type: ignore
"""Custom Resource to check to see if a resource exists.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging
import os

import boto3
import re
import cfnresponse
from botocore.client import ClientError

S3_CLIENT = boto3.client("s3")
S3_RESOURCE = boto3.resource("s3")

LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)
HELPER_BUCKET: str = os.environ.get("SRA_HELPER_BUCKET_NAME")
REGION: str = os.environ.get("AWS_REGION")


def query_for_s3_bucket():
    try:
        S3_RESOURCE.meta.client.head_bucket(Bucket=HELPER_BUCKET)
        return True
    except ClientError:
        return False


def create_helper_bucket():
    if REGION != "us-east-1":
        create_bucket = S3_CLIENT.create_bucket(
            ACL="private", Bucket=HELPER_BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION}, ObjectOwnership="BucketOwnerPreferred"
        )
    else:
        create_bucket = S3_CLIENT.create_bucket(ACL="private", Bucket=HELPER_BUCKET, ObjectOwnership="BucketOwnerPreferred")
    LOGGER.info(f"Bucket created: {create_bucket}")


def list_stacks(cfn_client):
    LOGGER.info("list_stacks function...")
    # 'CREATE_IN_PROGRESS'|'CREATE_FAILED'|'CREATE_COMPLETE'|'ROLLBACK_IN_PROGRESS'|'ROLLBACK_FAILED'|'ROLLBACK_COMPLETE'|'DELETE_IN_PROGRESS'|'DELETE_FAILED'|'DELETE_COMPLETE'|'UPDATE_IN_PROGRESS'|'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS'|'UPDATE_COMPLETE'|'UPDATE_FAILED'|'UPDATE_ROLLBACK_IN_PROGRESS'|'UPDATE_ROLLBACK_FAILED'|'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS'|'UPDATE_ROLLBACK_COMPLETE'|'REVIEW_IN_PROGRESS'|'IMPORT_IN_PROGRESS'|'IMPORT_COMPLETE'|'IMPORT_ROLLBACK_IN_PROGRESS'|'IMPORT_ROLLBACK_FAILED'|'IMPORT_ROLLBACK_COMPLETE',
    return cfn_client.list_stacks(
        StackStatusFilter=[
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_COMPLETE",
        ]
    )


def find_common_prerequisite_stack():
    LOGGER.info("find_common_prerequisite_stack function...")
    LOGGER.info("checking for helper bucket...")
    if query_for_s3_bucket() is False:
        LOGGER.info("helper bucket not found, creating...")
        create_helper_bucket()
    cfn_client = boto3.client("cloudformation")
    for stack in list_stacks(cfn_client)["StackSummaries"]:
        if (
            re.match(r".*common-prerequisites-main$", stack["StackName"])
            or re.match(r".*common-prerequisites-main-ssm$", stack["StackName"])
            or re.match(r".*CommonPrerequisitesMain-.{13}$", stack["StackName"])
            or re.match(r".*CommonPrerequisitesMainSsm-.{13}$", stack["StackName"])
        ):
            LOGGER.info(f"StackName: {stack['StackName']}| StackStatus: {stack['StackStatus']}")
            if re.match(r".*sra-1ssgnse2h.*", stack["TemplateDescription"]):
                return {
                    "sra-common-prerequisites-installed": "true",
                    "sra-common-prerequisite-stack-name": stack["StackName"],
                    "sra-common-prerequisite-stack-status": stack["StackStatus"],
                }
    return {
        "sra-common-prerequisites-installed": "false",
        "sra-common-prerequisite-stack-name": "no_stack",
        "sra-common-prerequisite-stack-status": "not_deployed",
    }


def create_event(event, context):
    data = find_common_prerequisite_stack()
    cfnresponse.send(event, context, cfnresponse.SUCCESS, data, "CheckForResourceID")
    return "CustomResourcePhysicalID"


def update_event(event, context):
    LOGGER.info("update event function")
    data = find_common_prerequisite_stack()
    cfnresponse.send(event, context, cfnresponse.SUCCESS, data, "CheckForResourceID")


def delete_event(event, context):
    LOGGER.info("delete event function")
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {"delete_operation": "succeeded deleting"}, "CheckForResourceID")


def lambda_handler(event, context):
    LOGGER.info(event)
    try:
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
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, "CheckForResourceID", reason=reason)
