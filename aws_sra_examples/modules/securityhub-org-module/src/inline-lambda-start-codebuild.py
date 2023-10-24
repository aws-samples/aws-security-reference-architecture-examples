# type: ignore
"""Custom Resource to start codebuild project.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging
import os

import boto3
import cfnresponse
import time
from botocore.exceptions import ClientError

LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "INFO")
LOGGER.setLevel(log_level)
CODE_BUILD_PROJECT_NAME: str = os.environ.get("CODE_BUILD_PROJECT_NAME")
SRA_CUSTOM_RESOURCE_NAME: str = os.environ.get("SRA_CUSTOM_RESOURCE_NAME")


def start_build():
    management_account_session = boto3.Session()
    codebuild_client = management_account_session.client("codebuild")
    response = codebuild_client.start_build(projectName=CODE_BUILD_PROJECT_NAME)
    LOGGER.info({"API_Call": "codebuild:StartBuild", "API_Response": response})
    buildId = response["build"]["id"]
    return wait_for_build([buildId], codebuild_client)


def wait_for_build(BuildId, client):
    buildWaitStatus = "FAILURE_WAIT_TIMEOUT"
    counter = 0
    while counter < 30:
        time.sleep(10)
        counter = counter + 1
        buildStatus = get_build_status(BuildId, client)
        if buildStatus == "SUCCEEDED":
            buildWaitStatus = "SUCCESS"
            break
        elif buildStatus == "FAILED" or buildStatus == "FAULT" or buildStatus == "STOPPED" or buildStatus == "TIMED_OUT":
            buildWaitStatus = "BUILD " + buildStatus + " (check codebuild project cloudwatch log group for details)"
            break
    return buildWaitStatus


def get_build_status(buildId, client):
    build = client.batch_get_builds(ids=buildId)
    return build["builds"][0]["buildStatus"]


def create_event(event, context):
    try:
        data = {"data": start_build()}
        if data["data"] == "SUCCESS":
            cfnresponse.send(event, context, cfnresponse.SUCCESS, data, SRA_CUSTOM_RESOURCE_NAME)
        else:
            reason = f"See the details in CloudWatch Log Stream: '{context.log_group_name} and CloudFormation Events'"
            cfnresponse.send(event, context, cfnresponse.FAILED, data, SRA_CUSTOM_RESOURCE_NAME)
    except Exception:
        LOGGER.exception("Unexpected!")
        reason = f"See the details in CloudWatch Log Stream: '{context.log_group_name}'"
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, SRA_CUSTOM_RESOURCE_NAME, reason=reason)
    return SRA_CUSTOM_RESOURCE_NAME


def delete_event(event, context):
    LOGGER.info("entered delete_event function.  Nothing to do...")
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, SRA_CUSTOM_RESOURCE_NAME)


def lambda_handler(event, context):
    LOGGER.info(event)
    if event["RequestType"] == "Create":
        LOGGER.info("CREATE EVENT!!")
        create_event(event, context)
    if event["RequestType"] == "Update":
        LOGGER.info("UPDATE EVENT!!")

    if event["RequestType"] == "Delete":
        LOGGER.info("DELETE EVENT!!")
        delete_event(event, context)
