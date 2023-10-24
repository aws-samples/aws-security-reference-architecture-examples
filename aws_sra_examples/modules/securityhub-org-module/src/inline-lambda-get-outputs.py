# type: ignore
"""Retrieves the outputs from the SRA common prerequisite parameter stack.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging
import os

import boto3
import re
import cfnresponse
from botocore.client import ClientError

LOGGER = logging.getLogger(__name__)
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)
REGION: str = os.environ.get("AWS_REGION")


def list_stacks(cfn_client):
    LOGGER.info("list_stacks function...")
    return cfn_client.list_stacks(
        StackStatusFilter=[
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_COMPLETE",
        ]
    )


def find_common_prerequisite_stack_outputs():
    LOGGER.info("find_common_prerequisite_stack_outputs function...")
    cfn_client = boto3.client("cloudformation")
    data = {}
    for stack in list_stacks(cfn_client)["StackSummaries"]:
        if (
            re.match(r".*sra-common-prerequisites-management-account-parameters.*$", stack["StackName"])
            or re.match(r".*rCommonPrerequisitesManagementAccountParam.*$", stack["StackName"])
            or re.match(r".*sra-common-prerequisites-staging-s3-bucket.*$", stack["StackName"])
        ):
            print(f"StackName: {stack['StackName']}| StackStatus: {stack['StackStatus']}")
            describe_stack_response = cfn_client.describe_stacks(
                StackName=stack['StackName']
            )
            for stack in describe_stack_response['Stacks']:
                 for output in stack['Outputs']:
                    data[output['OutputKey']] = output['OutputValue']
    return data


def create_event(event, context):
    data = find_common_prerequisite_stack_outputs()
    cfnresponse.send(event, context, cfnresponse.SUCCESS, data, "RetrieveCommonOutputsID")
    return "RetrieveCommonOutputsID"


def update_event(event, context):
    LOGGER.info("update event function")
    data = find_common_prerequisite_stack_outputs()
    cfnresponse.send(event, context, cfnresponse.SUCCESS, data, "RetrieveCommonOutputsID")
    return "RetrieveCommonOutputsID"

def delete_event(event, context):
    LOGGER.info("delete event function")
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {"delete_operation": "succeeded deleting"}, "RetrieveCommonOutputsID")
    return "RetrieveCommonOutputsID"


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
        else:
            LOGGER.info("Not a CFN event, running lambda...")
            data = find_common_prerequisite_stack_outputs()
            return data
        
    except Exception:
        LOGGER.exception("Unexpected!")
        reason = f"See the details in CloudWatch Log Stream: '{context.log_group_name}'"
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, "RetrieveCommonOutputsID", reason=reason)
