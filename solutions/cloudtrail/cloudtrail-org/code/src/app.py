########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
from __future__ import print_function
import logging
import os
import re
import boto3
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

"""
The purpose of this script is to create and configure an Organization CloudTrail.
"""

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level="CRITICAL")

AWS_SERVICE_PRINCIPAL = "cloudtrail.amazonaws.com"

try:
    # Process Environment Variables
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

    # Required variables
    cloudtrail_regex = "^[A-Za-z0-9][a-zA-Z0-9-\\-_.]{2,127}$"
    CLOUDTRAIL_NAME = os.environ.get("CLOUDTRAIL_NAME", "")
    if not CLOUDTRAIL_NAME or not re.match(cloudtrail_regex, CLOUDTRAIL_NAME):
        raise ValueError("Missing or Invalid CloudTrail Name")

    S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME", "")
    bucket_regex = "^[a-zA-Z0-9-\\-_.]{2,62}$"
    if not S3_BUCKET_NAME or not re.match(bucket_regex, S3_BUCKET_NAME):
        raise ValueError("Missing or Invalid S3 Bucket Name")

    KMS_KEY_ID = os.environ.get("KMS_KEY_ID", "")
    if not KMS_KEY_ID:
        raise ValueError("Missing KMS Key ID ARN")

    ENABLE_S3_DATA_EVENTS = (os.environ.get("ENABLE_S3_DATA_EVENTS", "false")).lower() in "true"
    ENABLE_LAMBDA_DATA_EVENTS = (os.environ.get("ENABLE_LAMBDA_DATA_EVENTS", "false")).lower() in "true"
    ENABLE_DATA_EVENTS_ONLY = (os.environ.get("ENABLE_DATA_EVENTS_ONLY", "false")).lower() in "true"

    # Optional Variables
    S3_KEY_PREFIX = os.environ.get("S3_KEY_PREFIX", "")
    CLOUDWATCH_LOG_GROUP_ARN = os.environ.get("CLOUDWATCH_LOG_GROUP_ARN", "")
    CLOUDWATCH_LOG_GROUP_ROLE_ARN = os.environ.get("CLOUDWATCH_LOG_GROUP_ROLE_ARN", "")
    TAG_KEY1 = os.environ.get("TAG_KEY1", "")
    TAG_VALUE1 = os.environ.get("TAG_VALUE1", "")

    cloudtrail = boto3.client("cloudtrail")
except Exception as e:
    helper.init_failure(e)


def get_data_event_config() -> dict:
    """
    Creates the CloudTrail event selectors configuration
    :return: event_selectors
    """

    if ENABLE_DATA_EVENTS_ONLY:
        event_selectors = {
            "ReadWriteType": "All",
            "IncludeManagementEvents": False,
            "DataResources": [],
        }
    else:
        event_selectors = {
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [],
        }

    s3_data_resource = {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]}

    lambda_data_resource = {
        "Type": "AWS::Lambda::Function",
        "Values": ["arn:aws:lambda"],
    }

    if ENABLE_S3_DATA_EVENTS:
        event_selectors["DataResources"].append(s3_data_resource)
        logger.info("S3 Data Events Added to Event Selectors")

    if ENABLE_LAMBDA_DATA_EVENTS:
        event_selectors["DataResources"].append(lambda_data_resource)
        logger.info("Lambda Data Events Added to Event Selectors")

    return event_selectors


def enable_aws_service_access(service_principal: str):
    """
    Enables the AWS Service Access for the provided service principal
    :param service_principal: AWS Service Principal format: service_name.amazonaws.com
    :return: None
    """
    logger.info("Enable AWS Service Access for: " + str(service_principal))

    try:
        organizations = boto3.client("organizations")
        organizations.enable_aws_service_access(ServicePrincipal=service_principal)
    except ClientError as ce:
        logger.error(f"Client Error: {str(ce)}")
        raise
    except Exception as exc:
        logger.error(f"Exception: {str(exc)}")
        raise


def get_cloudtrail_parameters(is_create) -> dict:
    """
    Dynamically creates a parameter dict for the CloudTrail create_trail and update_trail API calls.
    :param is_create: True = create, False = update
    :return: cloudtrail_params dict
    """
    cloudtrail_params = {
        "Name": CLOUDTRAIL_NAME,
        "S3BucketName": S3_BUCKET_NAME,
        "IncludeGlobalServiceEvents": True,
        "IsMultiRegionTrail": True,
        "EnableLogFileValidation": True,
        "KmsKeyId": KMS_KEY_ID,
        "IsOrganizationTrail": True,
    }

    if is_create and TAG_KEY1 and TAG_VALUE1:
        cloudtrail_params["TagsList"] = [{"Key": TAG_KEY1, "Value": TAG_VALUE1}]

    if S3_KEY_PREFIX:
        cloudtrail_params["S3KeyPrefix"] = S3_KEY_PREFIX

    if CLOUDWATCH_LOG_GROUP_ARN and CLOUDWATCH_LOG_GROUP_ROLE_ARN:
        cloudtrail_params["CloudWatchLogsLogGroupArn"] = CLOUDWATCH_LOG_GROUP_ARN
        cloudtrail_params["CloudWatchLogsRoleArn"] = CLOUDWATCH_LOG_GROUP_ROLE_ARN

    return cloudtrail_params


@helper.create
def create(event, context) -> str:
    """
    CloudFormation Create Event. Creates a CloudTrail with the provided parameters
    :param event: event data
    :param context: runtime information
    :return: OrganizationTrailResourceId
    """
    logger.info("Create Event")
    try:
        enable_aws_service_access(AWS_SERVICE_PRINCIPAL)

        cloudtrail.create_trail(**get_cloudtrail_parameters(True))
        logger.info("Created an Organization CloudTrail")

        event_selectors = get_data_event_config()

        if event_selectors and event_selectors["DataResources"]:

            cloudtrail.put_event_selectors(
                TrailName=CLOUDTRAIL_NAME, EventSelectors=[event_selectors]
            )

            logger.info("Data Events Enabled")

        cloudtrail.start_logging(Name=CLOUDTRAIL_NAME)
    except ClientError as ce:
        logger.error(f"Unexpected error: {str(ce)}")
        raise ValueError(f"CloudTrail API Exception: {str(ce)}")
    except Exception as exc:
        logger.error(f"Unexpected error: {str(exc)}")
        raise ValueError(f"Exception: {str(exc)}")

    return "OrganizationTrailResourceId"


@helper.update
def update(event, context):
    """
    CloudFormation Update Event. Updates CloudTrail with the provided parameters.
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("Update Event")

    try:
        cloudtrail.update_trail(**get_cloudtrail_parameters(False))
        logger.info("Updated Organization CloudTrail")

        event_selectors = get_data_event_config()

        if event_selectors and event_selectors["DataResources"]:
            cloudtrail.put_event_selectors(
                TrailName=CLOUDTRAIL_NAME, EventSelectors=[event_selectors]
            )

            logger.info("Data Events Updated")
    except ClientError as ce:
        if ce.response["Error"]["Code"] == "TrailNotFoundException":
            logger.error("Trail Does Not Exist")
            raise ValueError(f"TrailNotFoundException: {str(ce)}")
        else:
            logger.error(f"Unexpected error: {str(ce)}")
            raise ValueError(f"CloudTrail API Exception: {str(ce)}")
    except Exception as exc:
        logger.error(f"Unexpected error: {str(exc)}")
        raise ValueError(f"Exception: {str(exc)}")


@helper.delete
def delete(event, context):
    """
    CloudFormation Delete Event. Deletes the provided CloudTrail
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("Delete Event")
    try:
        cloudtrail.delete_trail(Name=CLOUDTRAIL_NAME)
    except ClientError as ce:
        if ce.response["Error"]["Code"] == "TrailNotFoundException":
            logger.error(f"Trail Does Not Exist {str(ce)}")
            raise ValueError(f"TrailNotFoundException: {str(ce)}")
        else:
            logger.error(f"Unexpected error: {str(ce)}")
            raise ValueError(f"CloudTrail API Exception: {str(ce)}")
    except Exception as exc:
        logger.error(f"Unexpected error: {str(exc)}")
        raise ValueError(f"Exception: {str(exc)}")

    logger.info("Deleted the Organizations CloudTrail")


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info("....Lambda Handler Started....")
    helper(event, context)
