########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
import logging
import os
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
helper = CfnResource(json_logging=False, log_level="INFO", boto_level="CRITICAL")

AWS_SERVICE_PRINCIPAL = "cloudtrail.amazonaws.com"
CLOUDFORMATION_PARAMETERS = ["AWS_PARTITION", "CLOUDTRAIL_NAME", "CLOUDWATCH_LOG_GROUP_ARN",
                             "CLOUDWATCH_LOG_GROUP_ROLE_ARN", "ENABLE_DATA_EVENTS_ONLY", "ENABLE_LAMBDA_DATA_EVENTS",
                             "ENABLE_S3_DATA_EVENTS", "KMS_KEY_ID", "S3_BUCKET_NAME", "S3_KEY_PREFIX", "TAG_KEY1",
                             "TAG_VALUE1"]

try:
    # Process Environment Variables
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")

    CLOUDTRAIL_CLIENT = boto3.client("cloudtrail")
except Exception as e:
    helper.init_failure(e)


def get_data_event_config(**params) -> dict:
    """
    Creates the CloudTrail event selectors configuration
    param: params: event parameters
    :return: event_selectors
    """

    if params["enable_data_events_only"]:
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

    if params["enable_s3_data_events"]:
        s3_data_resource = {
            "Type": "AWS::S3::Object",
            "Values": [f"arn:{params['aws_partition']}:s3:::"]
        }
        event_selectors["DataResources"].append(s3_data_resource)
        logger.info("S3 Data Events Added to Event Selectors")

    if params["enable_lambda_data_events"]:
        lambda_data_resource = {
            "Type": "AWS::Lambda::Function",
            "Values": [f"arn:{params['aws_partition']}:lambda"],
        }
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


def get_cloudtrail_parameters(is_create: bool, **params) -> dict:
    """
    Dynamically creates a parameter dict for the CloudTrail create_trail and update_trail API calls.
    :param is_create: True = create, False = update
    :param params: CloudTrail parameters
    :return: cloudtrail_params dict
    """
    cloudtrail_params = {
        "Name": params["cloudtrail_name"],
        "S3BucketName": params["s3_bucket_name"],
        "IncludeGlobalServiceEvents": True,
        "IsMultiRegionTrail": True,
        "EnableLogFileValidation": True,
        "KmsKeyId": params["kms_key_id"],
        "IsOrganizationTrail": True,
    }

    if is_create and params.get("tag_key1", "") and params.get("tag_value1", ""):
        cloudtrail_params["TagsList"] = [{"Key": params["tag_key1"], "Value": params["tag_value1"]}]

    if params.get("s3_key_prefix", ""):
        cloudtrail_params["S3KeyPrefix"] = params["s3_key_prefix"]

    if params.get("cloudwatch_log_group_arn", "") and params.get("cloudwatch_log_group_role_arn", ""):
        cloudtrail_params["CloudWatchLogsLogGroupArn"] = params["cloudwatch_log_group_arn"]
        cloudtrail_params["CloudWatchLogsRoleArn"] = params["cloudwatch_log_group_role_arn"]

    return cloudtrail_params


def check_parameters(event: dict):
    """
    Check event for required parameters in the ResourceProperties
    :param event:
    :return:
    """
    try:
        if "StackId" not in event or "ResourceProperties" not in event:
            raise ValueError("Invalid CloudFormation request, missing StackId or ResourceProperties.")

        # Check CloudFormation parameters
        for parameter in CLOUDFORMATION_PARAMETERS:
            if parameter not in event.get("ResourceProperties", ""):
                raise ValueError("Invalid CloudFormation request, missing one or more ResourceProperties.")

        logger.debug(f"Stack ID : {event.get('StackId')}")
        logger.debug(f"Stack Name : {event.get('StackId').split('/')[1]}")
    except Exception as error:
        logger.error(f"Exception checking parameters {error}")
        raise ValueError("Error checking parameters")


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
        check_parameters(event)
        params = event.get("ResourceProperties")
        enable_aws_service_access(AWS_SERVICE_PRINCIPAL)
        cloudtrail_name = params.get("CLOUDTRAIL_NAME")

        CLOUDTRAIL_CLIENT.create_trail(
            **get_cloudtrail_parameters(True,
                                        cloudtrail_name=cloudtrail_name,
                                        cloudwatch_log_group_arn=params.get("CLOUDWATCH_LOG_GROUP_ARN"),
                                        cloudwatch_log_group_role_arn=params.get("CLOUDWATCH_LOG_GROUP_ROLE_ARN"),
                                        kms_key_id=params.get("KMS_KEY_ID"),
                                        s3_bucket_name=params.get("S3_BUCKET_NAME"),
                                        s3_key_prefix=params.get("S3_KEY_PREFIX"),
                                        tag_key1=params.get("TAG_KEY1"),
                                        tag_value1=params.get("TAG_VALUE1")
                                        ))
        logger.info("Created an Organization CloudTrail")

        event_selectors = get_data_event_config(
            aws_partition=params.get("AWS_PARTITION", "aws"),
            enable_s3_data_events=(params.get("ENABLE_S3_DATA_EVENTS", "false")).lower() in "true",
            enable_lambda_data_events=(params.get("ENABLE_LAMBDA_DATA_EVENTS", "false")).lower() in "true",
            enable_data_events_only=(params.get("ENABLE_DATA_EVENTS_ONLY", "false")).lower() in "true"
        )

        if event_selectors and event_selectors["DataResources"]:

            CLOUDTRAIL_CLIENT.put_event_selectors(
                TrailName=cloudtrail_name,
                EventSelectors=[event_selectors]
            )

            logger.info("Data Events Enabled")

        CLOUDTRAIL_CLIENT.start_logging(Name=cloudtrail_name)
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
        check_parameters(event)
        params = event.get("ResourceProperties")
        cloudtrail_name = params.get("CLOUDTRAIL_NAME")
        CLOUDTRAIL_CLIENT.update_trail(
            **get_cloudtrail_parameters(False,
                                        cloudtrail_name=cloudtrail_name,
                                        cloudwatch_log_group_arn=params.get("CLOUDWATCH_LOG_GROUP_ARN"),
                                        cloudwatch_log_group_role_arn=params.get("CLOUDWATCH_LOG_GROUP_ROLE_ARN"),
                                        kms_key_id=params.get("KMS_KEY_ID"),
                                        s3_bucket_name=params.get("S3_BUCKET_NAME"),
                                        s3_key_prefix=params.get("S3_KEY_PREFIX"),
                                        tag_key1=params.get("TAG_KEY1"),
                                        tag_value1=params.get("TAG_VALUE1")
                                        )
        )
        logger.info("Updated Organization CloudTrail")

        event_selectors = get_data_event_config(
            aws_partition=params.get("AWS_PARTITION", "aws"),
            enable_s3_data_events=(params.get("ENABLE_S3_DATA_EVENTS", "false")).lower() in "true",
            enable_lambda_data_events=(params.get("ENABLE_LAMBDA_DATA_EVENTS", "false")).lower() in "true",
            enable_data_events_only=(params.get("ENABLE_DATA_EVENTS_ONLY", "false")).lower() in "true"
        )

        if event_selectors and event_selectors["DataResources"]:
            CLOUDTRAIL_CLIENT.put_event_selectors(
                TrailName=cloudtrail_name,
                EventSelectors=[event_selectors]
            )

            logger.info("Data Events Updated")

        CLOUDTRAIL_CLIENT.start_logging(Name=cloudtrail_name)
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
        check_parameters(event)
        params = event.get("ResourceProperties")
        CLOUDTRAIL_CLIENT.delete_trail(Name=params.get("CLOUDTRAIL_NAME"))
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
