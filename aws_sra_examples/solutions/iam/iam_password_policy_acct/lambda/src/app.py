#!/usr/bin/python
########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
"""
Create or Update password policy on an account

Event:

RequestType: [ Delete | Create | Update ]
ResourceProperties:
    AllowUsersToChangePassword: [ True | False ]
    HardExpiry: [ True | False ]
    MaxPasswordAge: int default: 0
    PasswordReusePrevention: int default: 0
    MinimumPasswordLength: int (no default)
    RequireLowerCaseCharacters: [ True | False ]
    RequireNumbers: [ True | False ]
    RequireSymbols: [ True | False ]
    RequireUppercaseCharacters [ True | False ]


Response:
    cfn_handler is called, passing the create and update function
    objects. cfn_handler takes care of sending the response to the Cloud-
    Formation stack.
"""
import boto3
import logging
import os
from ast import literal_eval
from botocore.client import Config
from botocore.exceptions import ClientError
from crhelper import CfnResource

# Setup Default Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level="DEBUG", boto_level='CRITICAL')

CLOUDFORMATION_PARAMETERS = ["AllowUsersToChangePassword", "HardExpiry", "MaxPasswordAge",
                             "MinimumPasswordLength", "PasswordReusePrevention",
                             "RequireLowercaseCharacters", "RequireNumbers", "RequireSymbols",
                             "RequireUppercaseCharacters"]

config = Config(retries={"max_attempts": 4})
IAM_CLIENT = boto3.client("iam", config=config)


try:
    # Environment Variables
    if "LOG_LEVEL" in os.environ:
        LOG_LEVEL = os.environ.get("LOG_LEVEL")
        if isinstance(LOG_LEVEL, str):
            log_level = logging.getLevelName(LOG_LEVEL.upper())
            logger.setLevel(log_level)
        else:
            raise ValueError("LOG_LEVEL parameter is not a string")
except Exception as e:
    logger.error(f"{e}")
    helper.init_failure(e)


def check_parameters(event: dict):
    """
    Check event for required parameters in the ResourceProperties
    :param event:
    :return: None
    """
    try:
        if "StackId" not in event or "ResourceProperties" not in event:
            raise ValueError("Invalid CloudFormation request, missing StackId or ResourceProperties.")

        # Check CloudFormation parameters
        for parameter in CLOUDFORMATION_PARAMETERS:
            if parameter not in event.get("ResourceProperties", {}):
                raise ValueError("Invalid CloudFormation request, missing one or more ResourceProperties.")

        logger.debug(f"Stack ID : {event.get('StackId')}")
        logger.debug(f"Stack Name : {event.get('StackId').split('/')[1]}")
    except Exception as error:
        logger.error(f"Exception checking parameters {error}")
        raise ValueError("Error checking parameters")


@helper.create
@helper.update
def create(event, _):
    """
    CloudFormation Create or Update.
    :param event: event data
    :param _:
    :return: ResourceId
    """
    request_type = event.get("RequestType", "Create")
    logger.info(f"{request_type} Event")

    try:
        check_parameters(event)
        params = event.get("ResourceProperties", {})

        IAM_CLIENT.update_account_password_policy(
            AllowUsersToChangePassword=literal_eval(params.get('AllowUsersToChangePassword', 'True').title()),
            HardExpiry=literal_eval(params.get('HardExpiry', 'False').title()),
            MaxPasswordAge=int(params.get('MaxPasswordAge', 90)),
            MinimumPasswordLength=int(params.get('MinimumPasswordLength', 14)),
            PasswordReusePrevention=int(params.get('PasswordReusePrevention', 24)),
            RequireLowercaseCharacters=literal_eval(params.get('RequireLowercaseCharacters', 'True').title()),
            RequireNumbers=literal_eval(params.get('RequireNumbers', 'True').title()),
            RequireSymbols=literal_eval(params.get('RequireSymbols', 'True').title()),
            RequireUppercaseCharacters=literal_eval(params.get('RequireUppercaseCharacters', 'True').title())
        )
    except ClientError as exc:
        logger.error(f"update_account_password_policy encountered an exception: {exc}")
        raise exc

    if event.get("RequestType", "Create") == "Create":
        return "PasswordPolicyResourceId"


def lambda_handler(event, context):
    """
    Lambda Handler
    :param event: event data
    :param context: runtime information
    :return: CloudFormation response
    """
    logger.info(f"Event: {event}")
    helper(event, context)
