"""This script performs operations to create, and delete ami-bakery-org solution.

Version: 1.0

'ami_bakery_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from time import sleep
from typing import TYPE_CHECKING, Any, Dict

import boto3
import codepipeline
import common
import iam
import s3
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context


LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

UNEXPECTED = "Unexpected!"
SERVICE_NAME = "imagebuilder.amazonaws.com"
IAM_RESOURCE_WAIT_TIME = 10

helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)


def get_validated_parameters() -> dict:  # noqa: CFQ001
    """Validate AWS CloudFormation parameters.

    Returns:
        Validated configuration parameters
    """
    params = {}
    allowed_patterns = r"^[\w+=,.@-]{1,64}$"
    # Required Parameters
    params.update(
        common.parameter_pattern_validator(
            "AWS_PARTITION",
            os.environ.get("AWS_PARTITION"),
            pattern=r"^(aws[a-zA-Z-]*)?$",
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "AMI_BAKERY_ACCOUNT_ID",
            os.environ.get("AMI_BAKERY_ACCOUNT_ID"),
            pattern=r"^\d{12}$",
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "AMI_BAKERY_REGION",
            os.environ.get("AMI_BAKERY_REGION"),
            pattern=r"^$|^([a-z0-9-]{1,64})$|^(([a-z0-9-]{1,64},)*[a-z0-9-]{1,64})$",
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "BUCKET_NAME",
            os.environ.get("BUCKET_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "BRANCH_NAME",
            os.environ.get("BRANCH_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "CONFIGURATION_ROLE_NAME",
            os.environ.get("CONFIGURATION_ROLE_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "CODEPIPELINE_POLICY_NAME",
            os.environ.get("CODEPIPELINE_POLICY_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "CLOUDFORMATION_POLICY_NAME",
            os.environ.get("CLOUDFORMATION_POLICY_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "CODEPIPELINE_ROLE_NAME",
            os.environ.get("CODEPIPELINE_ROLE_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "CLOUDFORMATION_ROLE_NAME",
            os.environ.get("CLOUDFORMATION_ROLE_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "IMAGEBUILDER_ROLE_NAME",
            os.environ.get("IMAGEBUILDER_ROLE_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "LIFECYCLE_ROLE_NAME",
            os.environ.get("LIFECYCLE_ROLE_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "FILE_NAME",
            os.environ.get("FILE_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "PIPELINE_NAME",
            os.environ.get("PIPELINE_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "REPO_DESCRIPTION",
            os.environ.get("REPO_DESCRIPTION"),
            pattern=r"^[\w+=,.@ +-]{1,200}$",
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "REPO_NAME",
            os.environ.get("REPO_NAME"),
            pattern=allowed_patterns,
        )
    )
    params.update(
        common.parameter_pattern_validator(
            "STACK_NAME",
            os.environ.get("STACK_NAME"),
            pattern=allowed_patterns,
        )
    )
    return params


def get_params() -> Dict:
    """Get Configuration parameters.

    Returns:
        Configuration parameters
    """
    params = get_validated_parameters()
    params["account_place_holder"] = "ACCOUNT_ID"
    params["bucket_place_holder"] = "BUCKET_NAME"
    params["region_place_holder"] = "REGION"
    params["repo_place_holder"] = "REPO_NAME"
    params["cfn_role_place_holder"] = "CLOUDFORMATION_ROLE_NAME"
    params["stack_name_placeholder"] = "STACK_NAME"
    params["imagebuilder_role_place_holder"] = "IMAGEBUILDER_ROLE_NAME"
    params["lifecycle_role_place_holder"] = "LIFECYCLE_ROLE_NAME"

    with Path("cp_trust_relationship.json").open() as codepipeline_trust_file:
        params["cp_trust_policy"] = json.load(codepipeline_trust_file)

    with Path("cfn_trust_relationship.json").open() as cloudformation_trust_file:
        params["cfn_trust_policy"] = json.load(cloudformation_trust_file)

    params["cp_policy_arn"] = (
        "arn:" + params["AWS_PARTITION"] + ":iam::" + params["AMI_BAKERY_ACCOUNT_ID"] + ":policy/" + params["CODEPIPELINE_POLICY_NAME"]
    )
    params["cfn_policy_arn"] = (
        "arn:" + params["AWS_PARTITION"] + ":iam::" + params["AMI_BAKERY_ACCOUNT_ID"] + ":policy/" + params["CLOUDFORMATION_POLICY_NAME"]
    )
    with Path("s3_bucket_policy.json").open() as bucket_policy_file:
        params["s3_bucket_policy_document"] = json.load(bucket_policy_file)
    params["bucket_policy"] = json.dumps(params["s3_bucket_policy_document"]).replace(params["bucket_place_holder"], params["BUCKET_NAME"])

    with Path("codepipeline_policy.json").open() as codepipeline_policy_file:
        params["cp_policy_document"] = json.load(codepipeline_policy_file)
    params["codepipeline_policy"] = (  # noqa: ECE001
        json.dumps(params["cp_policy_document"])
        .replace(params["account_place_holder"], params["AMI_BAKERY_ACCOUNT_ID"])
        .replace(params["bucket_place_holder"], params["BUCKET_NAME"])
        .replace(params["region_place_holder"], params["AMI_BAKERY_REGION"])
        .replace(params["repo_place_holder"], params["REPO_NAME"])
        .replace(params["cfn_role_place_holder"], params["CLOUDFORMATION_ROLE_NAME"])
        .replace(params["stack_name_placeholder"], params["STACK_NAME"])
    )
    with Path("cloudformation_policy.json").open() as cloudformation_policy_file:
        params["cfn_policy_document"] = json.load(cloudformation_policy_file)
    params["cloudformation_policy"] = (  # noqa: ECE001
        json.dumps(params["cfn_policy_document"])
        .replace(params["account_place_holder"], params["AMI_BAKERY_ACCOUNT_ID"])
        .replace(params["region_place_holder"], params["AMI_BAKERY_REGION"])
        .replace(params["repo_place_holder"], params["REPO_NAME"])
        .replace(params["imagebuilder_role_place_holder"], params["IMAGEBUILDER_ROLE_NAME"])
        .replace(params["lifecycle_role_place_holder"], params["LIFECYCLE_ROLE_NAME"])
    )
    return params


def get_session(params: Dict) -> boto3.Session:
    """Get boto3 Session.

    Args:
        params: The configuration parameters

    Returns:
        Session object for the specified AWS account
    """
    return common.assume_role(params.get("CONFIGURATION_ROLE_NAME", ""), "create-ami-bakery", params.get("AMI_BAKERY_ACCOUNT_ID", ""))


@helper.create
def create(event: Dict[str, Any], context: Context) -> None:  # noqa: U100
    """Create an S3 bucket, enable bucket Versioning, upload a file to that bucket, create IAM Roles/Policies, CodeCommit Repository and CodePipeline.

    Args:
        event: event data
        context: runtime information
    """
    LOGGER.info("Creating sra-ami-bakery-org started...")
    params = get_params()
    session = get_session(params)
    s3.create_s3_bucket(session, params["BUCKET_NAME"], params["AMI_BAKERY_REGION"])
    s3.enable_bucket_versioning(session, params["BUCKET_NAME"])
    s3.add_bucket_policy(session, params["BUCKET_NAME"], params["bucket_policy"])
    iam.create_role(session, params["CODEPIPELINE_ROLE_NAME"], params["cp_trust_policy"])
    iam.create_role(session, params["CLOUDFORMATION_ROLE_NAME"], params["cfn_trust_policy"])
    iam.create_policy(session, params["CODEPIPELINE_POLICY_NAME"], params["codepipeline_policy"])
    iam.create_policy(session, params["CLOUDFORMATION_POLICY_NAME"], params["cloudformation_policy"])
    iam.attach_policy(session, params["CODEPIPELINE_ROLE_NAME"], params["CODEPIPELINE_POLICY_NAME"], params["codepipeline_policy"])
    iam.attach_policy(session, params["CLOUDFORMATION_ROLE_NAME"], params["CLOUDFORMATION_POLICY_NAME"], params["cloudformation_policy"])
    sleep(IAM_RESOURCE_WAIT_TIME)  # Pause for IAM resources to be created and be ready for use
    codepipeline.create_repo(session, params["REPO_NAME"], params["REPO_DESCRIPTION"])
    codepipeline.add_file_to_repo(session, params["REPO_NAME"], params["BRANCH_NAME"], params["FILE_NAME"])
    codepipeline.create_codepipeline(
        session, params["BUCKET_NAME"], params["FILE_NAME"], params["PIPELINE_NAME"], params["REPO_NAME"], params["STACK_NAME"], params
    )


@helper.update
def update(event: Dict[str, Any], context: Context) -> None:  # noqa: U100
    """Update function - currently unsupported.

    Args:
        event: event data
        context: runtime information
    """
    LOGGER.info("Updates are not supported!!")


@helper.delete
def delete(event: Dict[str, Any], context: Context) -> None:  # noqa: U100
    """Opposite of create().

    Args:
        event: event data
        context: runtime information
    """
    LOGGER.info("Deleting sra-ami-bakery-org started...")
    params = get_params()
    session = get_session(params)
    codepipeline.delete_repo(session, params["REPO_NAME"])
    codepipeline.delete_codepipeline(session, params["PIPELINE_NAME"])
    s3.delete_objects_from_s3(session, params["BUCKET_NAME"])
    s3.delete_s3_bucket_policy(session, params["BUCKET_NAME"])
    s3.delete_s3_bucket(session, params["BUCKET_NAME"])
    iam.detach_policy(session, params["CODEPIPELINE_ROLE_NAME"], params["CODEPIPELINE_POLICY_NAME"])
    iam.delete_policy(session, params["cp_policy_arn"])
    iam.delete_policy(session, params["cfn_policy_arn"])
    iam.delete_role(session, params["CODEPIPELINE_ROLE_NAME"])


def lambda_handler(event: Dict[str, Any], context: Context) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information
    """
    helper(event, context)
