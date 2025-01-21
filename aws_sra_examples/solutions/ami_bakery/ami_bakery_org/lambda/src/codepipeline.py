"""This script performs operations to create and delete CodeCommit Repository and CodePipeline pipeline.

Version: 1.0

'ami_bakery_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

import boto3

if TYPE_CHECKING:
    from mypy_boto3_codecommit.client import CodeCommitClient
    from mypy_boto3_codecommit.type_defs import CreateRepositoryOutputTypeDef, DeleteRepositoryOutputTypeDef, PutFileOutputTypeDef
    from mypy_boto3_codepipeline.client import CodePipelineClient
    from mypy_boto3_codepipeline.type_defs import CreatePipelineOutputTypeDef, EmptyResponseMetadataTypeDef, PipelineDeclarationTypeDef

LOGGER = logging.getLogger("sra")

log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)


def create_repo(session: boto3.Session, repo_name: str, description: str) -> CreateRepositoryOutputTypeDef:
    """Create a CodeCommit repository for storing EC2 Image Builder template file.

    Args:
        session: session: boto3 session used by boto3 API calls
        repo_name: Name for the CodeCommit repository to be created
        description: Description for the repo

    Returns:
        Dictionary of the create repository output
    """
    codecommit_client: CodeCommitClient = session.client("codecommit")
    LOGGER.info("Creating CodeCommit repo %s.", repo_name)
    return codecommit_client.create_repository(repositoryName=repo_name, repositoryDescription=description)


def add_file_to_repo(session: boto3.Session, repo_name: str, branch_name: str, file_name: str) -> PutFileOutputTypeDef:
    """Store an EC2 Image Builder template file to repo.

    Args:
        session: session: boto3 session used by boto3 API calls
        repo_name: Name of the CodeCommit repository where you want to add or update the file
        branch_name: Name of the branch where you want to add or update the file
        file_name: CloudFormation file template

    Returns:
        Dictionary of the PutFile output
    """
    codecommit_client: CodeCommitClient = session.client("codecommit")
    LOGGER.info("Adding a file to CodeCommit repo %s.", file_name)
    with Path(file_name).open() as file_content:
        return codecommit_client.put_file(repositoryName=repo_name, branchName=branch_name, fileContent=file_content.read(), filePath=file_name)


def create_codepipeline(
    session: boto3.Session, bucket_name: str, file_name: str, pipeline_name: str, repo_name: str, stack_name: str, params: dict
) -> CreatePipelineOutputTypeDef:
    """Create a CodePipeline service.

    Args:
        session: boto3 session used by boto3 API calls
        bucket_name: Name of the s3 bucket where CloudFormation file is stored
        file_name: File CloudFormation file template to retrieve from the repo
        pipeline_name: Name of the CodePipeline's pipeline to be created
        repo_name: Name of the CodeCommit repository where you want to add or update the file
        stack_name: Name of the CloudFormation stack used to create AMI Bakery resources
        params: Configuration parameters to be called during the pipeline creation

    Returns:
        CodePipeline client
    """
    codepipeline_client: CodePipelineClient = session.client("codepipeline")
    LOGGER.info("Creating CodePipeline.")
    account_id: str = params["AMI_BAKERY_ACCOUNT_ID"]
    codepipeline_role_name: str = params["CODEPIPELINE_ROLE_NAME"]
    aws_partition: str = params["AWS_PARTITION"]
    cloudformation_role_name: str = params["CLOUDFORMATION_ROLE_NAME"]
    pipeline: PipelineDeclarationTypeDef = {  # noqa: ECE001
        "name": pipeline_name,
        "roleArn": "arn:" + aws_partition + ":iam::" + account_id + ":role/" + codepipeline_role_name,
        "artifactStore": {"type": "S3", "location": bucket_name},
        "stages": [
            {  # type: ignore
                "name": pipeline_name + "-CodeCommitSource",
                "actions": [
                    {
                        "name": "CodeCommitSource",
                        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "CodeCommit", "version": "1"},
                        "runOrder": 1,
                        "configuration": {"PollForSourceChanges": "false", "BranchName": "main", "RepositoryName": repo_name},
                        "outputArtifacts": [
                            {"name": "CodeCommitSource"},
                        ],
                    }
                ],
            },
            {  # type: ignore
                "name": pipeline_name + "-DeployEC2ImageBuilder",
                "actions": [
                    {
                        "name": "CreateStack",
                        "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "CloudFormation", "version": "1"},
                        "runOrder": 1,
                        "configuration": {
                            "ActionMode": "REPLACE_ON_FAILURE",
                            "RoleArn": "arn:" + aws_partition + ":iam::" + account_id + ":role/" + cloudformation_role_name,
                            "StackName": stack_name,
                            "TemplatePath": "CodeCommitSource::" + file_name,
                            "Capabilities": "CAPABILITY_NAMED_IAM",
                        },
                        "inputArtifacts": [
                            {"name": "CodeCommitSource"},
                        ],
                    }
                ],
            },
        ],
        "version": 1,
    }
    return codepipeline_client.create_pipeline(pipeline=pipeline)


def delete_codepipeline(session: boto3.Session, pipeline_name: str) -> EmptyResponseMetadataTypeDef:
    """Delete a CodePipeline service.

    Args:
        session: boto3 session used by boto3 API calls
        pipeline_name: Name of the CodePipeline

    Returns:
        CodePipeline client
    """
    codepipeline_client: CodePipelineClient = session.client("codepipeline")
    LOGGER.info("Deleting Codepipeline %s .", pipeline_name)
    return codepipeline_client.delete_pipeline(name=pipeline_name)


def delete_repo(session: boto3.Session, repo_name: str) -> DeleteRepositoryOutputTypeDef:
    """Delete a CodeCommit repository used for storing EC2 Image Builder template file.

    Args:
        session: session: boto3 session used by boto3 API calls
        repo_name: Name for the repository to be deleted

    Returns:
        Dictionary of the DeleteRepository output
    """
    codecommit_client: CodeCommitClient = session.client("codecommit")
    LOGGER.info("Deleting CodeCommit repo %s.", repo_name)
    return codecommit_client.delete_repository(
        repositoryName=repo_name,
    )
