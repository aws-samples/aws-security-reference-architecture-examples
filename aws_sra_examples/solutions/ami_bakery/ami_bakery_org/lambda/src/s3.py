"""This script performs operations to create and delete Amazon s3 bucket and policy, and enable bucket versioning.

Version: 1.0

'ami_bakery_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Literal

import boto3

if TYPE_CHECKING:
    from mypy_boto3_s3.client import S3Client
    from mypy_boto3_s3.service_resource import S3ServiceResource
    from mypy_boto3_s3.type_defs import DeleteObjectsOutputTypeDef, EmptyResponseMetadataTypeDef
LOGGER = logging.getLogger("sra")

log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)


def create_s3_bucket(
    session: boto3.Session,
    bucket_name: str,
    region: Literal[  # noqa: TAE003
        "EU",
        "af-south-1",
        "ap-east-1",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ca-central-1",
        "cn-north-1",
        "cn-northwest-1",
        "eu-central-1",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "me-south-1",
        "sa-east-1",
        "us-east-2",
        "us-gov-east-1",
        "us-gov-west-1",
        "us-west-1",
        "us-west-2",
    ],
) -> None:
    """Create S3 bucket for storing the EC2 ImageBuilder CloudFormation file.

    Args:
        session: boto3 session used by boto3 API calls
        bucket_name: Name of the s3 bucket to be created
        region: Region for the ami bakery to be deployed
    """
    s3_client: S3Client = session.client("s3")
    LOGGER.info("Creating bucket %s.", bucket_name)
    if "us-east-1" not in region:
        create_bucket = s3_client.create_bucket(
            ACL="private", Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}, ObjectOwnership="BucketOwnerPreferred"
        )
    else:
        create_bucket = s3_client.create_bucket(ACL="private", Bucket=bucket_name, ObjectOwnership="BucketOwnerPreferred")
    LOGGER.info(f"Bucket created: {create_bucket}")


def enable_bucket_versioning(session: boto3.Session, bucket_name: str) -> EmptyResponseMetadataTypeDef:
    """Enable versioning to S3 bucket.

    Args:
        session: boto3 session used by boto3 API calls
        bucket_name: Name of the s3 bucket to be created

    Returns:
        Empty response metadata
    """
    s3_client: S3Client = session.client("s3")
    LOGGER.info("Enabling bucket versioning to S3 Bucket %s.", bucket_name)
    return s3_client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})


def add_bucket_policy(session: boto3.Session, bucket_name: str, bucket_policy: str) -> EmptyResponseMetadataTypeDef:
    """Create s3 bucket policy to restrict access to S3 for only codepipeline and lambda services.

    Args:
        session: boto3 session used by boto3 API calls
        bucket_name: Name of the bucket for policy to be applied
        bucket_policy: Bucket policy to be attached

    Returns:
        Empty response metadata
    """
    s3_client: S3Client = session.client("s3")
    LOGGER.info("Creating and attaching bucket policy to S3 Bucket %s.", bucket_name)
    return s3_client.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)


def delete_s3_bucket_policy(session: boto3.Session, bucket_name: str) -> EmptyResponseMetadataTypeDef:
    """Delete s3 bucket policy.

    Args:
        session: boto3 session used by boto3 API calls
        bucket_name: Name of the bucket for policy to be deleted

    Returns:
        Empty response metadata
    """
    s3_client: S3Client = session.client("s3")
    LOGGER.info("Deleting S3 bucket policy from %s.", bucket_name)
    return s3_client.delete_bucket_policy(Bucket=bucket_name)


def delete_objects_from_s3(session: boto3.Session, bucket_name: str) -> list[DeleteObjectsOutputTypeDef]:
    """Delete all files objects from S3 bucket.

    Args:
        session: boto3 session used by boto3 API calls
        bucket_name: Name of the s3 bucket where the file is to be uploaded

    Returns:
        List of DeleteObject output
    """
    s3_resource: S3ServiceResource = session.resource("s3")
    bucket = s3_resource.Bucket(bucket_name)
    LOGGER.info("Deleting all objects from %s.", (bucket_name))
    return bucket.object_versions.all().delete()


def delete_s3_bucket(session: boto3.Session, bucket_name: str) -> EmptyResponseMetadataTypeDef:
    """Delete S3 bucket.

    Args:
        session: boto3 session used by boto3 API calls
        bucket_name: Name of the s3 bucket to be created

    Returns:
        Empty response metadata
    """
    s3_client: S3Client = session.client("s3")
    LOGGER.info("Deleting bucket %s.", bucket_name)
    return s3_client.delete_bucket(Bucket=bucket_name)
