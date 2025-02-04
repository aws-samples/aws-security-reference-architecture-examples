"""Lambda python module to setup SRA S3 resources in the organization.

Version: 1.0

S3 module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging
import os

import boto3
from botocore.client import ClientError


class SRAS3:
    """Class to setup SRA S3 resources in the organization."""

    S3_CLIENT = boto3.client("s3")
    S3_RESOURCE = boto3.resource("s3")

    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    REGION: str = os.environ.get("AWS_REGION", "us-east-1")
    ORG_ID: str = boto3.client("organizations").describe_organization()["Organization"]["Id"]
    PARTITION = boto3.session.Session().get_partition_for_region(REGION)
    STAGING_BUCKET: str = ""
    BUCKET_POLICY_TEMPLATE: dict = {  # noqa: ECE001
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDeploymentRoleGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:" + PARTITION + ":s3:::BUCKET_NAME/*",
                "Condition": {
                    "ArnLike": {
                        "aws:PrincipalArn": [
                            "arn:" + PARTITION + ":iam::*:role/AWSControlTowerExecution",
                            "arn:" + PARTITION + ":iam::*:role/stacksets-exec-*",
                        ]
                    }
                },
            },
            {
                "Sid": "DenyExternalPrincipals",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:" + PARTITION + ":s3:::BUCKET_NAME", "arn:" + PARTITION + ":s3:::BUCKET_NAME/*"],
                "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": ORG_ID}},
            },
            {
                "Sid": "SecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:" + PARTITION + ":s3:::BUCKET_NAME", "arn:" + PARTITION + ":s3:::BUCKET_NAME/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }

    def query_for_s3_bucket(self, bucket: str) -> bool:
        """Query for S3 bucket.

        Args:
            bucket (str): Name of the S3 bucket to query

        Returns:
            bool: True if the bucket exists, False otherwise
        """
        try:
            self.S3_RESOURCE.meta.client.head_bucket(Bucket=bucket)
            return True
        except ClientError:
            return False

    def create_s3_bucket(self, bucket: str) -> None:
        """Create S3 bucket.

        Args:
            bucket (str): Name of the S3 bucket to create
        """
        if self.REGION != "us-east-1":
            create_bucket = self.S3_CLIENT.create_bucket(
                ACL="private",
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": self.REGION},  # type: ignore
                ObjectOwnership="BucketOwnerPreferred",
            )
        else:
            create_bucket = self.S3_CLIENT.create_bucket(ACL="private", Bucket=bucket, ObjectOwnership="BucketOwnerPreferred")
        self.LOGGER.info(f"Bucket created: {create_bucket}")
        self.apply_bucket_policy(bucket)

    def apply_bucket_policy(self, bucket: str) -> None:
        """Apply bucket policy to S3 bucket.

        Args:
            bucket (str): Name of the S3 bucket to apply the policy to
        """
        self.LOGGER.info(self.BUCKET_POLICY_TEMPLATE)
        for sid in self.BUCKET_POLICY_TEMPLATE["Statement"]:
            if isinstance(sid["Resource"], list):
                sid["Resource"] = list(map(lambda x: x.replace("BUCKET_NAME", bucket), sid["Resource"]))  # noqa C417
            else:
                sid["Resource"] = sid["Resource"].replace("BUCKET_NAME", bucket)
        self.LOGGER.info(self.BUCKET_POLICY_TEMPLATE)
        bucket_policy_response = self.S3_CLIENT.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(self.BUCKET_POLICY_TEMPLATE),
        )
        self.LOGGER.info(bucket_policy_response)

    def s3_resource_check(self, bucket: str) -> None:
        """Check for S3 bucket and create if it doesn't exist.

        Args:
            bucket (str): Name of the S3 bucket to check and create if it doesn't exist
        """
        self.LOGGER.info(f"Checking for {bucket} s3 bucket...")
        if self.query_for_s3_bucket(bucket) is False:
            self.LOGGER.info(f"Bucket not found, creating {bucket} s3 bucket...")
            self.create_s3_bucket(bucket)

    def stage_code_to_s3(self, directory_path: str, bucket_name: str) -> None:
        """Upload the prepared code directory to the staging S3 bucket.

        Args:
            directory_path (str): Path to the directory to be uploaded
            bucket_name (str): Name of the S3 bucket
        """
        for root, dirs, files in os.walk(directory_path):  # noqa: B007
            for single_file in files:
                local_path = os.path.join(root, single_file)  # noqa: PL118

                relative_path = os.path.relpath(local_path, directory_path)
                s3_file_path = relative_path
                try:
                    self.S3_CLIENT.upload_file(local_path, bucket_name, s3_file_path)
                except ClientError as e:
                    self.LOGGER.info(f"Error uploading file: {e}")
                    return
                self.LOGGER.info(f"Uploaded {local_path} to {bucket_name} {s3_file_path}")

    def download_s3_file(self, local_file_path: str, s3_key: str, bucket_name: str) -> None:
        """Download the rule code from the staging S3 bucket.

        Args:
            local_file_path (str): Local path to download the file to
            s3_key (str): S3 key (path) of the file to download
            bucket_name (str): Name of the S3 bucket
        """
        self.LOGGER.info("Downloading file from s3...")

        # Ensure local directories exist
        self.LOGGER.info(f"Creating local directories ({os.path.dirname(local_file_path)}) if they don't exist...")
        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)  # noqa: PL103

        try:
            # Download the file from S3
            self.LOGGER.info(f"Downloading file from {bucket_name} {s3_key} to {local_file_path}")
            self.S3_CLIENT.download_file(bucket_name, s3_key, local_file_path)
        except ClientError as e:
            self.LOGGER.info(f"Error downloading file: {e}")

        # Check if the file was downloaded successfully
        if os.path.exists(local_file_path):  # noqa: PL110
            self.LOGGER.info(f"File downloaded successfully to {local_file_path}")
            # list the directory contents
            self.LOGGER.info(f"Listing directory contents: {os.listdir(os.path.dirname(local_file_path))}")
        else:
            self.LOGGER.info(f"File not found: {local_file_path}")

    def upload_file_to_s3(self, local_file_path: str, bucket_name: str, s3_key: str) -> None:
        """Upload a file to an S3 bucket.

        Args:
            local_file_path (str): Local path of the file to upload
            bucket_name (str): Name of the S3 bucket
            s3_key (str): S3 key (path) to upload the file to
        """
        try:
            # Upload the file to S3
            self.S3_CLIENT.upload_file(local_file_path, bucket_name, s3_key)
            self.LOGGER.info(f"File uploaded successfully to {bucket_name}/{s3_key}")
        except ClientError as e:
            self.LOGGER.info(f"Error uploading file: {e}")
