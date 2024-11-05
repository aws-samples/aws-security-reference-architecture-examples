# type: ignore
"""Custom Resource to check to see if a resource exists.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging
import os

import boto3
from botocore.client import ClientError
import json


class sra_s3:
    S3_CLIENT = boto3.client("s3")
    S3_RESOURCE = boto3.resource("s3")

    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    REGION: str = os.environ.get("AWS_REGION")
    ORG_ID: str = boto3.client("organizations").describe_organization()["Organization"]["Id"]
    PARTITION: str = boto3.session.Session().get_partition_for_region(REGION)
    STAGING_BUCKET: str = ""
    BUCKET_POLICY_TEMPLATE: dict = {
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

    def query_for_s3_bucket(self, bucket):
        try:
            self.S3_RESOURCE.meta.client.head_bucket(Bucket=bucket)
            return True
        except ClientError:
            return False

    def create_s3_bucket(self, bucket):
        if self.REGION != "us-east-1":
            create_bucket = self.S3_CLIENT.create_bucket(
                ACL="private", Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": self.REGION}, ObjectOwnership="BucketOwnerPreferred"
            )
        else:
            create_bucket = self.S3_CLIENT.create_bucket(ACL="private", Bucket=bucket, ObjectOwnership="BucketOwnerPreferred")
        self.LOGGER.info(f"Bucket created: {create_bucket}")
        self.apply_bucket_policy(bucket)

    def apply_bucket_policy(self, bucket):
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

    def s3_resource_check(self, bucket):
        self.LOGGER.info(f"Checking for {bucket} s3 bucket...")
        if self.query_for_s3_bucket(bucket) is False:
            self.LOGGER.info(f"Bucket not found, creating {bucket} s3 bucket...")
            self.create_s3_bucket(bucket)

    # todo(liamschn): parameter formatting validation

    def stage_code_to_s3(self, directory_path, bucket_name, s3_path):
        """
        Uploads the prepared code directory to the staging S3 bucket.

        :param directory_path: Local path to directory
        :param bucket_name: Name of the S3 bucket
        :param s3_path: S3 path where the directory will be uploaded
        """
        # s3_client = boto3.client("s3")

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                local_path = os.path.join(root, file)

                relative_path = os.path.relpath(local_path, directory_path)
                s3_file_path = relative_path
                try:
                    self.S3_CLIENT.upload_file(local_path, bucket_name, s3_file_path)
                except NoCredentialsError:
                    self.LOGGER.info("Credentials not available")
                    return
                self.LOGGER.info(f"Uploaded {local_path} to {bucket_name} {s3_file_path}")

    def download_s3_file(self, local_file_path, s3_key, bucket_name):
        """
        Downloads the rule code from the staging S3 bucket.

        :param local_file_path: Local path to save the downloaded file
        :param s3_key: Name of the S3 bucket key
        :param bucket_name: Name of the S3 bucket
        """
        self.LOGGER.info(f"Downloading file from s3...")
        
        # Ensure local directories exist
        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
        
        try:
            # Download the file from S3
            self.S3_CLIENT.download_file(bucket_name, s3_key, local_file_path)
        except ClientError as e:
            self.LOGGER.info(f"Error downloading file: {e}")

        # Check if the file was downloaded successfully
        if os.path.exists(local_file_path):
            self.LOGGER.info(f"File downloaded successfully to {local_file_path}")
            # list the directory contents
            self.LOGGER.info(f"Listing directory contents: {os.listdir(os.path.dirname(local_file_path))}")
        else:
            self.LOGGER.info(f"File not found: {local_file_path}")