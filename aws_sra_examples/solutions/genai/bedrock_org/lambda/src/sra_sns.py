"""Custom Resource to setup SRA Lambda resources in the organization.

Version: 0.1

SNS module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep

from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import sra_sts

if TYPE_CHECKING:
    from mypy_boto3_sns.client import SNSClient
import json
import json


# TODO(liamschn): kms key for sns topic
class sra_sns:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    sts = sra_sts.sra_sts()

    def find_sns_topic(self, topic_name: str) -> str:
        """Find SNS Topic ARN."""
        try:
            response = self.SNS_CLIENT.get_topic_attributes(
                TopicArn=f"arn:{self.sts.PARTITION}:sns:{self.sts.HOME_REGION}:{self.sts.MANAGEMENT_ACCOUNT}:{topic_name}"
            )
            return response["Attributes"]["TopicArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                self.LOGGER.info(f"SNS Topic '{topic_name}' not found exception.")
                return None
            elif e.response["Error"]["Code"] == "NotFound":
                self.LOGGER.info(f"SNS Topic '{topic_name}' not found.")
                return None
            else:
                raise ValueError(f"Error finding SNS topic: {e}") from None

    def create_sns_topic(self, topic_name: str, solution_name: str, kms_key: str = "default") -> str:
        """Create SNS Topic."""
        if kms_key == "default":
            self.LOGGER.info("Using default KMS key for SNS topic.")
            kms_key = f"arn:{self.sts.PARTITION}:kms:{self.sts.HOME_REGION}:{self.sts.MANAGEMENT_ACCOUNT}:alias/aws/sns"
        else:
            self.LOGGER.info(f"Using provided KMS key '{kms_key}' for SNS topic.")
        try:
            response = self.SNS_CLIENT.create_topic(
                Name=topic_name, 
                Attributes={"DisplayName": topic_name, 
                    "KmsMasterKeyId": kms_key},
                Tags=[{"Key": "sra-solution", "Value": solution_name}]
            )
            topic_arn = response["TopicArn"]
            self.LOGGER.info(f"SNS Topic '{topic_name}' created with ARN: {topic_arn}")
            return topic_arn
        except ClientError as e:
            raise ValueError(f"Error creating SNS topic: {e}") from None

    def delete_sns_topic(self, topic_arn: str) -> None:
        """Delete SNS Topic."""
        try:
            self.SNS_CLIENT.delete_topic(TopicArn=topic_arn)
            self.LOGGER.info(f"SNS Topic '{topic_arn}' deleted")
            return None
        except ClientError as e:
            raise ValueError(f"Error deleting SNS topic: {e}") from None

    def find_sns_subscription(self, topic_arn: str, protocol: str, endpoint: str) -> bool:
        """Find SNS Subscription."""
        try:
            response = self.SNS_CLIENT.get_subscription_attributes(
                SubscriptionArn=f"arn:{self.sts.PARTITION}:sns:{self.sts.HOME_REGION}:{self.sts.MANAGEMENT_ACCOUNT}:{topic_arn}:{protocol}:{endpoint}"
            )
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                self.LOGGER.info(f"SNS Subscription for {endpoint} not found on topic {topic_arn}.")
                return False
            else:
                raise ValueError(f"Error finding SNS subscription: {e}") from None

    def create_sns_subscription(self, topic_arn: str, protocol: str, endpoint: str) -> None:
        """Create SNS Subscription."""
        try:
            self.SNS_CLIENT.subscribe(TopicArn=topic_arn, Protocol=protocol, Endpoint=endpoint)
            self.LOGGER.info(f"SNS Subscription created for {endpoint} on topic {topic_arn}")
            sleep(5)  # Wait for subscription to be created
            return None
        except ClientError as e:
            raise ValueError(f"Error creating SNS subscription: {e}") from None

    def set_topic_access_for_alarms(self, topic_arn: str, source_account: str) -> None:
        """Set SNS Topic Policy to allow access for alarm."""
        try:
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowAlarmToPublish",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudwatch.amazonaws.com"},
                        "Action": "sns:Publish",
                        "Resource": topic_arn,
                        "Condition": {
                            "ArnLike": {
                                "aws:SourceArn": f"arn:{self.sts.PARTITION}:cloudwatch:{self.sts.HOME_REGION}:{source_account}:alarm:*"
                            },
                            "StringEquals" : {"AWS:SourceAccount": source_account}
                        }
                    }
                ]
            }
            self.SNS_CLIENT.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName="Policy",
                AttributeValue=json.dumps(policy)
            )
            self.LOGGER.info(f"SNS Topic Policy set for {topic_arn} to allow access for CloudWatch alarms in the {source_account} account")
            return None
        except ClientError as e:
            raise ValueError(f"Error setting SNS topic policy: {e}") from None