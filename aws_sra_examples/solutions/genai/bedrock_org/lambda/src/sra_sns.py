"""Lambda module to setup SRA SNS resources in the organization.

Version: 0.1

SNS module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
import json

from time import sleep

from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import sra_sts

if TYPE_CHECKING:
    from mypy_boto3_sns.client import SNSClient
    from mypy_boto3_sns.type_defs import PublishBatchResponseTypeDef


class SRASNS:
    """Class to setup SRA SNS resources in the organization."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    SNS_PUBLISH_BATCH_MAX = 10

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    sts = sra_sts.SRASTS()

    def find_sns_topic(self, topic_name: str, region: str = "default", account: str = "default") -> str | None:
        """Find SNS Topic ARN.

        Args:
            topic_name (str): SNS Topic Name
            region (str): AWS Region
            account (str): AWS Account

        Raises:
            ValueError: Error finding SNS topic

        Returns:
            str: SNS Topic ARN
        """
        if region == "default":
            region = self.sts.HOME_REGION
        if account == "default":
            account = self.sts.MANAGEMENT_ACCOUNT
        try:
            response = self.SNS_CLIENT.get_topic_attributes(
                TopicArn=f"arn:{self.sts.PARTITION}:sns:{region}:{account}:{topic_name}"
            )
            return response["Attributes"]["TopicArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                self.LOGGER.info(f"SNS Topic '{topic_name}' not found exception.")
                return None
            if e.response["Error"]["Code"] == "NotFound":
                self.LOGGER.info(f"SNS Topic '{topic_name}' not found.")
                return None
            raise ValueError(f"Error finding SNS topic: {e}") from None

    def create_sns_topic(self, topic_name: str, solution_name: str, kms_key: str = "default") -> str:
        """Create SNS Topic.

        Args:
            topic_name (str): SNS Topic Name
            solution_name (str): Solution Name
            kms_key (str): KMS Key ARN

        Raises:
            ValueError: Error creating SNS topic

        Returns:
            str: SNS Topic ARN
        """
        if kms_key == "default":
            self.LOGGER.info("Using default KMS key for SNS topic.")
            kms_key = f"arn:{self.sts.PARTITION}:kms:{self.sts.HOME_REGION}:{self.sts.MANAGEMENT_ACCOUNT}:alias/aws/sns"
        else:
            self.LOGGER.info(f"Using provided KMS key '{kms_key}' for SNS topic.")
        try:
            response = self.SNS_CLIENT.create_topic(
                Name=topic_name,
                Attributes={"DisplayName": topic_name, "KmsMasterKeyId": kms_key},
                Tags=[{"Key": "sra-solution", "Value": solution_name}]
            )
            topic_arn = response["TopicArn"]
            self.LOGGER.info(f"SNS Topic '{topic_name}' created with ARN: {topic_arn}")
            return topic_arn
        except ClientError as e:
            raise ValueError(f"Error creating SNS topic: {e}") from None

    def delete_sns_topic(self, topic_arn: str) -> None:
        """Delete SNS Topic.

        Args:
            topic_arn (str): SNS Topic ARN

        Raises:
            ValueError: Error deleting SNS topic
        """
        try:
            self.SNS_CLIENT.delete_topic(TopicArn=topic_arn)
            self.LOGGER.info(f"SNS Topic '{topic_arn}' deleted")
        except ClientError as e:
            raise ValueError(f"Error deleting SNS topic: {e}") from None

    def find_sns_subscription(self, topic_arn: str, protocol: str, endpoint: str) -> bool:
        """Find SNS Subscription.

        Args:
            topic_arn (str): SNS Topic ARN
            protocol (str): SNS Subscription Protocol
            endpoint (str): SNS Subscription Endpoint

        Raises:
            ValueError: Error finding SNS subscription

        Returns:
            bool: True if SNS Subscription exists, False otherwise.
        """
        try:
            self.SNS_CLIENT.get_subscription_attributes(
                SubscriptionArn=f"arn:{self.sts.PARTITION}:sns:{self.sts.HOME_REGION}:{self.sts.MANAGEMENT_ACCOUNT}:{topic_arn}:{protocol}:{endpoint}"
            )
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                self.LOGGER.info(f"SNS Subscription for {endpoint} not found on topic {topic_arn}.")
                return False
            raise ValueError(f"Error finding SNS subscription: {e}") from None

    def create_sns_subscription(self, topic_arn: str, protocol: str, endpoint: str) -> None:
        """Create SNS Subscription.

        Args:
            topic_arn (str): SNS Topic ARN
            protocol (str): SNS Subscription Protocol
            endpoint (str): SNS Subscription Endpoint

        Raises:
            ValueError: Error creating SNS subscription
        """
        try:
            self.SNS_CLIENT.subscribe(TopicArn=topic_arn, Protocol=protocol, Endpoint=endpoint)
            self.LOGGER.info(f"SNS Subscription created for {endpoint} on topic {topic_arn}")
            sleep(5)  # Wait for subscription to be created
        except ClientError as e:
            raise ValueError(f"Error creating SNS subscription: {e}") from None

    def set_topic_access_for_alarms(self, topic_arn: str, source_account: str) -> None:
        """Set SNS Topic Policy to allow access for alarm.

        Args:
            topic_arn (str): SNS Topic ARN
            source_account (str): Source AWS Account

        Raises:
            ValueError: Error setting SNS topic policy
        """
        try:
            policy = {  # noqa: ECE001
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
        except ClientError as e:
            raise ValueError(f"Error setting SNS topic policy: {e}") from None

    def publish_sns_message_batch(self, message_batch: list, sns_topic_arn: str) -> None:
        """Publish SNS Message Batches.

        Args:
            message_batch: Batch of SNS messages
            sns_topic_arn: SNS Topic ARN
        """
        self.LOGGER.info("Publishing SNS Message Batch...")
        self.LOGGER.info({"SNSMessageBatch": message_batch})
        response: PublishBatchResponseTypeDef = self.SNS_CLIENT.publish_batch(TopicArn=sns_topic_arn, PublishBatchRequestEntries=message_batch)
        api_call_details = {"API_Call": "sns:PublishBatch", "API_Response": response}
        self.LOGGER.info(api_call_details)

    def process_sns_message_batches(self, sns_messages: list, sns_topic_arn: str) -> None:
        """Process SNS Message Batches for Publishing.

        Args:
            sns_messages: SNS messages to be batched.
            sns_topic_arn: SNS Topic ARN
        """
        self.LOGGER.info("Processing SNS Message Batches...")
        message_batches = []
        for i in range(
            self.SNS_PUBLISH_BATCH_MAX,
            len(sns_messages) + self.SNS_PUBLISH_BATCH_MAX,
            self.SNS_PUBLISH_BATCH_MAX,
        ):
            message_batches.append(sns_messages[i - self.SNS_PUBLISH_BATCH_MAX : i])

        for batch in message_batches:
            self.publish_sns_message_batch(batch, sns_topic_arn)
