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
            response = self.SNS_CLIENT.get_topic_attributes(TopicArn=f"arn:{self.sts.PARTITION}:sns:{self.sts.HOME_REGION}:{self.sts.MANAGEMENT_ACCOUNT}:{topic_name}")
            return response['Attributes']['TopicArn']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NotFoundException':
                self.LOGGER.error(f"SNS Topic '{topic_name}' not found.")
                return None
            else:
                raise ValueError(f"Error finding SNS topic: {e}") from None
    
    def create_sns_topic(self, topic_name: str, solution_name: str) -> str:
        """Create SNS Topic."""
        try:
            response = self.SNS_CLIENT.create_topic(Name=topic_name, Attributes={'DisplayName': topic_name}, Tags=[{'Key': 'sra-solution', 'Value': solution_name}])
            topic_arn = response['TopicArn']
            self.LOGGER.info(f"SNS Topic '{topic_name}' created with ARN: {topic_arn}")
            return topic_arn
        except ClientError as e:
            raise ValueError(f"Error creating SNS topic: {e}") from None

    def create_sns_subscription(self, topic_arn: str, protocol: str, endpoint: str) -> None:
        """Create SNS Subscription."""
        try:
            self.SNS_CLIENT.subscribe(TopicArn=topic_arn, Protocol=protocol, Endpoint=endpoint)
            self.LOGGER.info(f"SNS Subscription created for {endpoint} on topic {topic_arn}")
            sleep(5)  # Wait for subscription to be created
            return None
        except ClientError as e:
            raise ValueError(f"Error creating SNS subscription: {e}") from None