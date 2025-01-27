"""Lambda module to setup SRA SQS resources in the organization.

Version: 0.1

SQS module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
from time import sleep
from typing import TYPE_CHECKING

import boto3
import sra_sts
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_sqs.client import SQSClient


class SRASQS:
    """Class to setup SRA SQS resources in the organization."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        SQS_CLIENT: SQSClient = MANAGEMENT_ACCOUNT_SESSION.client("sqs", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    sts = sra_sts.SRASTS()

    def find_sqs_queue(self, queue_name: str, region: str = "default", account: str = "default") -> str | None:
        """Find SQS Queue ARN.

        Args:
            queue_name (str): SQS Queue Name
            region (str): AWS Region
            account (str): AWS Account

        Raises:
            ValueError: Error finding SQS Queue

        Returns:
            str: SQS Queue ARN
        """
        if region == "default":
            region = self.sts.HOME_REGION
        if account == "default":
            account = self.sts.MANAGEMENT_ACCOUNT
        try:
            response = self.SQS_CLIENT.get_queue_attributes(
                QueueUrl=f"https://sqs.{region}.amazonaws.com/{account}/{queue_name}", AttributeNames=["QueueArn"]
            )
            return response["Attributes"]["QueueArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                self.LOGGER.info(f"SQS Queue '{queue_name}' not found exception.")
                return None
            if e.response["Error"]["Code"] == "NotFound":
                self.LOGGER.info(f"SQS Queue '{queue_name}' not found.")
                return None
            raise ValueError(f"Error finding SQS topic: {e}") from None
