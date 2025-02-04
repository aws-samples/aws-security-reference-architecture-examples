"""Lambda module to setup SRA Config resources in the organization.

Version: 1.0

Config module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_bedrock.client import BedrockClient


class SRABedrock:
    """Class to setup SRA Bedrock resources in the organization."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        BEDROCK_CLIENT: BedrockClient = MANAGEMENT_ACCOUNT_SESSION.client("bedrock", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_guardrail(self, guardrail_params: dict) -> str:
        """Create Bedrock guardrail.

        Args:
            guardrail_params: guardrail parameters

        Returns:
            str: guardrail arn
        """
        response = self.BEDROCK_CLIENT.create_guardrail(**guardrail_params)
        return response["guardrailArn"]

    def delete_guardrail(self, guardrail_identifier: str) -> dict:
        """Delete Bedrock guardrail.

        Args:
            guardrail_identifier: Bedrock guardrail id

        Returns:
            dict: api call response
        """
        return self.BEDROCK_CLIENT.delete_guardrail(guardrailIdentifier=guardrail_identifier)

    def get_guardrail_id(self, guardrail_name: str) -> str:
        """List Bedrock guardrails and return guardrail id.

        Args:
            guardrail_name: Bedrock guardrail name

        Returns:
            str: Bedrock guardrail id
        """
        guardrail_id = ""
        paginator = self.BEDROCK_CLIENT.get_paginator("list_guardrails")
        for page in paginator.paginate():
            for guardrail in page["guardrails"]:
                if guardrail["name"] == guardrail_name:
                    guardrail_id = guardrail["id"]
                    return guardrail_id
        return guardrail_id
