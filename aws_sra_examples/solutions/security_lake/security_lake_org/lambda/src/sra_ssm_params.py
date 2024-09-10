"""Custom Resource to gather data and create SSM paramters in the management account.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient


class SraSsmParams:
    """SRA SSM parameter values."""

    def __init__(self, logger: Any) -> None:
        """Get SSM parameter values.

        Args:
            logger: logger

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.
        """
        self.LOGGER = logger

        # Global Variables
        self.UNEXPECTED = "Unexpected!"
        self.BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

        try:
            management_account_session = boto3.Session()
            self.SSM_CLIENT: SSMClient = management_account_session.client("ssm")
        except Exception:
            self.LOGGER.exception(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def get_security_acct(self) -> str:
        """Query SSM Parameter Store to identify security tooling account id.

        Returns:
            Security tooling account id
        """
        self.LOGGER.info("Getting security tooling (audit) account id")
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/control-tower/audit-account-id")
        return ssm_response["Parameter"]["Value"]

    def get_home_region(self) -> str:
        """Query SSM Parameter Store to identify home region.

        Returns:
            Home region
        """
        ssm_response = self.SSM_CLIENT.get_parameter(
            Name="/sra/control-tower/home-region",
        )
        return ssm_response["Parameter"]["Value"]
