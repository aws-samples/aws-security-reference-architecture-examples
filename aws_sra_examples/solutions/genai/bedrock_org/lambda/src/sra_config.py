"""Lambda module to setup SRA Config resources in the organization.

Version: 1.0

Config module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Literal

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_config import ConfigServiceClient
    from mypy_boto3_config.type_defs import DescribeConfigRulesResponseTypeDef
    from mypy_boto3_organizations import OrganizationsClient


class SRAConfig:
    """Class to setup SRA Config resources in the organization."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
        CONFIG_CLIENT: ConfigServiceClient = MANAGEMENT_ACCOUNT_SESSION.client("config", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def get_organization_config_rules(self) -> dict:
        """Get Organization Config Rules.

        Returns:
            dict: Organization Config Rules
        """
        # Get the Organization ID
        org_id: str = self.ORG_CLIENT.describe_organization()["Organization"]["Id"]

        # Get the Organization Config Rules
        response = self.ORG_CLIENT.describe_organization_config_rules(  # type: ignore
            OrganizationConfigRuleNames=["sra_config_rule"],
            OrganizationId=org_id,
        )

        # Log the response
        self.LOGGER.info(response)

        # Return the response
        return response

    def put_organization_config_rule(self) -> dict:
        """Put Organization Config Rule.

        Returns:
            dict: Organization Config Rule
        """
        # Get the Organization ID
        org_id: str = self.ORG_CLIENT.describe_organization()["Organization"]["Id"]

        # Put the Organization Config Rule
        response = self.ORG_CLIENT.put_organization_config_rule(  # type: ignore
            OrganizationConfigRuleName="sra_config_rule",
            OrganizationId=org_id,
            ConfigRuleName="sra_config_rule",
        )

        # Log the response
        self.LOGGER.info(response)

        # Return the response
        return response

    def find_config_rule(self, rule_name: str) -> tuple[bool, dict | DescribeConfigRulesResponseTypeDef]:
        """Get config rule.

        Args:
            rule_name (str): Config rule name

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.

        Returns:
            tuple[bool, dict | DescribeConfigRulesResponseTypeDef]: True if the config rule is found, False if not, and the response
        """
        try:

            response = self.CONFIG_CLIENT.describe_config_rules(
                ConfigRuleNames=[
                    rule_name,
                ],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchConfigRuleException":
                self.LOGGER.info(f"No such config rule: {rule_name}")
                return False, {}
            self.LOGGER.info(f"Unexpected error: {e}")
            raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs for details. {e}") from None
        self.LOGGER.info(f"Config rule {rule_name} exists: {response}")
        return True, response

    def create_config_rule(
        self,
        rule_name: str,
        lambda_arn: str,  # noqa: CFQ002
        max_frequency: Literal["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"],
        owner: Literal["CUSTOM_LAMBDA", "AWS"],
        description: str,
        input_params: dict,
        eval_mode: Literal["DETECTIVE", "PROACTIVE"],
        solution_name: str,
    ) -> None:
        """Create Config Rule.

        Args:
            rule_name (str): Config rule name
            lambda_arn (str): Lambda ARN
            max_frequency (Literal["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"]): Config rule max frequency
            owner (Literal["CUSTOM_LAMBDA", "AWS"]): Config rule owner
            description (str): Config rule description
            input_params (dict): Config rule input parameters
            eval_mode (Literal["DETECTIVE", "PROACTIVE"]): Config rule evaluation mode
            solution_name (str): SRA solution name
        """
        self.CONFIG_CLIENT.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Description": description,
                "Source": {
                    "Owner": owner,
                    "SourceIdentifier": lambda_arn,
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ScheduledNotification",
                            "MaximumExecutionFrequency": max_frequency,
                        }
                    ],
                },
                "InputParameters": json.dumps(input_params),
                "EvaluationModes": [
                    {"Mode": eval_mode},
                ],
            },
            Tags=[{"Key": "sra-solution", "Value": solution_name}],
        )

        # Log the response
        self.LOGGER.info(f"{rule_name} config rule created...")

    def delete_config_rule(self, rule_name: str) -> None:
        """Delete Config Rule.

        Args:
            rule_name (str): Config rule name
        """
        # Delete the Config Rule
        try:
            self.CONFIG_CLIENT.delete_config_rule(ConfigRuleName=rule_name)

            # Log the response
            self.LOGGER.info(f"Deleted {rule_name} config rule succeeded.")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchConfigRuleException":
                self.LOGGER.info(f"No such config rule: {rule_name}")
            else:
                self.LOGGER.info(f"Unexpected error: {e}")
