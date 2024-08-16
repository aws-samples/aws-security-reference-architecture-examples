"""Custom Resource to setup SRA Config resources in the organization.

Version: 0.1

Config module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep

# import re
# from time import sleep
from typing import TYPE_CHECKING

# , Literal, Optional, Sequence, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import urllib.parse
import json

import cfnresponse

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_config import ConfigServiceClient
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef


class sra_config:
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

    def get_organization_config_rules(self):
        """Get Organization Config Rules."""
        # Get the Organization ID
        org_id: str = self.ORG_CLIENT.describe_organization()["Organization"]["Id"]

        # Get the Organization Config Rules
        response = self.ORG_CLIENT.describe_organization_config_rules(
            OrganizationConfigRuleNames=["sra_config_rule"],
            OrganizationId=org_id,
        )

        # Log the response
        sra_config.LOGGER.info(response)

        # Return the response
        return response

    def put_organization_config_rule(self):
        """Put Organization Config Rule."""
        # Get the Organization ID
        org_id: str = self.ORG_CLIENT.describe_organization()["Organization"]["Id"]

        # Put the Organization Config Rule
        response = self.ORG_CLIENT.put_organization_config_rule(
            OrganizationConfigRuleName="sra_config_rule",
            OrganizationId=org_id,
            ConfigRuleName="sra_config_rule",
        )

        # Log the response
        sra_config.LOGGER.info(response)

        # Return the response
        return response

    def find_config_rule(self, rule_name):
        """Get Config Rule."""
        # Get the Config Rule
        try:

            response = self.CONFIG_CLIENT.describe_config_rules(
                ConfigRuleNames=[
                    rule_name,
                ],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchConfigRuleException":
                self.LOGGER.info(f"No such config rule: {rule_name}")
                return False, None
            else:
                self.LOGGER.info(f"Unexpected error: {e}")
                raise e
        # Log the response
        self.LOGGER.info(f"Config rule {rule_name} already exists: {response}")
        return True, response


    def create_config_rule(self, rule_name, lambda_arn, max_frequency, owner, description, input_params, eval_mode, scope={}):
        """Create Config Rule."""
        # Create the Config Rule
        response = self.CONFIG_CLIENT.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Description": description,
                "Scope": scope,
                "Source": {
                    "Owner": owner,
                    "SourceIdentifier": lambda_arn,
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            # TODO(liamschn): does messagetype need to be a parameter
                            "MessageType": "ScheduledNotification",
                            "MaximumExecutionFrequency": max_frequency,
                        }
                    ],
                },
                "InputParameters": json.dumps(input_params),
                # "MaximumExecutionFrequency": max_frequency,
                "EvaluationModes": [
                    {
                        'Mode': eval_mode
                    },
                ]
            }
        )

        # Log the response
        sra_config.LOGGER.info(response)

        # Return the response
        return response
