"""Custom Resource to setup SRA Config resources in the organization.

Version: 0.1

'bedrock_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

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
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef


class sra_config:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    def put_organization_config_rule():
        """Put Organization Config Rule."""
        # Setup Boto3 Clients
        org_client: OrganizationsClient = boto3.client("organizations")

        # Get the Organization ID
        org_id: str = (
            org_client.describe_organization()["Organization"]["Id"]
        )

        # Put the Organization Config Rule
        response = org_client.put_organization_config_rule(
            OrganizationConfigRuleName="sra_config_rule",
            OrganizationId=org_id,
            ConfigRuleName="sra_config_rule",
        )

        # Log the response
        sra_config.LOGGER.info(response)

        # Return the response
        return response