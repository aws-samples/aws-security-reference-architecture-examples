"""Lambda module to setup SRA KMS resources in the management account.

Version: 1.0

KMS module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from mypy_boto3_kms.client import KMSClient
    from mypy_boto3_kms.type_defs import DescribeKeyResponseTypeDef
    from boto3 import Session

import json
import urllib.parse

import boto3
from botocore.config import Config


class SRAKMS:
    """Class to represent SRA KMS resources."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    # Global Variables
    UNEXPECTED = "Unexpected!"
    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    SERVICE_NAME: Literal["kms"] = "kms"

    try:
        MANAGEMENT_ACCOUNT_SESSION: Session = boto3.Session()
        STS_CLIENT = boto3.client("sts")
        HOME_REGION = MANAGEMENT_ACCOUNT_SESSION.region_name
        LOGGER.info(f"Detected home region: {HOME_REGION}")
        SM_HOST_NAME = urllib.parse.urlparse(boto3.client("secretsmanager", region_name=HOME_REGION).meta.endpoint_url).hostname
        MANAGEMENT_ACCOUNT = STS_CLIENT.get_caller_identity().get("Account")
        PARTITION: str = boto3.session.Session().get_partition_for_region(HOME_REGION)
        LOGGER.info(f"Detected management account (current account): {MANAGEMENT_ACCOUNT}")
        KMS_CLIENT: KMSClient = MANAGEMENT_ACCOUNT_SESSION.client(SERVICE_NAME, config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_kms_key(self, kms_client: KMSClient, key_policy: str, description: str = "Key description") -> str:
        """Create KMS key.

        Args:
            kms_client (KMSClient): KMS boto3 client
            key_policy (str): key policy
            description (str): Description of KMS key. Defaults to "Key description".

        Returns:
            str: KMS key id
        """
        self.LOGGER.info(f"Key policy: {key_policy}")
        key_response = kms_client.create_key(
            Policy=key_policy,
            Description=description,
            KeyUsage="ENCRYPT_DECRYPT",
            CustomerMasterKeySpec="SYMMETRIC_DEFAULT",
        )
        key_id = key_response["KeyMetadata"]["KeyId"]

        # Enable key rotation
        self.LOGGER.info(f"Enabling key rotation for key: {key_id}")
        kms_client.enable_key_rotation(KeyId=key_id)

        return key_id

    def create_alias(self, kms_client: KMSClient, alias_name: str, target_key_id: str) -> None:
        """Create KMS alias.

        Args:
            kms_client (KMSClient): KMS boto3 client
            alias_name (str): KMS alias name
            target_key_id (str): KMS key id
        """
        self.LOGGER.info(f"Create KMS alias: {alias_name}")
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=target_key_id)

    def delete_alias(self, kms_client: KMSClient, alias_name: str) -> None:
        """Delete KMS alias.

        Args:
            kms_client (KMSClient): KMS boto3 client
            alias_name (str): KMS alias name
        """
        self.LOGGER.info(f"Delete KMS alias: {alias_name}")
        kms_client.delete_alias(AliasName=alias_name)

    def schedule_key_deletion(self, kms_client: KMSClient, key_id: str, pending_window_in_days: int = 30) -> None:
        """Schedule KMS key deletion.

        Args:
            kms_client (KMSClient): KMS boto3 client
            key_id (str): KMS key id
            pending_window_in_days (int): Number of days to wait before deleting the key. Defaults to 30.
        """
        self.LOGGER.info(f"Schedule deletion of key: {key_id} in {pending_window_in_days} days")
        kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=pending_window_in_days)

    def search_key_policies(self, kms_client: KMSClient, key_policy: str) -> tuple[bool, str]:
        """Search KMS keys for a specific policy.

        Args:
            kms_client (KMSClient): KMS boto3 client
            key_policy (str): key policy

        Returns:
            tuple[bool, str]: True if policy is found, False if not found
        """
        for key in self.list_all_keys(kms_client):
            self.LOGGER.info(f"Examining state of key: {key['KeyId']}")
            if kms_client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"] != "Enabled":
                self.LOGGER.info(f"Skipping non-enabled key: {key['KeyId']}")
                continue
            self.LOGGER.info(f"Examinining policies in {key} kms key...")
            for policy in self.list_key_policies(kms_client, key["KeyId"]):
                policy_body = kms_client.get_key_policy(KeyId=key["KeyId"], PolicyName=policy)["Policy"]
                policy_body = json.loads(policy_body)
                self.LOGGER.info(f"Examining policy: {policy_body}")
                self.LOGGER.info(f"Comparing policy to provided policy: {key_policy}")
                expected_key_policy = json.loads(key_policy)
                if policy_body == expected_key_policy:
                    self.LOGGER.info(f"Key policy match found for key {key['KeyId']} policy {policy}: {policy_body}")
                    self.LOGGER.info(f"Attempted to match to: {expected_key_policy}")
                    return True, key["KeyId"]
                self.LOGGER.info(f"No key policy match found for key {key['KeyId']} policy {policy}: {policy_body}")
                self.LOGGER.info(f"Attempted to match to: {expected_key_policy}")
        return False, "None"

    def list_key_policies(self, kms_client: KMSClient, key_id: str) -> list:
        """List KMS key policies.

        Args:
            kms_client (KMSClient): KMS boto3 client
            key_id (str): KMS key id

        Returns:
            list: list of KMS key policies
        """
        response = kms_client.list_key_policies(KeyId=key_id)
        return response["PolicyNames"]

    def list_all_keys(self, kms_client: KMSClient) -> list:
        """List all KMS keys.

        Args:
            kms_client (KMSClient): KMS boto3 client

        Returns:
            list: list of KMS keys
        """
        response = kms_client.list_keys()
        return response["Keys"]

    def check_key_exists(self, kms_client: KMSClient, key_id: str) -> tuple[bool, DescribeKeyResponseTypeDef]:
        """Check if a KMS key exists.

        Args:
            kms_client (KMSClient): KMS boto3 client
            key_id (str): KMS key id

        Returns:
            tuple[bool, DescribeKeyResponseTypeDef]: True if key exists, False otherwise, and key description
        """
        try:
            response: DescribeKeyResponseTypeDef = kms_client.describe_key(KeyId=key_id)
            return True, response
        except kms_client.exceptions.NotFoundException:
            return False, cast(DescribeKeyResponseTypeDef, None)

    def check_alias_exists(self, kms_client: KMSClient, alias_name: str) -> tuple[bool, str, str, str]:
        """Check if an alias exists in KMS.

        Args:
            kms_client (KMSClient): KMS boto3 client
            alias_name (str): alias name to check for

        Returns:
            tuple: True if alias exists, False otherwise, alias name, target key id, and alias arn
        """
        self.LOGGER.info(f"Checking alias: {alias_name}")
        try:
            response = kms_client.list_aliases()
            self.LOGGER.info(f"Aliases: {response['Aliases']}")
            for alias in response["Aliases"]:
                self.LOGGER.info(f"Alias: {alias}")
                if alias["AliasName"] == alias_name:
                    self.LOGGER.info(f"Found alias: {alias}")
                    return True, alias["AliasName"], alias["TargetKeyId"], alias["AliasArn"]
            return False, "", "", ""
        except Exception as e:
            self.LOGGER.info(f"Unexpected error: {e}")
            return False, "", "", ""
