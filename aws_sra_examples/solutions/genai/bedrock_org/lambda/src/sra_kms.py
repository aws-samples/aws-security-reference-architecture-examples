"""Custom Resource to setup SRA IAM resources in the management account.

Version: 1.0

KMS module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os

from typing import TYPE_CHECKING
from typing import cast
from typing import Literal

if TYPE_CHECKING:
    from mypy_boto3_kms.client import KMSClient
    from mypy_boto3_kms.type_defs import CreateKeyResponseTypeDef, DescribeKeyResponseTypeDef
    from boto3 import Session
    from mypy_boto3_sts.client import STSClient
    from mypy_boto3_sts.type_defs import AssumeRoleResponseTypeDef

import boto3
from botocore.config import Config
from botocore.client import BaseClient

import urllib.parse
import json


class sra_kms:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    # Global Variables
    UNEXPECTED = "Unexpected!"
    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    SERVICE_NAME: Literal["kms"] = "kms"
    # SECRETS_KEY_POLICY: str = ""

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

    # def define_key_policy(self, target_account_id: str, partition: str, home_region: str, org_id: str, management_account: str) -> str:
    #     policy_template = {  # noqa ECE001
    #         "Version": "2012-10-17",
    #         "Id": "sra-secrets-key",
    #         "Statement": [
    #             {
    #                 "Sid": "Enable IAM User Permissions",
    #                 "Effect": "Allow",
    #                 "Principal": {"AWS": "arn:" + partition + ":iam::" + target_account_id + ":root"},
    #                 "Action": "kms:*",
    #                 "Resource": "*",
    #             },
    #             {
    #                 "Sid": "Allow access through AWS Secrets Manager for all principals in the account that are authorized to use AWS Secrets Manager",
    #                 "Effect": "Allow",
    #                 "Principal": {"AWS": "*"},
    #                 "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*", "kms:CreateGrant", "kms:DescribeKey"],
    #                 "Resource": "*",
    #                 "Condition": {
    #                     "StringEquals": {"kms:ViaService": "secretsmanager." + home_region + ".amazonaws.com", "aws:PrincipalOrgId": org_id},
    #                     "StringLike": {
    #                         "kms:EncryptionContext:SecretARN": "arn:aws:secretsmanager:" + home_region + ":*:secret:sra/*",
    #                         "aws:PrincipalArn": "arn:" + partition + ":iam::*:role/sra-execution",
    #                     },
    #                 },
    #             },
    #             {
    #                 "Sid": "Allow direct access to key metadata",
    #                 "Effect": "Allow",
    #                 "Principal": {"AWS": "arn:" + partition + ":iam::" + management_account + ":root"},
    #                 "Action": ["kms:Decrypt", "kms:Describe*", "kms:Get*", "kms:List*"],
    #                 "Resource": "*",
    #             },
    #             {
    #                 "Sid": "Allow alias creation during setup",
    #                 "Effect": "Allow",
    #                 "Principal": {"AWS": "arn:" + partition + ":iam::" + target_account_id + ":root"},
    #                 "Action": "kms:CreateAlias",
    #                 "Resource": "*",
    #                 "Condition": {
    #                     "StringEquals": {"kms:ViaService": "cloudformation." + home_region + ".amazonaws.com", "kms:CallerAccount": target_account_id}
    #                 },
    #             },
    #         ],
    #     }
    #     self.LOGGER.info(f"Key Policy:\n{json.dumps(policy_template)}")
    #     self.SECRETS_KEY_POLICY = json.dumps(policy_template)
    #     return json.dumps(policy_template)

    def create_kms_key(self, kms_client: KMSClient, key_policy: str, description: str = "Key description") -> str:
        """Create KMS key

        Args:
            kms_client (KMSClient): KMS boto3 client
            key_policy (dict): key policy
            description (str, optional): Description of KMS key. Defaults to "Key description".

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
        return key_response["KeyMetadata"]["KeyId"]

    def create_alias(self, kms_client: KMSClient, alias_name: str, target_key_id: str) -> None:
        self.LOGGER.info(f"Create KMS alias: {alias_name}")
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=target_key_id)

    def delete_alias(self, kms_client: KMSClient, alias_name: str) -> None:
        self.LOGGER.info(f"Delete KMS alias: {alias_name}")
        kms_client.delete_alias(AliasName=alias_name)

    def schedule_key_deletion(self, kms_client: KMSClient, key_id: str, pending_window_in_days: int = 30) -> None:
        self.LOGGER.info(f"Schedule deletion of key: {key_id} in {pending_window_in_days} days")
        kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=pending_window_in_days)

    def search_key_policies(self, kms_client: KMSClient, key_policy: str) -> tuple[bool, str]:
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
                else:
                    self.LOGGER.info(f"No key policy match found for key {key['KeyId']} policy {policy}: {policy_body}")
                    self.LOGGER.info(f"Attempted to match to: {expected_key_policy}")
        return False, "None"

    def list_key_policies(self, kms_client: KMSClient, key_id: str) -> list:
        response = kms_client.list_key_policies(KeyId=key_id)
        return response["PolicyNames"]

    def list_all_keys(self, kms_client: KMSClient) -> list:
        response = kms_client.list_keys()
        return response["Keys"]

    def check_key_exists(self, kms_client: KMSClient, key_id: str) -> tuple[bool, DescribeKeyResponseTypeDef]:
        try:
            response: DescribeKeyResponseTypeDef = kms_client.describe_key(KeyId=key_id)
            return True, response
        except kms_client.exceptions.NotFoundException:
            return False, cast(DescribeKeyResponseTypeDef, None)

    def check_alias_exists(self, kms_client: KMSClient, alias_name: str) -> tuple[bool, str, str, str]:
        """Check if an alias exists in KMS.

        Args:
            kms_client (kms_client): KMS boto3 client
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
