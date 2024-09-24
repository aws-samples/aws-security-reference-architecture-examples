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
if TYPE_CHECKING:
    from mypy_boto3_kms.client import KMSClient


import boto3
from botocore.config import Config

import urllib.parse
import json


class sra_kms:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    # Global Variables
    RESOURCE_TYPE: str = ""
    UNEXPECTED = "Unexpected!"
    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    SRA_SOLUTION_NAME = "sra-common-prerequisites"
    CFN_RESOURCE_ID: str = "sra-iam-function"
    CFN_CUSTOM_RESOURCE: str = "Custom::LambdaCustomResource"

    CONFIGURATION_ROLE: str = ""
    TARGET_ACCOUNT_ID: str = ""
    ORG_ID: str = ""

    KEY_ALIAS: str = "alias/sra-secrets-key"  # todo(liamschn): parameterize this alias name
    KEY_DESCRIPTION: str = "SRA Secrets Key"  # todo(liamschn): parameterize this description
    EXECUTION_ROLE: str = "sra-execution"  # todo(liamschn): parameterize this role name
    SECRETS_PREFIX: str = "sra"  # todo(liamschn): parameterize this?
    SECRETS_KEY_POLICY: str = ""

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        STS_CLIENT = boto3.client("sts")
        HOME_REGION = MANAGEMENT_ACCOUNT_SESSION.region_name
        LOGGER.info(f"Detected home region: {HOME_REGION}")
        SM_HOST_NAME = urllib.parse.urlparse(boto3.client("secretsmanager", region_name=HOME_REGION).meta.endpoint_url).hostname
        MANAGEMENT_ACCOUNT = STS_CLIENT.get_caller_identity().get("Account")
        PARTITION: str = boto3.session.Session().get_partition_for_region(HOME_REGION)
        LOGGER.info(f"Detected management account (current account): {MANAGEMENT_ACCOUNT}")
        KMS_CLIENT: KMSClient = MANAGEMENT_ACCOUNT_SESSION.client("kms", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def define_key_policy(self, target_account_id, partition, home_region, org_id, management_account):
        policy_template = {  # noqa ECE001
            "Version": "2012-10-17",
            "Id": "sra-secrets-key",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:" + partition + ":iam::" + target_account_id + ":root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "Allow access through AWS Secrets Manager for all principals in the account that are authorized to use AWS Secrets Manager",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*", "kms:CreateGrant", "kms:DescribeKey"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:ViaService": "secretsmanager." + home_region + ".amazonaws.com", "aws:PrincipalOrgId": org_id},
                        "StringLike": {
                            "kms:EncryptionContext:SecretARN": "arn:aws:secretsmanager:" + home_region + ":*:secret:sra/*",
                            "aws:PrincipalArn": "arn:" + partition + ":iam::*:role/sra-execution",
                        },
                    },
                },
                {
                    "Sid": "Allow direct access to key metadata",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:" + partition + ":iam::" + management_account + ":root"},
                    "Action": ["kms:Decrypt", "kms:Describe*", "kms:Get*", "kms:List*"],
                    "Resource": "*",
                },
                {
                    "Sid": "Allow alias creation during setup",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:" + partition + ":iam::" + target_account_id + ":root"},
                    "Action": "kms:CreateAlias",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:ViaService": "cloudformation." + home_region + ".amazonaws.com", "kms:CallerAccount": target_account_id}
                    },
                },
            ],
        }
        self.LOGGER.info(f"Key Policy:\n{json.dumps(policy_template)}")
        self.SECRETS_KEY_POLICY = json.dumps(policy_template)
        return json.dumps(policy_template)

    def assume_role(self, account, role_name, service, region_name):
        """Get boto3 client assumed into an account for a specified service.

        Args:
            account: aws account id
            service: aws service
            region_name: aws region

        Returns:
            client: boto3 client
        """
        client = self.MANAGEMENT_ACCOUNT_SESSION.client("sts")
        sts_response = client.assume_role(
            RoleArn="arn:" + self.PARTITION + ":iam::" + account + ":role/" + role_name,
            RoleSessionName="SRA-AssumeCrossAccountRole",
            DurationSeconds=900,
        )

        return self.MANAGEMENT_ACCOUNT_SESSION.client(
            service,
            region_name=region_name,
            aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
            aws_session_token=sts_response["Credentials"]["SessionToken"],
        )

    def create_kms_key(self, kms_client, key_policy, description="Key description"):
        """_summary_

        Args:
            kms_client (KMSClient): KMS boto3 client
            key_policy (dict): key policy
            description (str, optional): Description of KMS key. Defaults to "Key description".

        Returns:
            str: KMS key id
        """
        key_response = kms_client.create_key(
            Policy=key_policy,
            Description=description,
            KeyUsage="ENCRYPT_DECRYPT",
            CustomerMasterKeySpec="SYMMETRIC_DEFAULT",
        )
        return key_response["KeyMetadata"]["KeyId"]

    # def apply_key_policy(kms_client, key_id, key_policy):
    #     kms_client.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(key_policy), BypassPolicyLockoutSafetyCheck=False)

    def create_alias(self, kms_client, alias_name, target_key_id):
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=target_key_id)

    def delete_alias(self, kms_client, alias_name):
        kms_client.delete_alias(AliasName=alias_name)

    def schedule_key_deletion(self, kms_client, key_id, pending_window_in_days=30):
        kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=pending_window_in_days)

    def search_key_policies(self, kms_client):
        for key in self.list_all_keys(kms_client):
            for policy in self.list_key_policies(kms_client, key["KeyId"]):
                policy_body = kms_client.get_key_policy(KeyId=key["KeyId"], PolicyName=policy)["Policy"]
                policy_body = json.loads(policy_body)
                self.LOGGER.info(f"Key policy: {policy_body}")
                self.LOGGER.info(f"SECRETS_KEY_POLICY: {self.SECRETS_KEY_POLICY}")
                secrets_key_policy = json.loads(self.SECRETS_KEY_POLICY)
                if policy_body == secrets_key_policy:
                    self.LOGGER.info(f"Key policy match found for key {key['KeyId']} policy {policy}: {policy_body}")
                    self.LOGGER.info(f"Attempted to match to: {secrets_key_policy}")
                    return True, key["KeyId"]
                else:
                    self.LOGGER.info(f"No key policy match found for key {key['KeyId']} policy {policy}: {policy_body}")
                    self.LOGGER.info(f"Attempted to match to: {secrets_key_policy}")
        return False, "None"

    def list_key_policies(self, kms_client, key_id):
        response = kms_client.list_key_policies(KeyId=key_id)
        return response["PolicyNames"]

    def list_all_keys(self, kms_client):
        response = kms_client.list_keys()
        return response["Keys"]

    def check_key_exists(self, kms_client, key_id):
        try:
            response = kms_client.describe_key(KeyId=key_id)
            return True, response
        except kms_client.exceptions.NotFoundException:
            return False, None

    def check_alias_exists(self, kms_client, alias_name):
        """Check if an alias exists in KMS.

        Args:
            kms_client (kms_client): KMS boto3 client
            alias_name (str): alias name to check for

        Returns:
            tuple (bool, str, str): (exists, alias_name, target_key_id)
        """
        try:
            response = kms_client.list_aliases()
            for alias in response["Aliases"]:
                if alias["AliasName"] == alias_name:
                    return True, alias["AliasName"], alias["TargetKeyId"]
            return False, "", ""
        except Exception as e:
            self.LOGGER.info(f"Unexpected error: {e}")
            return False, "", ""
