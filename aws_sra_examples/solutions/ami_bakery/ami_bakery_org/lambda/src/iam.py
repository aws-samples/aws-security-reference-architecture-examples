"""This script performs operations to create roles and policies for SRA AMI Bakery solution.

Version: 1.0

'ami_bakery_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING

import boto3

if TYPE_CHECKING:
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef


LOGGER = logging.getLogger("sra")

log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)


def create_role(session: boto3.Session, role_name: str, trust_policy: str) -> CreateRoleResponseTypeDef:
    """Create AMI Bakery role.

    Args:
        session: boto3 session used by boto3 API calls
        role_name: Name of the role to be created
        trust_policy: Trust policy relationship for the role

    Returns:
        Dictionary output of a successful CreateRole request
    """
    iam_client: IAMClient = session.client("iam")
    LOGGER.info("Creating role %s.", role_name)
    return iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))


def create_policy(session: boto3.Session, policy_name: str, policy_document: str) -> CreatePolicyResponseTypeDef:
    """Create AMI Bakery policy.

    Args:
        session: boto3 session used by boto3 API calls
        policy_name: Name of the policy to be created
        policy_document: IAM policy document for the role

    Returns:
        Dictionary output of a successful CreatePolicy request
    """
    iam_client: IAMClient = session.client("iam")
    LOGGER.info("Creating policy %s.", policy_name)
    return iam_client.create_policy(PolicyName=policy_name, PolicyDocument=policy_document)


def attach_policy(session: boto3.Session, role_name: str, policy_name: str, policy_document: str) -> EmptyResponseMetadataTypeDef:
    """Attach policy to AMI Bakery role.

    Args:
        session: boto3 session used by boto3 API calls
        role_name: Name of the role for policy to be attached to
        policy_name: Name of the policy to be attached
        policy_document: IAM policy document to be attached

    Returns:
        Empty response metadata
    """
    iam_client: IAMClient = session.client("iam")

    LOGGER.info("Attaching policy to %s.", role_name)
    return iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document)


def detach_policy(session: boto3.Session, role_name: str, policy_name: str) -> EmptyResponseMetadataTypeDef:
    """Detach AMI Bakery policy.

    Args:
        session: boto3 session used by boto3 API calls
        role_name: Name of the role for which the policy is removed from
        policy_name: Name of the policy to be removed (detached)

    Returns:
        Empty response metadata
    """
    iam_client: IAMClient = session.client("iam")
    LOGGER.info("Detaching policy from %s.", role_name)
    return iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)


def delete_policy(session: boto3.Session, policy_arn: str) -> EmptyResponseMetadataTypeDef:
    """Delete AMI Bakery Policy.

    Args:
        session: boto3 session used by boto3 API calls
        policy_arn: The Amazon Resource Name (ARN) of the policy to be deleted

    Returns:
        Empty response metadata
    """
    iam_client: IAMClient = session.client("iam")
    LOGGER.info("Deleting policy %s.", policy_arn)
    return iam_client.delete_policy(PolicyArn=policy_arn)


def delete_role(session: boto3.Session, role_name: str) -> EmptyResponseMetadataTypeDef:
    """Delete AMI Bakery role.

    Args:
        session: boto3 session used by boto3 API calls
        role_name: Name of the role to be deleted

    Returns:
        Empty response metadata
    """
    iam_client: IAMClient = session.client("iam")
    LOGGER.info("Deleting role %s.", role_name)
    return iam_client.delete_role(RoleName=role_name)
