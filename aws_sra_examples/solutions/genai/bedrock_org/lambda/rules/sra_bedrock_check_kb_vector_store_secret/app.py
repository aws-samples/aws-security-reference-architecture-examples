"""Config rule to check knowledge base vector store secret configuration for Bedrock environments.

Version: 1.0

Config rule for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

# Get AWS region from environment variable
AWS_REGION = os.environ.get("AWS_REGION")

# Initialize AWS clients
bedrock_agent_client = boto3.client("bedrock-agent", region_name=AWS_REGION)
secretsmanager_client = boto3.client("secretsmanager", region_name=AWS_REGION)
config_client = boto3.client("config", region_name=AWS_REGION)


def check_knowledge_base(kb_id: str, kb_name: str) -> tuple[bool, str]:  # noqa: CFQ004
    """Check if a knowledge base's vector store is using KMS encrypted secrets.

    Args:
        kb_id (str): Knowledge base ID
        kb_name (str): Knowledge base name

    Raises:
        ClientError: If there is an error accessing the knowledge base or secret.

    Returns:
        tuple[bool, str]: (is_compliant, message)
    """
    try:
        kb_details = bedrock_agent_client.get_knowledge_base(knowledgeBaseId=kb_id)
        vector_store = kb_details.get("vectorStoreConfiguration")

        if not vector_store or not isinstance(vector_store, dict):
            return False, f"{kb_name} (no vector store configuration)"

        secret_arn = vector_store.get("secretArn")
        if not secret_arn:
            return False, f"{kb_name} (no secret configured)"

        try:
            secret_details = secretsmanager_client.describe_secret(SecretId=secret_arn)
            if not secret_details.get("KmsKeyId"):
                return False, f"{kb_name} (secret not using CMK)"
            return True, ""
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                return False, f"{kb_name} (secret access denied)"
            raise
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            return False, f"{kb_name} (access denied)"
        raise


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:  # noqa: U100
    """Evaluate if Bedrock Knowledge Base vector stores are using KMS encrypted secrets.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance type and annotation message.
    """
    try:
        non_compliant_kbs = []
        paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")

        for page in paginator.paginate():
            for kb in page["knowledgeBaseSummaries"]:
                kb_id = kb["knowledgeBaseId"]
                kb_name = kb.get("name", kb_id)
                is_compliant, message = check_knowledge_base(kb_id, kb_name)
                if not is_compliant:
                    non_compliant_kbs.append(message)

        if non_compliant_kbs:
            return "NON_COMPLIANT", f"The following knowledge bases have vector store secret issues: {'; '.join(non_compliant_kbs)}"
        return "COMPLIANT", "All knowledge base vector stores are using KMS encrypted secrets"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Knowledge Base vector store secrets: {str(e)}")
        return "ERROR", f"Error evaluating compliance: {str(e)}"


def lambda_handler(event: dict, context: Any) -> None:  # noqa: U100
    """Lambda handler.

    Args:
        event (dict): Lambda event object
        context (Any): Lambda context object
    """
    LOGGER.info("Evaluating compliance for AWS Config rule")
    LOGGER.info(f"Event: {json.dumps(event)}")

    invoking_event = json.loads(event["invokingEvent"])
    rule_parameters = json.loads(event["ruleParameters"]) if "ruleParameters" in event else {}

    compliance_type, annotation = evaluate_compliance(rule_parameters)

    evaluation = {
        "ComplianceResourceType": "AWS::::Account",
        "ComplianceResourceId": event["accountId"],
        "ComplianceType": compliance_type,
        "Annotation": annotation,
        "OrderingTimestamp": invoking_event["notificationCreationTime"],
    }

    LOGGER.info(f"Compliance evaluation result: {compliance_type}")
    LOGGER.info(f"Annotation: {annotation}")

    config_client.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])  # type: ignore

    LOGGER.info("Compliance evaluation complete.")
