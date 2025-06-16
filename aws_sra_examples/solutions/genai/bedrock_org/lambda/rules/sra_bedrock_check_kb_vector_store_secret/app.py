"""Config rule to check knowledge base vector store secret configuration for Bedrock environments.

Version: 1.0

Config rule for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
import logging
import os
from typing import Any, List, Optional

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

# Maximum annotation length for AWS Config PutEvaluations API
MAX_ANNOTATION_LENGTH = 256


def check_knowledge_base(kb_id: str, kb_name: str) -> tuple[bool, str]:  # noqa: CFQ004
    """Check if a knowledge base's vector store is using AWS Secrets Manager for credentials.

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
        LOGGER.info(f"KB Details: {json.dumps(kb_details, default=str)}")

        # Get the knowledge base object from the response
        kb = kb_details.get("knowledgeBase", {})
        storage_config = kb.get("storageConfiguration")
        LOGGER.info(f"Storage config from kb: {json.dumps(storage_config, default=str)}")

        if not storage_config or not isinstance(storage_config, dict):
            return False, f"{kb_name} (No vector config)"

        storage_type = storage_config.get("type")
        LOGGER.info(f"Storage type: {storage_type}")
        if not storage_type:
            return False, f"{kb_name} (No store type)"

        # Check if storage type is one of the supported types
        supported_types = {
            "PINECONE": "pineconeConfiguration",
            "MONGO_DB_ATLAS": "mongoDbAtlasConfiguration",
            "REDIS_ENTERPRISE_CLOUD": "redisEnterpriseCloudConfiguration",
            "RDS": "rdsConfiguration",
        }

        # If storage type is not supported, it's compliant (no credentials needed)
        if storage_type not in supported_types:
            LOGGER.info(f"Storage type {storage_type} not supported - no credentials needed")
            return True, f"{kb_name} ({storage_type} - no creds needed)"

        # Get the configuration block for the storage type
        config_key = supported_types[storage_type]
        LOGGER.info(f"Config key: {config_key}")
        type_config = storage_config.get(config_key)
        LOGGER.info(f"Type config: {type_config}")

        if not type_config or not isinstance(type_config, dict):
            return False, f"{kb_name} (Missing {storage_type} config)"

        # Check for credentials secret ARN
        secret_arn = type_config.get("credentialsSecretArn")
        LOGGER.info(f"Secret ARN: {secret_arn}")
        if not secret_arn:
            return False, f"{kb_name} (Missing secret)"

        try:
            # Verify the secret exists and is using KMS encryption
            secret_details = secretsmanager_client.describe_secret(SecretId=secret_arn)
            LOGGER.info(f"Secret details: {secret_details}")
            if not secret_details.get("KmsKeyId"):
                return False, f"{kb_name} (Secret not using CMK)"
            return True, f"{kb_name} (Uses CMK)"
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                return False, f"{kb_name} (Secret access denied)"
            raise
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            return False, f"{kb_name} (KB access denied)"
        raise


def format_annotation(compliance_type: str, compliant_kbs: List[str], non_compliant_kbs: Optional[List[str]] = None) -> str:
    """Format annotation message and ensure it doesn't exceed 256 characters.

    Args:
        compliance_type (str): Compliance status
        compliant_kbs (List[str]): List of compliant knowledge bases
        non_compliant_kbs (Optional[List[str]]): List of non-compliant knowledge bases

    Returns:
        str: Formatted annotation message
    """
    if compliance_type == "ERROR":
        return compliant_kbs[0]  # In this case, compliant_kbs contains the error message

    non_compliant_count = len(non_compliant_kbs) if non_compliant_kbs else 0
    message = ""

    # Start with a brief message
    if compliance_type == "NON_COMPLIANT":
        base_message = "KB vector store check: "
        if non_compliant_kbs:
            combined = "; ".join(non_compliant_kbs)
            # If message would be too long, provide a count instead of details
            if len(base_message + combined) > MAX_ANNOTATION_LENGTH:
                message = f"{base_message}{non_compliant_count} non-compliant KBs. See logs for details."
            else:
                message = base_message + combined
    else:  # COMPLIANT
        if len(compliant_kbs) > 3:
            message = f"All {len(compliant_kbs)} KBs comply with vector store requirements."
        elif len("; ".join(compliant_kbs)) > MAX_ANNOTATION_LENGTH:
            message = f"{len(compliant_kbs)} KBs comply with vector store requirements."
        else:
            message = "; ".join(compliant_kbs)

    # Final check to ensure we don't exceed limit
    if len(message) > MAX_ANNOTATION_LENGTH:
        return f"See CloudWatch logs for details. Found {non_compliant_count} issues."

    return message


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:  # noqa: U100
    """Evaluate if Bedrock Knowledge Base vector stores are using KMS encrypted secrets.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance type and annotation message.
    """
    try:
        non_compliant_kbs = []
        compliant_kbs = []
        paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")

        for page in paginator.paginate():
            for kb in page["knowledgeBaseSummaries"]:
                kb_id = kb["knowledgeBaseId"]
                LOGGER.info(f"KB ID: {kb_id}")
                kb_name = kb.get("name", kb_id)
                LOGGER.info(f"KB Name: {kb_name}")
                is_compliant, message = check_knowledge_base(kb_id, kb_name)
                if is_compliant:
                    compliant_kbs.append(message)
                else:
                    non_compliant_kbs.append(message)

        # Log full details for CloudWatch reference
        LOGGER.info(f"Compliant KBs: {'; '.join(compliant_kbs)}")
        if non_compliant_kbs:
            LOGGER.info(f"Non-compliant KBs: {'; '.join(non_compliant_kbs)}")
            return "NON_COMPLIANT", format_annotation("NON_COMPLIANT", compliant_kbs, non_compliant_kbs)
        return "COMPLIANT", format_annotation("COMPLIANT", compliant_kbs)

    except Exception as e:
        error_msg = f"Error evaluating compliance: {str(e)}"
        LOGGER.error(error_msg)
        return "ERROR", format_annotation("ERROR", [error_msg])


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
