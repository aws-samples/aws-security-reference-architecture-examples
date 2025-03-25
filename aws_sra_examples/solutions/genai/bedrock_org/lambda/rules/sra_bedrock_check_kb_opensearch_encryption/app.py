"""Config rule to check OpenSearch vector store encryption for Bedrock Knowledge Base.

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
opensearch_client = boto3.client("opensearch", region_name=AWS_REGION)
opensearch_serverless_client = boto3.client("opensearchserverless", region_name=AWS_REGION)
config_client = boto3.client("config", region_name=AWS_REGION)


def check_opensearch_serverless(collection_id: str, kb_name: str) -> str | None:  # type: ignore
    """Check OpenSearch Serverless collection encryption.

    Args:
        collection_id (str): Collection ID
        kb_name (str): Knowledge base name

    Returns:
        str | None: Error message if non-compliant, None if compliant
    """
    try:
        collection = opensearch_serverless_client.get_security_policy(name=collection_id, type="encryption")
        security_policy = collection.get("securityPolicyDetail", {})
        if security_policy.get("Type") == "encryption":
            security_policies = security_policy.get("SecurityPolicies", [])
            if isinstance(security_policies, list) and security_policies:
                encryption_policy = security_policies[0]
                kms_key_arn = encryption_policy.get("KmsARN", "")
                if not kms_key_arn or "aws/opensearchserverless" in kms_key_arn:
                    return f"{kb_name} (OpenSearch Serverless not using CMK)"
    except ClientError as e:
        LOGGER.error(f"Error checking OpenSearch Serverless collection: {str(e)}")
        return f"{kb_name} (error checking OpenSearch Serverless)"
    return None


def check_opensearch_domain(domain_name: str, kb_name: str) -> str | None:  # type: ignore  # noqa: CFQ004
    """Check standard OpenSearch domain encryption.

    Args:
        domain_name (str): Domain name
        kb_name (str): Knowledge base name

    Returns:
        str | None: Error message if non-compliant, None if compliant
    """
    try:
        domain = opensearch_client.describe_domain(DomainName=domain_name)
        encryption_config = domain.get("DomainStatus", {}).get("EncryptionAtRestOptions", {})
        if not encryption_config.get("Enabled", False):
            return f"{kb_name} (OpenSearch domain encryption not enabled)"
        kms_key_id = encryption_config.get("KmsKeyId", "")
        if not kms_key_id or "aws/opensearch" in kms_key_id:
            return f"{kb_name} (OpenSearch domain not using CMK)"
    except ClientError as e:
        LOGGER.error(f"Error checking OpenSearch domain: {str(e)}")
        return f"{kb_name} (error checking OpenSearch domain)"
    return None


def check_knowledge_base(kb_id: str, kb_name: str) -> tuple[bool, str | None]:  # type: ignore  # noqa: CFQ004
    """Check a knowledge base's OpenSearch configuration.

    Args:
        kb_id (str): Knowledge base ID
        kb_name (str): Knowledge base name

    Raises:
        ClientError: If there is an error checking the knowledge base

    Returns:
        tuple[bool, str | None]: (has_opensearch, error_message)
    """
    try:
        kb_details = bedrock_agent_client.get_knowledge_base(knowledgeBaseId=kb_id)
        # Convert datetime objects to strings before JSON serialization
        kb_details_serializable = json.loads(json.dumps(kb_details, default=str))
        LOGGER.info(f"Knowledge base details for {kb_name}: {json.dumps(kb_details_serializable)}")

        # Access the knowledgeBase key from the response
        kb_data = kb_details.get("knowledgeBase", {})

        # Check both possible locations for vector store config
        vector_store = kb_data.get("vectorStoreConfiguration") or kb_data.get("storageConfiguration", {})
        LOGGER.info(f"Vector store config for {kb_name}: {json.dumps(vector_store)}")

        if not vector_store or not isinstance(vector_store, dict):
            LOGGER.info(f"No vector store configuration found for {kb_name}")
            return False, None

        vector_store_type = vector_store.get("vectorStoreType") or vector_store.get("type")
        LOGGER.info(f"Vector store type for {kb_name}: {vector_store_type}")
        if not vector_store_type or (vector_store_type.upper() != "OPENSEARCH" and vector_store_type.upper() != "OPENSEARCH_SERVERLESS"):
            LOGGER.info(f"Vector store type is not OpenSearch for {kb_name}")
            return False, None

        opensearch_config = vector_store.get("opensearchServerlessConfiguration") or vector_store.get("opensearchConfiguration")
        LOGGER.info(f"OpenSearch config for {kb_name}: {json.dumps(opensearch_config)}")
        if not opensearch_config:
            return True, f"{kb_name} (missing OpenSearch configuration)"

        if "collectionArn" in opensearch_config:
            collection_id = opensearch_config["collectionArn"].split("/")[-1]
            LOGGER.info(f"Found OpenSearch Serverless collection {collection_id} for {kb_name}")
            return True, check_opensearch_serverless(collection_id, kb_name)

        domain_endpoint = opensearch_config.get("endpoint", "")
        if not domain_endpoint:
            return True, f"{kb_name} (missing OpenSearch domain endpoint)"
        domain_name = domain_endpoint.split(".")[0]
        LOGGER.info(f"Found OpenSearch domain {domain_name} for {kb_name}")
        return True, check_opensearch_domain(domain_name, kb_name)

    except ClientError as e:
        LOGGER.error(f"Error checking knowledge base {kb_id}: {str(e)}")
        if e.response["Error"]["Code"] == "AccessDeniedException":
            return True, f"{kb_name} (access denied)"
        raise


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:  # noqa: U100, CFQ004
    """Evaluate if Bedrock Knowledge Base OpenSearch vector stores are encrypted with KMS CMK.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance type and annotation message.
    """
    try:
        non_compliant_kbs = []
        has_opensearch = False
        paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")

        for page in paginator.paginate():
            for kb in page["knowledgeBaseSummaries"]:
                kb_id = kb["knowledgeBaseId"]
                kb_name = kb.get("name", kb_id)
                is_opensearch, error = check_knowledge_base(kb_id, kb_name)
                has_opensearch = has_opensearch or is_opensearch
                if error:
                    non_compliant_kbs.append(error)

        if not has_opensearch:
            return "COMPLIANT", "No OpenSearch vector stores found in knowledge bases"
        if non_compliant_kbs:
            return "NON_COMPLIANT", (
                "The following knowledge bases have OpenSearch vector stores not encrypted with CMK: " + f"{'; '.join(non_compliant_kbs)}"
            )
        return "COMPLIANT", "All knowledge base OpenSearch vector stores are encrypted with KMS CMK"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Knowledge Base OpenSearch encryption: {str(e)}")
        return "INSUFFICIENT_DATA", f"Error evaluating compliance: {str(e)}"


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
