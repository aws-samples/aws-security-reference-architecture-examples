"""Config rule to check knowledge base data ingestion encryption for Bedrock environments.

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
config_client = boto3.client("config", region_name=AWS_REGION)


def check_data_sources(kb_id: str, kb_name: str) -> str | None:  # type: ignore  # noqa: CFQ004, CCR001
    """Check if a knowledge base's data sources are encrypted with KMS during ingestion.

    Args:
        kb_id (str): Knowledge base ID
        kb_name (str): Knowledge base name

    Raises:
        ClientError: If there is an error checking the knowledge base

    Returns:
        str | None: Error message if non-compliant, None if compliant
    """
    try:
        data_sources = bedrock_agent_client.list_data_sources(knowledgeBaseId=kb_id)
        LOGGER.info(f"Data sources: {data_sources}")
        if not isinstance(data_sources, dict):
            return f"{kb_name} (invalid data sources response)"

        unencrypted_sources = []
        for source in data_sources.get("dataSourceSummaries", []):
            LOGGER.info(f"Source: {source}")
            if not isinstance(source, dict):
                continue

            # Get the detailed data source configuration
            try:
                source_details = bedrock_agent_client.get_data_source(
                    knowledgeBaseId=kb_id,
                    dataSourceId=source["dataSourceId"]
                )
                LOGGER.info(f"Source details: {source_details}")

                # Check for KMS encryption configuration
                data_source = source_details.get("dataSource", {})
                encryption_config = data_source.get("serverSideEncryptionConfiguration", {})
                LOGGER.info(f"Encryption config: {encryption_config}")

                # Check if KMS key is configured for encryption
                if not encryption_config.get("kmsKeyArn"):
                    unencrypted_sources.append(source.get("name", source["dataSourceId"]))

            except ClientError as e:
                LOGGER.error(f"Error getting data source details for {source.get('name', source['dataSourceId'])}: {str(e)}")
                if e.response["Error"]["Code"] == "AccessDeniedException":
                    unencrypted_sources.append(f"{source.get('name', source['dataSourceId'])} (access denied)")
                continue

        if unencrypted_sources:
            return f"{kb_name} (sources without KMS encryption: {', '.join(unencrypted_sources)})"
        return None
    except ClientError as e:
        LOGGER.error(f"Error checking data sources for knowledge base {kb_name}: {str(e)}")
        if e.response["Error"]["Code"] == "AccessDeniedException":
            return f"{kb_name} (access denied)"
        raise


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:  # noqa: U100
    """Evaluate if Bedrock Knowledge Base data sources are encrypted with KMS.

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
                error = check_data_sources(kb_id, kb_name)
                if error:
                    non_compliant_kbs.append(error)

        if non_compliant_kbs:
            return "NON_COMPLIANT", f"The following knowledge bases have unencrypted data sources: {'; '.join(non_compliant_kbs)}"
        return "COMPLIANT", "All knowledge base data sources are encrypted with KMS"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Knowledge Base encryption: {str(e)}")
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
