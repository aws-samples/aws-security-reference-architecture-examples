"""Config rule to check knowledge base logging for Bedrock environments.

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
bedrock_client = boto3.client("bedrock", region_name=AWS_REGION)
config_client = boto3.client("config", region_name=AWS_REGION)


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:
    """Evaluate if Bedrock Knowledge Base logging is properly configured.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance type and annotation message.
    """
    try:
        # List all knowledge bases
        kb_list = []
        paginator = bedrock_client.get_paginator('list_knowledge_bases')
        for page in paginator.paginate():
            kb_list.extend(page.get('knowledgeBases', []))

        if not kb_list:
            return "COMPLIANT", "No knowledge bases found in the account"

        non_compliant_kbs = []
        
        # Check each knowledge base for logging configuration
        for kb in kb_list:
            kb_id = kb['knowledgeBaseId']
            try:
                kb_details = bedrock_client.get_knowledge_base(
                    knowledgeBaseId=kb_id
                )
                
                # Check if logging is enabled
                logging_config = kb_details.get('loggingConfiguration', {})
                if not logging_config or not logging_config.get('enabled', False):
                    non_compliant_kbs.append(f"{kb_id} ({kb.get('name', 'unnamed')})")
                    
            except ClientError as e:
                LOGGER.error(f"Error checking knowledge base {kb_id}: {str(e)}")
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    non_compliant_kbs.append(f"{kb_id} (access denied)")
                else:
                    raise

        if non_compliant_kbs:
            return "NON_COMPLIANT", f"The following knowledge bases do not have logging enabled: {', '.join(non_compliant_kbs)}"
        return "COMPLIANT", "All knowledge bases have logging enabled"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Knowledge Base logging configuration: {str(e)}")
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