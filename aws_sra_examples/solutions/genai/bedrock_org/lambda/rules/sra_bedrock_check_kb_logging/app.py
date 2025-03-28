"""Config rule to check knowledge base logging for Bedrock environments.

Version: 1.0

Config rule for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
import logging
import os
from typing import Any, Optional, Tuple

import boto3

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
logs_client = boto3.client("logs", region_name=AWS_REGION)
sts_client = boto3.client("sts", region_name=AWS_REGION)

# Max length for AWS Config annotation
MAX_ANNOTATION_LENGTH = 256


def truncate_annotation(message: str) -> str:
    """Ensure annotation stays within AWS Config's 256 character limit.

    Args:
        message (str): Original annotation message

    Returns:
        str: Truncated message with CloudWatch reference if needed
    """
    if len(message) <= MAX_ANNOTATION_LENGTH:
        return message

    log_group = f"/aws/lambda/{os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')}"
    reference = f" See CloudWatch logs ({log_group}) for details."

    # Calculate available space for the actual message
    available_chars = MAX_ANNOTATION_LENGTH - len(reference)

    # Truncate message and add reference
    truncated = message[:available_chars - 3] + "..."
    return truncated + reference


def check_kb_logging(kb_id: str) -> Tuple[bool, Optional[str]]:  # noqa: CCR001
    """Check if knowledge base has CloudWatch logging enabled.

    Args:
        kb_id (str): Knowledge base ID

    Returns:
        Tuple[bool, Optional[str]]: (True if logging is enabled, destination type if found)
    """
    try:
        account_id = sts_client.get_caller_identity()["Account"]
        kb_arn = f"arn:aws:bedrock:{AWS_REGION}:{account_id}:knowledge-base/{kb_id}"
        LOGGER.info(f"Checking logging for KB ARN: {kb_arn}")

        # Get delivery sources
        delivery_sources = logs_client.describe_delivery_sources()
        LOGGER.info(f"Found {len(delivery_sources.get('deliverySources', []))} delivery sources")

        for source in delivery_sources.get("deliverySources", []):
            LOGGER.info(f"Checking source: {source.get('name')}")
            if kb_arn in source.get("resourceArns", []):
                source_name = source.get("name")
                LOGGER.info(f"Found matching source name: {source_name}")
                if not source_name:
                    continue

                # Get deliveries to find the delivery ID
                LOGGER.info("Calling describe_deliveries API")
                deliveries = logs_client.describe_deliveries()
                LOGGER.info(f"Found {len(deliveries.get('deliveries', []))} deliveries")

                for delivery in deliveries.get("deliveries", []):
                    LOGGER.info(f"Checking delivery: {delivery.get('id')} with source name: {delivery.get('deliverySourceName')}")
                    if delivery.get("deliverySourceName") == source_name:
                        delivery_id = delivery.get("id")
                        LOGGER.info(f"Found matching delivery ID: {delivery_id}")
                        if not delivery_id:
                            continue

                        # Get delivery details to get the destination ARN
                        LOGGER.info(f"Calling get_delivery API with ID: {delivery_id}")
                        delivery_details = logs_client.get_delivery(id=delivery_id)
                        LOGGER.info(f"Delivery details: {delivery_details}")

                        delivery_destination_arn = delivery_details.get("delivery", {}).get("deliveryDestinationArn")
                        LOGGER.info(f"Found delivery destination ARN: {delivery_destination_arn}")
                        if not delivery_destination_arn:
                            continue

                        # Get delivery destinations to match the ARN
                        LOGGER.info("Calling describe_delivery_destinations API")
                        delivery_destinations = logs_client.describe_delivery_destinations()
                        LOGGER.info(f"Found {len(delivery_destinations.get('deliveryDestinations', []))} delivery destinations")

                        for destination in delivery_destinations.get("deliveryDestinations", []):
                            LOGGER.info(f"Checking destination: {destination.get('name')} with ARN: {destination.get('arn')}")
                            if destination.get("arn") == delivery_destination_arn:
                                destination_type = destination.get("deliveryDestinationType")
                                LOGGER.info(f"Found matching destination with type: {destination_type}")
                                return True, destination_type

        LOGGER.info("No matching logging configuration found")
        return False, None

    except Exception as e:
        LOGGER.error(f"Error checking logging for knowledge base {kb_id}: {str(e)}")
        return False, None


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:  # noqa: CFQ004, U100
    """Evaluate if Bedrock Knowledge Base logging is properly configured.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance type and annotation message.
    """
    try:
        # List all knowledge bases
        kb_list = []
        paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")
        for page in paginator.paginate():
            kb_list.extend(page.get("knowledgeBaseSummaries", []))

        if not kb_list:
            return "COMPLIANT", "No KBs found"

        non_compliant_kbs = []
        compliant_count = 0

        # Check each knowledge base for logging configuration
        for kb in kb_list:
            kb_id = kb["knowledgeBaseId"]
            kb_name = kb.get("name", "unnamed")

            has_logging, destination_type = check_kb_logging(kb_id)
            if not has_logging:
                # Use shorter format for non-compliant KBs
                non_compliant_kbs.append(f"{kb_id[:8]}..({kb_name[:10]})")
            else:
                compliant_count += 1
                LOGGER.info(f"KB {kb_id} ({kb_name}) has logging to {destination_type}")

        if non_compliant_kbs:
            msg = f"{len(non_compliant_kbs)} KBs without logging: {', '.join(non_compliant_kbs[:5])}"
            # Add count indicator if there are more than shown
            if len(non_compliant_kbs) > 5:
                msg += f" +{len(non_compliant_kbs) - 5} more"
            return "NON_COMPLIANT", truncate_annotation(msg)

        return "COMPLIANT", truncate_annotation(f"All {compliant_count} KBs have logging enabled")

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock KB logging: {str(e)}")
        return "ERROR", truncate_annotation(f"Error: {str(e)}")


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
