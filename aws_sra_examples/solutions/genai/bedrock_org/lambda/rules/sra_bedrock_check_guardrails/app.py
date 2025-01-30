"""Config rule to check for the existence of guardrails for Bedrock environemts.

Version: 1.0

Config rule for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import ast
import json
import logging
import os
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

GUARDRAIL_FEATURES = {
    "content_filters": True,
    "denied_topics": True,
    "word_filters": True,
    "sensitive_info_filters": True,
    "contextual_grounding": True,
}


def lambda_handler(event: dict, context: Any) -> dict:  # noqa: CCR001, C901, U100
    """Lambda handler.

    Args:
        event (dict): The AWS Config event
        context (Any): Lambda context object

    Raises:
        Exception: Any exception thrown by the lambda function

    Returns:
        dict: The evaluation results
    """
    LOGGER.info("Starting lambda_handler function")
    bedrock = boto3.client("bedrock")

    # Parse rule parameters safely using ast.literal_eval
    LOGGER.info("Parsing rule parameters")
    rule_params = ast.literal_eval(event.get("ruleParameters", "{}"))
    LOGGER.info(f"Rule parameters: {rule_params}")
    for param, default in GUARDRAIL_FEATURES.items():
        GUARDRAIL_FEATURES[param] = rule_params.get(param, default)
    LOGGER.info(f"Guardrail features to check: {GUARDRAIL_FEATURES}")

    # List all guardrails
    LOGGER.info("Listing all Bedrock guardrails")
    guardrails = bedrock.list_guardrails()["guardrails"]
    LOGGER.info(f"Found {len(guardrails)} guardrails")

    compliant_guardrails = []
    non_compliant_guardrails = {}

    for guardrail in guardrails:
        guardrail_id = guardrail["id"]
        guardrail_name = guardrail.get("name", guardrail_id)  # Use 'name' if available, otherwise use the identifier
        LOGGER.info(f"Checking guardrail: {guardrail_name} (ID: {guardrail_id})")

        try:
            guardrail_details = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)

            missing_features = []
            for feature, required in GUARDRAIL_FEATURES.items():
                if required:
                    LOGGER.info(f"Checking feature: {feature}")
                    if feature == "content_filters" and not guardrail_details.get("contentPolicy"):
                        missing_features.append("content_filters")
                    elif feature == "denied_topics" and not guardrail_details.get("topicPolicy"):
                        missing_features.append("denied_topics")
                    elif feature == "word_filters" and not guardrail_details.get("wordPolicy"):
                        missing_features.append("word_filters")
                    elif feature == "sensitive_info_filters" and not guardrail_details.get("sensitiveInformationPolicy"):
                        missing_features.append("sensitive_info_filters")
                    elif feature == "contextual_grounding" and not guardrail_details.get("contextualGroundingPolicy"):
                        missing_features.append("contextual_grounding")

            if not missing_features:
                LOGGER.info(f"Guardrail {guardrail_name} is compliant")
                compliant_guardrails.append(guardrail_name)
            else:
                LOGGER.info(f"Guardrail {guardrail_name} is missing features: {missing_features}")
                non_compliant_guardrails[guardrail_name] = missing_features

        except bedrock.exceptions.ResourceNotFoundException:
            LOGGER.warning(f"Guardrail {guardrail_name} (ID: {guardrail_id}) not found")
        except ClientError as client_error:
            if client_error.response['Error']['Code'] == 'AccessDeniedException':
                LOGGER.info(
                    f"Access denied to guardrail {guardrail_name} (ID: {guardrail_id}). "
                    + "If guardrail uses KMS encryption, ensure Lambda's IAM role has permissions to the KMS key."
                )
                non_compliant_guardrails[guardrail_name] = ["(access_denied; see log for details)"]
        except Exception as e:
            LOGGER.error(f"Error checking guardrail {guardrail_name} (ID: {guardrail_id}): {str(e)}")

    LOGGER.info("Determining overall compliance status")
    if compliant_guardrails:
        compliance_type = "COMPLIANT"
        if len(compliant_guardrails) == 1:
            annotation = f"The following Bedrock guardrail contains all required features: {compliant_guardrails[0]}"
        else:
            annotation = f"The following Bedrock guardrails contain all required features: {', '.join(compliant_guardrails)}"
        LOGGER.info(f"Account is COMPLIANT. {annotation}")
    else:
        compliance_type = "NON_COMPLIANT"
        annotation = "No Bedrock guardrails contain all required features. "
        for guardrail, missing in non_compliant_guardrails.items():  # type: ignore
            annotation += f" [{guardrail} is missing {', '.join(missing)}]"
        LOGGER.info(f"Account is NON_COMPLIANT. {annotation}")

    evaluation = {
        "ComplianceResourceType": "AWS::::Account",
        "ComplianceResourceId": event["accountId"],
        "ComplianceType": compliance_type,
        "Annotation": annotation,
        "OrderingTimestamp": datetime.now().isoformat(),
    }

    LOGGER.info("Sending evaluation results to AWS Config")
    config = boto3.client("config")

    try:
        response = config.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])  # type: ignore
        LOGGER.info(f"Evaluation sent successfully: {response}")
    except Exception as e:
        LOGGER.error(f"Error sending evaluation: {str(e)}")
        raise

    LOGGER.info("Lambda function execution completed")
    return {"statusCode": 200, "body": json.dumps("Evaluation complete")}
