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
config_client = boto3.client("config", region_name=AWS_REGION)

def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:
    """Evaluate if Bedrock Knowledge Base OpenSearch vector stores are encrypted with KMS CMK.

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
                
                try:
                    # Get knowledge base details
                    kb_details = bedrock_agent_client.get_knowledge_base(knowledgeBaseId=kb_id)
                    vector_store = kb_details.get("vectorStoreConfiguration")
                    
                    if vector_store and vector_store.get("vectorStoreType") == "OPENSEARCH":
                        # Extract OpenSearch domain information
                        opensearch_config = vector_store.get("opensearchServerlessConfiguration") or vector_store.get("opensearchConfiguration")
                        
                        if not opensearch_config:
                            non_compliant_kbs.append(f"{kb_name} (missing OpenSearch configuration)")
                            continue
                            
                        # Check if it's OpenSearch Serverless or standard OpenSearch
                        if "collectionArn" in opensearch_config:
                            # OpenSearch Serverless - always encrypted with AWS owned key at minimum
                            collection_id = opensearch_config["collectionArn"].split("/")[-1]
                            try:
                                collection = opensearch_client.get_security_policy(
                                    Name=collection_id,
                                    Type="encryption"
                                )
                                # Check if using customer managed key
                                security_policy = collection.get("securityPolicyDetail", {})
                                if security_policy.get("Type") == "encryption":
                                    encryption_policy = security_policy.get("SecurityPolicies", [])[0]
                                    kms_key_arn = encryption_policy.get("KmsARN", "")
                                    
                                    # If not using customer managed key
                                    if not kms_key_arn or "aws/opensearchserverless" in kms_key_arn:
                                        non_compliant_kbs.append(f"{kb_name} (OpenSearch Serverless not using CMK)")
                            except ClientError as e:
                                LOGGER.error(f"Error checking OpenSearch Serverless collection: {str(e)}")
                                non_compliant_kbs.append(f"{kb_name} (error checking OpenSearch Serverless)")
                        else:
                            # Standard OpenSearch
                            domain_endpoint = opensearch_config.get("endpoint", "")
                            if not domain_endpoint:
                                non_compliant_kbs.append(f"{kb_name} (missing OpenSearch domain endpoint)")
                                continue
                                
                            # Extract domain name from endpoint
                            domain_name = domain_endpoint.split(".")[0]
                            
                            try:
                                domain = opensearch_client.describe_domain(DomainName=domain_name)
                                encryption_config = domain.get("DomainStatus", {}).get("EncryptionAtRestOptions", {})
                                
                                # Check if encryption is enabled and using CMK
                                if not encryption_config.get("Enabled", False):
                                    non_compliant_kbs.append(f"{kb_name} (OpenSearch domain encryption not enabled)")
                                elif not encryption_config.get("KmsKeyId"):
                                    non_compliant_kbs.append(f"{kb_name} (OpenSearch domain not using CMK)")
                            except ClientError as e:
                                LOGGER.error(f"Error checking OpenSearch domain: {str(e)}")
                                non_compliant_kbs.append(f"{kb_name} (error checking OpenSearch domain)")
                
                except ClientError as e:
                    LOGGER.error(f"Error checking knowledge base {kb_id}: {str(e)}")
                    if e.response["Error"]["Code"] == "AccessDeniedException":
                        non_compliant_kbs.append(f"{kb_name} (access denied)")
                    else:
                        raise

        if non_compliant_kbs:
            return "NON_COMPLIANT", f"The following knowledge bases have OpenSearch vector stores not encrypted with CMK: {'; '.join(non_compliant_kbs)}"
        return "COMPLIANT", "All knowledge base OpenSearch vector stores are encrypted with KMS CMK"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Knowledge Base OpenSearch encryption: {str(e)}")
        return "ERROR", f"Error evaluating compliance: {str(e)}"

def lambda_handler(event: dict, context: Any) -> None:
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

    config_client.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])

    LOGGER.info("Compliance evaluation complete.") 