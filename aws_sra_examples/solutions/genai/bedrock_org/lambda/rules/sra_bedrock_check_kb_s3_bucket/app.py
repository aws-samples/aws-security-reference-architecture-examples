"""Config rule to check knowledge base S3 bucket configuration for Bedrock environments.

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
s3_client = boto3.client("s3", region_name=AWS_REGION)
config_client = boto3.client("config", region_name=AWS_REGION)

def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:
    """Evaluate if Bedrock Knowledge Base S3 bucket has required configurations.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance status and annotation
    """
    try:
        # Get all knowledge bases
        non_compliant_buckets = []
        paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")
        
        for page in paginator.paginate():
            for kb in page["knowledgeBaseSummaries"]:
                kb_id = kb["knowledgeBaseId"]
                
                # List data sources for this knowledge base
                data_sources_paginator = bedrock_agent_client.get_paginator("list_data_sources")
                
                for ds_page in data_sources_paginator.paginate(knowledgeBaseId=kb_id):
                    for ds in ds_page.get("dataSourceSummaries", []):
                        data_source = bedrock_agent_client.get_data_source(
                            knowledgeBaseId=kb_id,
                            dataSourceId=ds["dataSourceId"]
                        )
                        
                        # Check if this is an S3 data source and extract bucket name
                        LOGGER.info(f"Data source structure: {json.dumps(data_source)}")
                        if "s3Configuration" in data_source.get("dataSource", {}).get("dataSourceConfiguration", {}):
                            s3_config = data_source["dataSource"]["dataSourceConfiguration"]["s3Configuration"]
                            bucket_name = s3_config.get("bucketName", "")
                        else:
                            continue
                        
                        if not bucket_name:
                            LOGGER.info(f"No bucket name found for data source {ds['dataSourceId']}")
                            continue
                        
                        # If bucket name contains a path, extract just the bucket name
                        if "/" in bucket_name:
                            bucket_name = bucket_name.split("/")[0]
                        
                        LOGGER.info(f"Checking S3 bucket: {bucket_name}")
                        
                        issues = []
                        
                        # Check retention
                        if rule_parameters.get("check_retention", "true").lower() == "true":
                            try:
                                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                                if not any(rule.get("Expiration") for rule in lifecycle.get("Rules", [])):
                                    issues.append("retention")
                            except ClientError as e:
                                if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                                    issues.append("retention")
                                elif e.response["Error"]["Code"] != "NoSuchBucket":
                                    LOGGER.error(f"Error checking retention for bucket {bucket_name}: {str(e)}")

                        # Check encryption
                        if rule_parameters.get("check_encryption", "true").lower() == "true":
                            try:
                                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                                if not encryption.get("ServerSideEncryptionConfiguration"):
                                    issues.append("encryption")
                            except ClientError as e:
                                if e.response["Error"]["Code"] != "NoSuchBucket":
                                    issues.append("encryption")

                        # Check server access logging
                        if rule_parameters.get("check_access_logging", "true").lower() == "true":
                            try:
                                logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                                if not logging_config.get("LoggingEnabled"):
                                    issues.append("access logging")
                            except ClientError as e:
                                if e.response["Error"]["Code"] != "NoSuchBucket":
                                    issues.append("access logging")

                        # Check object lock
                        if rule_parameters.get("check_object_locking", "true").lower() == "true":
                            try:
                                lock_config = s3_client.get_object_lock_configuration(Bucket=bucket_name)
                                if not lock_config.get("ObjectLockConfiguration"):
                                    issues.append("object locking")
                            except ClientError as e:
                                if e.response["Error"]["Code"] != "NoSuchBucket":
                                    issues.append("object locking")

                        # Check versioning
                        if rule_parameters.get("check_versioning", "true").lower() == "true":
                            try:
                                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                                if versioning.get("Status") != "Enabled":
                                    issues.append("versioning")
                            except ClientError as e:
                                if e.response["Error"]["Code"] != "NoSuchBucket":
                                    issues.append("versioning")

                        if issues:
                            non_compliant_buckets.append(f"{bucket_name} (missing: {', '.join(issues)})")

        if non_compliant_buckets:
            return "NON_COMPLIANT", f"The following KB S3 buckets are non-compliant: {'; '.join(non_compliant_buckets)}"
        return "COMPLIANT", "All Knowledge Base S3 buckets meet the required configurations"

    except Exception as e:
        LOGGER.error(f"Error evaluating Knowledge Base S3 bucket configurations: {str(e)}")
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
    