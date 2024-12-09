from typing import Any
import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime
import logging
import os  # maybe not needed for logging
import ast

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False
DEFAULT_RESOURCE_TYPE = "AWS::S3::Bucket"

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

# Define the AWS Config rule parameters
RULE_NAME = "sra-bedrock-check-eval-job-bucket"
SERVICE_NAME = "bedrock.amazonaws.com"


def evaluate_compliance(event: dict, context: Any) -> tuple[str, str]:
    LOGGER.info(f"Evaluate Compliance Event: {event}")
    # Initialize AWS clients
    s3 = boto3.client('s3')
    config = boto3.client('config')

    # Get rule parameters
    params = ast.literal_eval(event['ruleParameters'])
    LOGGER.info(f"Parameters: {params}")
    bucket_name = params.get('BucketName', '')
    check_retention = params.get('CheckRetention', 'true').lower() != 'false'
    check_encryption = params.get('CheckEncryption', 'true').lower() != 'false'
    check_logging = params.get('CheckLogging', 'true').lower() != 'false'
    check_object_locking = params.get('CheckObjectLocking', 'true').lower() != 'false'
    check_versioning = params.get('CheckVersioning', 'true').lower() != 'false'

    # Check if the bucket exists
    # try:
    #     s3.head_bucket(Bucket=bucket_name)
    # except ClientError as e:
    if not check_bucket_exists(bucket_name):
        return build_evaluation('NOT_APPLICABLE', f"Bucket {bucket_name} does not exist or is not accessible")

    compliance_type = 'COMPLIANT'
    annotation = []

    # Check retention
    if check_retention:
        try:
            retention = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            if not any(rule.get('Expiration') for rule in retention.get('Rules', [])):
                compliance_type = 'NON_COMPLIANT'
                annotation.append("Retention policy not set")
        except ClientError:
            compliance_type = 'NON_COMPLIANT'
            annotation.append("Retention policy not set")

    # Check encryption
    if check_encryption:
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if 'ServerSideEncryptionConfiguration' not in encryption:
                compliance_type = 'NON_COMPLIANT'
                annotation.append("KMS CMK encryption not enabled")
        except ClientError:
            compliance_type = 'NON_COMPLIANT'
            annotation.append("KMS CMK encryption not enabled")

    # Check logging
    if check_logging:
        logging = s3.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' not in logging:
            compliance_type = 'NON_COMPLIANT'
            annotation.append("Server access logging not enabled")

    # Check object locking
    if check_object_locking:
        try:
            object_locking = s3.get_object_lock_configuration(Bucket=bucket_name)
            if 'ObjectLockConfiguration' not in object_locking:
                compliance_type = 'NON_COMPLIANT'
                annotation.append("Object locking not enabled")
        except ClientError:
            compliance_type = 'NON_COMPLIANT'
            annotation.append("Object locking not enabled")

    # Check versioning
    if check_versioning:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get('Status') != 'Enabled':
            compliance_type = 'NON_COMPLIANT'
            annotation.append("Versioning not enabled")

    annotation_str = '; '.join(annotation) if annotation else "All checked features are compliant"
    return build_evaluation(compliance_type, annotation_str)

def check_bucket_exists(bucket_name: str) -> Any:
    s3 = boto3.client('s3')
    try:
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        return bucket_name in buckets
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False

def build_evaluation(compliance_type: str, annotation: str) -> Any:
    LOGGER.info(f"Build Evaluation Compliance Type: {compliance_type} Annotation: {annotation}")
    return {
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': datetime.now().isoformat()
    }

def lambda_handler(event: dict, context: Any) -> None:
    LOGGER.info(f"Lambda Handler Event: {event}")
    evaluation = evaluate_compliance(event, context)
    config = boto3.client('config')
    params = ast.literal_eval(event['ruleParameters'])
    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': 'AWS::S3::Bucket',
                'ComplianceResourceId': params.get('BucketName'),
                'ComplianceType': evaluation['ComplianceType'], # type: ignore
                'Annotation': evaluation['Annotation'], # type: ignore
                'OrderingTimestamp': evaluation['OrderingTimestamp'] # type: ignore
            }
        ],
        ResultToken=event['resultToken']
    )