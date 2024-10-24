import boto3
import json
import os
import logging
import botocore

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

# Get AWS region from environment variable
AWS_REGION = os.environ.get('AWS_REGION')

# Initialize AWS clients
bedrock_client = boto3.client('bedrock', region_name=AWS_REGION)
config_client = boto3.client('config', region_name=AWS_REGION)
s3_client = boto3.client('s3', region_name=AWS_REGION)

def evaluate_compliance(rule_parameters):
    """Evaluates if Bedrock Model Invocation Logging is properly configured for S3"""
    
    # Parse rule parameters
    params = json.loads(json.dumps(rule_parameters)) if rule_parameters else {}
    check_retention = params.get('check_retention', 'true').lower() == 'true'
    check_encryption = params.get('check_encryption', 'true').lower() == 'true'
    check_access_logging = params.get('check_access_logging', 'true').lower() == 'true'
    check_object_locking = params.get('check_object_locking', 'true').lower() == 'true'
    check_versioning = params.get('check_versioning', 'true').lower() == 'true'

    try:
        response = bedrock_client.get_model_invocation_logging_configuration()
        logging_config = response.get('loggingConfig', {})
        
        s3_config = logging_config.get('s3Config', {})
        LOGGER.info(f"Bedrock Model Invocation S3 config: {s3_config}")
        bucket_name = s3_config.get('bucketName', "")
        LOGGER.info(f"Bedrock Model Invocation S3 bucketName: {bucket_name}")

        if not s3_config or not bucket_name:
            return 'NON_COMPLIANT', "S3 logging is not enabled for Bedrock Model Invocation Logging"

        # Check S3 bucket configurations
        issues = []

        if check_retention:
            lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            if not any(rule.get('Expiration') for rule in lifecycle.get('Rules', [])):
                issues.append("retention not set")

        if check_encryption:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            if 'ServerSideEncryptionConfiguration' not in encryption:
                issues.append("encryption not set")

        if check_access_logging:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging:
                issues.append("server access logging not enabled")

        if check_versioning:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                issues.append("versioning not enabled")
        try:
            if check_object_locking:
                object_lock = s3_client.get_object_lock_configuration(Bucket=bucket_name)
                if 'ObjectLockConfiguration' not in object_lock:
                    issues.append("object locking not enabled")
        except botocore.exceptions.ClientError as error:
            error_code = error.response['Error']['Code']
            if error_code == "ObjectLockConfigurationNotFoundError":
                LOGGER.info(f"Object Lock is not enabled for S3 bucket: {bucket_name}")
                issues.append("object locking not enabled")
            else:
                LOGGER.info(f"Error evaluating Object Lock configuration: {str(error)}")
                return 'INSUFFICIENT_DATA', f"Error evaluating Object Lock configuration: {str(error)}"
        # except Exception as error:
        #     error_code = type(error).__name__
        #     if error_code == "ObjectLockConfigurationNotFoundError":
        #         LOGGER.info(f"Object Lock is not enabled for S3 bucket: {bucket_name}")
        #         return 'NON_COMPLIANT', f"Object Lock is not enabled for S3 bucket: {bucket_name}"
        #     else:
        #         LOGGER.error(f"Error evaluating Object Lock configuration: {str(error)}")
        #         return 'INSUFFICIENT_DATA', f"Error evaluating Object Lock configuration: {str(error)}"

        if issues:
            return 'NON_COMPLIANT', f"S3 logging enabled but {', '.join(issues)}"
        else:
            return 'COMPLIANT', f"S3 logging properly configured for Bedrock Model Invocation Logging. Bucket: {bucket_name}"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Model Invocation Logging configuration: {str(e)}")
        return 'INSUFFICIENT_DATA', f"Error evaluating compliance: {str(e)}"

def lambda_handler(event, context):
    LOGGER.info('Evaluating compliance for AWS Config rule')
    LOGGER.info(f"Event: {json.dumps(event)}")

    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters']) if 'ruleParameters' in event else {}

    compliance_type, annotation = evaluate_compliance(rule_parameters)
    
    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': event['accountId'],
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': invoking_event['notificationCreationTime']
    }

    LOGGER.info(f"Compliance evaluation result: {compliance_type}")
    LOGGER.info(f"Annotation: {annotation}")

    config_client.put_evaluations(
        Evaluations=[evaluation],
        ResultToken=event['resultToken']
    )
# ^^^ [ERROR] ValidationException: An error occurred (ValidationException) when calling the PutEvaluations operation: 
# 1 validation error detected: Value 'ERROR' at 'evaluations.1.member.complianceType' failed to satisfy constraint: Member must satisfy enum value set: [INSUFFICIENT_DATA, NON_COMPLIANT, NOT_APPLICABLE, COMPLIANT]

    LOGGER.info("Compliance evaluation complete.")