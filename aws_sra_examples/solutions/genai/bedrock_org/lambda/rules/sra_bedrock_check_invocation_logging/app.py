import boto3
import json
import os
import logging

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

def evaluate_compliance(rule_parameters):
    """Evaluates if Bedrock Model Invocation Logging is properly configured"""
    
    # Parse rule parameters
    params = json.loads(json.dumps(rule_parameters)) if rule_parameters else {}
    check_cloudwatch = params.get('check_cloudwatch', 'true').lower() == 'true'
    check_s3 = params.get('check_s3', 'true').lower() == 'true'

    try:
        response = bedrock_client.get_model_invocation_logging_configuration()
        logging_config = response.get('loggingConfig', {})
        
        cloudwatch_enabled = logging_config.get('cloudWatchConfig', {}).get('enabled', False)
        s3_enabled = logging_config.get('s3Config', {}).get('enabled', False)
        
        cloudwatch_log_group = logging_config.get('cloudWatchConfig', {}).get('logGroupName', 'Not configured')
        s3_bucket = logging_config.get('s3Config', {}).get('s3BucketName', 'Not configured')

        missing_configs = []
        enabled_configs = []

        if check_cloudwatch and not cloudwatch_enabled:
            missing_configs.append('CloudWatch')
        elif check_cloudwatch:
            enabled_configs.append(f'CloudWatch (Log Group: {cloudwatch_log_group})')

        if check_s3 and not s3_enabled:
            missing_configs.append('S3')
        elif check_s3:
            enabled_configs.append(f'S3 (Bucket: {s3_bucket})')

        if missing_configs:
            return 'NON_COMPLIANT', f"Bedrock Model Invocation Logging is not configured for: {', '.join(missing_configs)}. " \
                                    f"Enabled configurations: {', '.join(enabled_configs) if enabled_configs else 'None'}"
        else:
            return 'COMPLIANT', f"Bedrock Model Invocation Logging is properly configured. " \
                                f"Enabled configurations: {', '.join(enabled_configs)}"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Model Invocation Logging configuration: {str(e)}")
        return 'ERROR', f"Error evaluating compliance: {str(e)}"

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

    LOGGER.info("Compliance evaluation complete.")