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
    """Evaluates if Bedrock guardrails are encrypted with a KMS key"""
    
    try:
        response = bedrock_client.list_guardrails()
        guardrails = response.get('guardrails', [])

        if not guardrails:
            return 'NON_COMPLIANT', "No Bedrock guardrails found"

        unencrypted_guardrails = []
        for guardrail in guardrails:
            guardrail_id = guardrail['id']
            guardrail_name = guardrail['name']
            guardrail_detail = bedrock_client.get_guardrail(guardrailIdentifier=guardrail_id)
            
            if 'kmsKeyArn' not in guardrail_detail:
                unencrypted_guardrails.append(guardrail_name)

        if unencrypted_guardrails:
            return 'NON_COMPLIANT', f"The following Bedrock guardrails are not encrypted with a KMS key: {', '.join(unencrypted_guardrails)}"
        else:
            return 'COMPLIANT', "All Bedrock guardrails are encrypted with a KMS key"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock guardrails encryption: {str(e)}")
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