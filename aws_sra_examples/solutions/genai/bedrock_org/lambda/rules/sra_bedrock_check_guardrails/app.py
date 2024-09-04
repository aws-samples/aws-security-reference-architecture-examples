import boto3
import json
from datetime import datetime
import ast
import logging
import os

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

GUARDRAIL_FEATURES = {
    'content_filters': True,
    'denied_topics': True,
    'word_filters': True,
    'sensitive_info_filters': True,
    'contextual_grounding': True
}

def evaluate_compliance(configuration_item, rule_parameters):
    return 'NOT_APPLICABLE'

def lambda_handler(event, context):
    LOGGER.info("Starting lambda_handler function")
    bedrock = boto3.client('bedrock')

    # Parse rule parameters safely using ast.literal_eval
    LOGGER.info("Parsing rule parameters")
    rule_params = ast.literal_eval(event.get('ruleParameters', '{}'))
    for param, default in GUARDRAIL_FEATURES.items():
        GUARDRAIL_FEATURES[param] = rule_params.get(param, default)
    LOGGER.info(f"Guardrail features to check: {GUARDRAIL_FEATURES}")

    # List all guardrails
    LOGGER.info("Listing all Bedrock guardrails")
    guardrails = bedrock.list_guardrails()['guardrails']
    LOGGER.info(f"Found {len(guardrails)} guardrails")

    compliant_guardrails = []
    non_compliant_guardrails = {}

    for guardrail in guardrails:
        guardrail_id = guardrail['id']
        guardrail_name = guardrail.get('name', guardrail_id)  # Use 'name' if available, otherwise use the identifier
        LOGGER.info(f"Checking guardrail: {guardrail_name} (ID: {guardrail_id})")
        
        try:
            guardrail_details = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
            
            missing_features = []
            for feature, required in GUARDRAIL_FEATURES.items():
                if required:
                    LOGGER.info(f"Checking feature: {feature}")
                    if feature == 'content_filters' and not guardrail_details.get('contentFilters'):
                        missing_features.append('content_filters')
                    elif feature == 'denied_topics' and not guardrail_details.get('deniedTopics'):
                        missing_features.append('denied_topics')
                    elif feature == 'word_filters' and not guardrail_details.get('wordFilters'):
                        missing_features.append('word_filters')
                    elif feature == 'sensitive_info_filters' and not guardrail_details.get('sensitiveInfoFilters'):
                        missing_features.append('sensitive_info_filters')
                    elif feature == 'contextual_grounding' and not guardrail_details.get('contextualGrounding'):
                        missing_features.append('contextual_grounding')

            if not missing_features:
                LOGGER.info(f"Guardrail {guardrail_name} is compliant")
                compliant_guardrails.append(guardrail_name)
            else:
                LOGGER.info(f"Guardrail {guardrail_name} is missing features: {missing_features}")
                non_compliant_guardrails[guardrail_name] = missing_features
        
        except bedrock.exceptions.ResourceNotFoundException:
            LOGGER.warning(f"Guardrail {guardrail_name} (ID: {guardrail_id}) not found")
        except Exception as e:
            LOGGER.error(f"Error checking guardrail {guardrail_name} (ID: {guardrail_id}): {str(e)}")

    LOGGER.info("Determining overall compliance status")
    if compliant_guardrails:
        compliance_type = 'COMPLIANT'
        if len(compliant_guardrails) == 1:
            annotation = f"The following Bedrock guardrail contains all required features: {compliant_guardrails[0]}"
        else:
            annotation = f"The following Bedrock guardrails contain all required features: {', '.join(compliant_guardrails)}"
        LOGGER.info(f"Account is COMPLIANT. {annotation}")
    else:
        compliance_type = 'NON_COMPLIANT'
        annotation = 'No Bedrock guardrails contain all required features. Missing features per guardrail:\n'
        for guardrail, missing in non_compliant_guardrails.items():
            annotation += f"- {guardrail}: missing {', '.join(missing)}\n"
        LOGGER.info(f"Account is NON_COMPLIANT. {annotation}")

    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': event['accountId'],
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': datetime.now().isoformat()
    }

    LOGGER.info("Sending evaluation results to AWS Config")
    config = boto3.client('config')
    
    try:
        response = config.put_evaluations(
            Evaluations=[evaluation],
            ResultToken=event['resultToken']
        )
        LOGGER.info(f"Evaluation sent successfully: {response}")
    except Exception as e:
        LOGGER.error(f"Error sending evaluation: {str(e)}")
        raise

    LOGGER.info("Lambda function execution completed")
    return {
        'statusCode': 200,
        'body': json.dumps('Evaluation complete')
    }
