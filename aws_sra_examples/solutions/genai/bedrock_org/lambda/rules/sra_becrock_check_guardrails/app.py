import boto3
import json
from datetime import datetime

# Define the guardrail types as parameters
GUARDRAIL_PARAMETERS = {
    'check_safe_content': True,
    'check_responsible_ai': True,
    'check_data_privacy': True,
    'check_content_filtering': True,
    'check_token_limit': True
}

def evaluate_compliance(configuration_item, rule_parameters):
    # This function is not used for scheduled rules, but is required by AWS Config
    return 'NOT_APPLICABLE'

def lambda_handler(event, context):
    # Initialize the Bedrock client
    bedrock = boto3.client('bedrock')

    # Get rule parameters, use defaults if not provided
    rule_params = event.get('ruleParameters', {})
    for param, default in GUARDRAIL_PARAMETERS.items():
        GUARDRAIL_PARAMETERS[param] = rule_params.get(param, default)

    # Get all available Bedrock model providers
    model_providers = bedrock.list_foundation_models()['modelSummaries']

    all_compliant = True
    non_compliant_models = []

    for model in model_providers:
        model_id = model['modelId']
        
        try:
            # Get the guardrails for each model
            guardrails = bedrock.get_foundation_model_guardrails(modelId=model_id)
            
            # Check if all selected guardrails are enabled
            for guardrail in guardrails['guardrails']:
                guardrail_type = guardrail['type'].lower()
                if guardrail_type in GUARDRAIL_PARAMETERS and GUARDRAIL_PARAMETERS[f'check_{guardrail_type}']:
                    if not guardrail['enabled']:
                        all_compliant = False
                        non_compliant_models.append(f"{model_id} ({guardrail_type})")
        except bedrock.exceptions.ResourceNotFoundException:
            # If the model doesn't support guardrails, skip it
            continue

    if all_compliant:
        compliance_type = 'COMPLIANT'
        annotation = 'All supported Bedrock models have the selected guardrails enabled.'
    else:
        compliance_type = 'NON_COMPLIANT'
        annotation = f'The following models do not have all selected guardrails enabled: {", ".join(non_compliant_models)}'

    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': event['accountId'],
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': str(datetime.now().isoformat())
    }

    result = {
        'evaluations': [evaluation],
        'resultToken': event['resultToken']
    }

    config = boto3.client('config')
    config.put_evaluations(**result)

    return result