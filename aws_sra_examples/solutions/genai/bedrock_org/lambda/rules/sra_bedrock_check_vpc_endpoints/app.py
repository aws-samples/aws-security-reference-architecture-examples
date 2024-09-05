
import boto3
import json
import os
import logging
import ast

# Configure logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
LOGGER = logging.getLogger()
LOGGER.setLevel(LOG_LEVEL)

# Initialize AWS clients
ec2_client = boto3.client('ec2')
config_client = boto3.client('config')

def evaluate_compliance(configuration_item, rule_parameters):
    """Evaluates if the required VPC endpoints are in place"""
    
    if configuration_item['resourceType'] != 'AWS::EC2::VPC':
        return 'NOT_APPLICABLE'

    vpc_id = configuration_item['configuration']['vpcId']
    
    # Parse rule parameters
    params = ast.literal_eval(json.dumps(rule_parameters)) if rule_parameters else {}
    check_bedrock = params.get('check_bedrock', True)
    check_bedrock_agent = params.get('check_bedrock_agent', True)
    check_bedrock_agent_runtime = params.get('check_bedrock_agent_runtime', True)
    check_bedrock_runtime = params.get('check_bedrock_runtime', True)

    required_endpoints = []
    if check_bedrock:
        required_endpoints.append('com.amazonaws.{region}.bedrock')
    if check_bedrock_agent:
        required_endpoints.append('com.amazonaws.{region}.bedrock-agent')
    if check_bedrock_agent_runtime:
        required_endpoints.append('com.amazonaws.{region}.bedrock-agent-runtime')
    if check_bedrock_runtime:
        required_endpoints.append('com.amazonaws.{region}.bedrock-runtime')

    # Get VPC endpoints
    response = ec2_client.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    
    existing_endpoints = [endpoint['ServiceName'] for endpoint in response['VpcEndpoints']]
    
    LOGGER.info(f"Checking VPC {vpc_id} for endpoints: {required_endpoints}")
    LOGGER.debug(f"Existing endpoints: {existing_endpoints}")

    missing_endpoints = [endpoint for endpoint in required_endpoints if endpoint.format(region=configuration_item['awsRegion']) not in existing_endpoints]

    if missing_endpoints:
        LOGGER.warning(f"Missing endpoints for VPC {vpc_id}: {missing_endpoints}")
        return 'NON_COMPLIANT'
    else:
        LOGGER.info(f"All required endpoints are in place for VPC {vpc_id}")
        return 'COMPLIANT'

def lambda_handler(event, context):
    LOGGER.info('Evaluating compliance for AWS Config rule')
    LOGGER.debug(f"Event: {json.dumps(event)}")

    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters']) if 'ruleParameters' in event else {}

    configuration_item = invoking_event.get('configurationItem')
    if not configuration_item:
        LOGGER.error("No configuration item found in the invoking event")
        return

    compliance_type = evaluate_compliance(configuration_item, rule_parameters)

    config_client.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': configuration_item['resourceId'],
                'ComplianceType': compliance_type,
                'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken']
    )

    LOGGER.info(f"Compliance evaluation complete. Result: {compliance_type}")