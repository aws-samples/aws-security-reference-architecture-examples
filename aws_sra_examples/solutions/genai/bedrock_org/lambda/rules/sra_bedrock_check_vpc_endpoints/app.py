
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
ec2_client = boto3.client('ec2', region_name=AWS_REGION)
config_client = boto3.client('config', region_name=AWS_REGION)

def evaluate_compliance(vpc_id, rule_parameters):
    """Evaluates if the required VPC endpoints are in place"""
    
    # Parse rule parameters
    params = json.loads(json.dumps(rule_parameters)) if rule_parameters else {}
    check_bedrock = params.get('check_bedrock', 'true').lower() == 'true'
    check_bedrock_agent = params.get('check_bedrock_agent', 'true').lower() == 'true'
    check_bedrock_agent_runtime = params.get('check_bedrock_agent_runtime', 'true').lower() == 'true'
    check_bedrock_runtime = params.get('check_bedrock_runtime', 'true').lower() == 'true'

    required_endpoints = []
    if check_bedrock:
        required_endpoints.append(f'com.amazonaws.{AWS_REGION}.bedrock')
    if check_bedrock_agent:
        required_endpoints.append(f'com.amazonaws.{AWS_REGION}.bedrock-agent')
    if check_bedrock_agent_runtime:
        required_endpoints.append(f'com.amazonaws.{AWS_REGION}.bedrock-agent-runtime')
    if check_bedrock_runtime:
        required_endpoints.append(f'com.amazonaws.{AWS_REGION}.bedrock-runtime')

    # Get VPC endpoints
    response = ec2_client.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    
    existing_endpoints = [endpoint['ServiceName'] for endpoint in response['VpcEndpoints']]
    
    LOGGER.info(f"Checking VPC {vpc_id} for endpoints: {required_endpoints}")
    LOGGER.info(f"Existing endpoints: {existing_endpoints}")

    missing_endpoints = [endpoint for endpoint in required_endpoints if endpoint not in existing_endpoints]

    if missing_endpoints:
        LOGGER.info(f"Missing endpoints for VPC {vpc_id}: {missing_endpoints}")
        return 'NON_COMPLIANT', f"VPC {vpc_id} is missing the following Bedrock endpoints: {', '.join(missing_endpoints)}"
    else:
        LOGGER.info(f"All required endpoints are in place for VPC {vpc_id}")
        return 'COMPLIANT', f"VPC {vpc_id} has all required Bedrock endpoints: {', '.join(required_endpoints)}"

def lambda_handler(event, context):
    LOGGER.info('Evaluating compliance for AWS Config rule')
    LOGGER.info(f"Event: {json.dumps(event)}")

    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters']) if 'ruleParameters' in event else {}

    if invoking_event['messageType'] == 'ScheduledNotification':
        # This is a scheduled run, evaluate all VPCs
        evaluations = []
        vpcs = ec2_client.describe_vpcs()
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            compliance_type, annotation = evaluate_compliance(vpc_id, rule_parameters)
            evaluations.append({
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'ComplianceResourceId': vpc_id,
                'ComplianceType': compliance_type,
                'Annotation': annotation,
                'OrderingTimestamp': invoking_event['notificationCreationTime']
            })
    else:
        # This is a configuration change event
        configuration_item = invoking_event['configurationItem']
        if configuration_item['resourceType'] != 'AWS::EC2::VPC':
            LOGGER.info(f"Skipping non-VPC resource: {configuration_item['resourceType']}")
            return

        vpc_id = configuration_item['resourceId']
        compliance_type, annotation = evaluate_compliance(vpc_id, rule_parameters)
        evaluations = [{
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': vpc_id,
            'ComplianceType': compliance_type,
            'Annotation': annotation,
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        }]

    # Submit compliance evaluations
    if evaluations:
        config_client.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event['resultToken']
        )

    LOGGER.info(f"Compliance evaluation complete. Processed {len(evaluations)} evaluations.")