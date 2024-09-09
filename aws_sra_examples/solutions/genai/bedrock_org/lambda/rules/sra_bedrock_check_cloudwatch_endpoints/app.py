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

def evaluate_compliance(vpc_id):
    """Evaluates if a CloudWatch gateway endpoint is in place for the given VPC"""
    try:
        response = ec2_client.describe_vpc_endpoints(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'service-name', 'Values': [f'com.amazonaws.{AWS_REGION}.logs']}
            ]
        )

        endpoints = response['VpcEndpoints']
        
        if endpoints:
            endpoint_id = endpoints[0]['VpcEndpointId']
            return 'COMPLIANT', f"CloudWatch gateway endpoint is in place for VPC {vpc_id}. Endpoint ID: {endpoint_id}"
        else:
            return 'NON_COMPLIANT', f"No CloudWatch gateway endpoint found for VPC {vpc_id}"

    except Exception as e:
        LOGGER.error(f"Error evaluating CloudWatch gateway endpoint for VPC {vpc_id}: {str(e)}")
        return 'ERROR', f"Error evaluating compliance: {str(e)}"

def lambda_handler(event, context):
    LOGGER.info('Evaluating compliance for AWS Config rule')
    LOGGER.info(f"Event: {json.dumps(event)}")

    invoking_event = json.loads(event['invokingEvent'])

    evaluations = []

    if invoking_event['messageType'] == 'ScheduledNotification':
        # This is a scheduled run, evaluate all VPCs
        vpcs = ec2_client.describe_vpcs()
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            compliance_type, annotation = evaluate_compliance(vpc_id)
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
        compliance_type, annotation = evaluate_compliance(vpc_id)
        evaluations.append({
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': vpc_id,
            'ComplianceType': compliance_type,
            'Annotation': annotation,
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        })

    # Submit compliance evaluations
    if evaluations:
        config_client.put_evaluations(
            Evaluations=evaluations,
            ResultToken=event['resultToken']
        )

    LOGGER.info(f"Compliance evaluation complete. Processed {len(evaluations)} evaluations.")