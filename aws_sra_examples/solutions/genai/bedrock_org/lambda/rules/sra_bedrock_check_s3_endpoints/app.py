
from typing import Any
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

def evaluate_compliance(configuration_item: dict) -> tuple[str, str]:
    """Evaluates if an S3 Gateway Endpoint is in place for the VPC"""
    
    if configuration_item['resourceType'] != 'AWS::EC2::VPC':
        return 'NOT_APPLICABLE', "Resource is not a VPC"

    vpc_id = configuration_item['configuration']['vpcId']
    
    try:
        response = ec2_client.describe_vpc_endpoints(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'service-name', 'Values': [f'com.amazonaws.{AWS_REGION}.s3']},
                {'Name': 'vpc-endpoint-type', 'Values': ['Gateway']}
            ]
        )

        if response['VpcEndpoints']:
            endpoint_id = response['VpcEndpoints'][0]['VpcEndpointId']
            return 'COMPLIANT', f"S3 Gateway Endpoint is in place for VPC {vpc_id}. Endpoint ID: {endpoint_id}"
        else:
            return 'NON_COMPLIANT', f"S3 Gateway Endpoint is not in place for VPC {vpc_id}"

    except Exception as e:
        LOGGER.error(f"Error evaluating S3 Gateway Endpoint configuration: {str(e)}")
        return 'ERROR', f"Error evaluating compliance: {str(e)}"

def lambda_handler(event: dict, context: Any) -> None:
    LOGGER.info('Evaluating compliance for AWS Config rule')
    LOGGER.info(f"Event: {json.dumps(event)}")

    invoking_event = json.loads(event['invokingEvent'])

    if invoking_event['messageType'] == 'ConfigurationItemChangeNotification':
        configuration_item = invoking_event['configurationItem']
        compliance_type, annotation = evaluate_compliance(configuration_item)
        evaluation = {
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': configuration_item['resourceId'],
            'ComplianceType': compliance_type,
            'Annotation': annotation,
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        }
        evaluations = [evaluation]
    elif invoking_event['messageType'] == 'ScheduledNotification':
        # For scheduled evaluations, check all VPCs
        evaluations = []
        vpcs = ec2_client.describe_vpcs()
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            mock_configuration_item = {'resourceType': 'AWS::EC2::VPC', 'configuration': {'vpcId': vpc_id}}
            compliance_type, annotation = evaluate_compliance(mock_configuration_item)
            evaluations.append({
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'ComplianceResourceId': vpc_id,
                'ComplianceType': compliance_type,
                'Annotation': annotation,
                'OrderingTimestamp': invoking_event['notificationCreationTime']
            })
    else:
        LOGGER.error(f"Unsupported message type: {invoking_event['messageType']}")
        return

    # Submit compliance evaluations
    if evaluations:
        config_client.put_evaluations(
            Evaluations=evaluations, # type: ignore
            ResultToken=event['resultToken']
        )

    LOGGER.info(f"Compliance evaluation complete. Processed {len(evaluations)} evaluations.")