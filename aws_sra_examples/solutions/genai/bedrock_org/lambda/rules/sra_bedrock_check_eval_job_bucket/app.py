import boto3
from botocore.exceptions import ClientError

def evaluate_compliance(configuration_item, rule_parameters):
    # Get the specified bucket name from rule parameters
    specified_bucket = rule_parameters.get('BedrockModelEvalJobBucketName')
    if not specified_bucket:
        return 'NON_COMPLIANT', 'BedrockModelEvalJobBucketName parameter is not specified'

    # Extract the bucket name from the configuration item
    evaluated_bucket = configuration_item['resourceName']

    # Check if the evaluated bucket matches the specified Bedrock model evaluation job bucket
    if evaluated_bucket != specified_bucket:
        return 'NOT_APPLICABLE', f'This bucket is not the specified Bedrock model evaluation job bucket ({specified_bucket})'

    # Initialize S3 client
    s3 = boto3.client('s3')

    # Set default values for configurable parameters
    check_retention = rule_parameters.get('CheckRetention', 'true').lower() == 'true'
    check_encryption = rule_parameters.get('CheckEncryption', 'true').lower() == 'true'
    check_logging = rule_parameters.get('CheckLogging', 'true').lower() == 'true'
    check_object_locking = rule_parameters.get('CheckObjectLocking', 'true').lower() == 'true'
    check_versioning = rule_parameters.get('CheckVersioning', 'true').lower() == 'true'

    try:
        # Check retention policy
        if check_retention:
            try:
                retention = s3.get_bucket_lifecycle_configuration(Bucket=evaluated_bucket)
                if not any(rule.get('Expiration') for rule in retention['Rules']):
                    return 'NON_COMPLIANT', 'Bucket does not have a retention policy'
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                    return 'NON_COMPLIANT', 'Bucket does not have a retention policy'
                raise

        # Check KMS CMK encryption
        if check_encryption:
            encryption = s3.get_bucket_encryption(Bucket=evaluated_bucket)
            if 'ServerSideEncryptionConfiguration' not in encryption:
                return 'NON_COMPLIANT', 'Bucket is not encrypted with KMS CMK'
            sse_config = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
            if sse_config['SSEAlgorithm'] != 'aws:kms':
                return 'NON_COMPLIANT', 'Bucket is not encrypted with KMS CMK'

        # Check server access logging
        if check_logging:
            logging = s3.get_bucket_logging(Bucket=evaluated_bucket)
            if 'LoggingEnabled' not in logging:
                return 'NON_COMPLIANT', 'Server access logging is not enabled'

        # Check object locking
        if check_object_locking:
            object_locking = s3.get_object_lock_configuration(Bucket=evaluated_bucket)
            if 'ObjectLockConfiguration' not in object_locking:
                return 'NON_COMPLIANT', 'Object locking is not enabled'

        # Check versioning
        if check_versioning:
            versioning = s3.get_bucket_versioning(Bucket=evaluated_bucket)
            if 'Status' not in versioning or versioning['Status'] != 'Enabled':
                return 'NON_COMPLIANT', 'Versioning is not enabled'

        return 'COMPLIANT', 'Bucket meets all security requirements'

    except ClientError as e:
        return 'NON_COMPLIANT', f'Error evaluating bucket: {str(e)}'

def lambda_handler(event, context):
    invoking_event = event['invokingEvent']
    rule_parameters = event['ruleParameters']
    configuration_item = invoking_event['configurationItem']

    compliance_type, annotation = evaluate_compliance(configuration_item, rule_parameters)

    config = boto3.client('config')
    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': configuration_item['resourceId'],
                'ComplianceType': compliance_type,
                'Annotation': annotation,
                'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken']
    )

    return {
        'compliance_type': compliance_type,
        'annotation': annotation
    }