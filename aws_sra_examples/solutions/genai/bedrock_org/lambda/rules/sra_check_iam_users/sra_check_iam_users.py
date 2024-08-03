import botocore
import boto3
import json
import datetime
import logging
import os  # maybe not needed for logging

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False
DEFAULT_RESOURCE_TYPE = "AWS::::Account"

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")


# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(
        service,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_assume_role_credentials(role_arn):
    sts_client = boto3.client("sts")
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response["Credentials"]
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if "AccessDenied" in ex.response["Error"]["Code"]:
            ex.response["Error"]["Message"] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response["Error"]["Message"] = "InternalError"
            ex.response["Error"]["Code"] = "InternalError"
        raise ex


# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    return message_type == "ScheduledNotification"


def count_resource_types(applicable_resource_type, next_token, count):
    resource_identifier = AWS_CONFIG_CLIENT.list_discovered_resources(resourceType=applicable_resource_type, nextToken=next_token)
    updated = count + len(resource_identifier["resourceIdentifiers"])
    return updated


# Evaluates the configuration items in the snapshot and returns the compliance value to the handler.
def evaluate_compliance(max_count, actual_count):
    return "NON_COMPLIANT" if int(actual_count) > int(max_count) else "COMPLIANT"


def evaluate_parameters(rule_parameters):
    if "applicableResourceType" not in rule_parameters:
        raise ValueError('The parameter with "applicableResourceType" as key must be defined.')
    if not rule_parameters["applicableResourceType"]:
        raise ValueError('The parameter "applicableResourceType" must have a defined value.')
    return rule_parameters


# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc["Annotation"] = annotation
    eval_cc["ComplianceResourceType"] = resource_type
    eval_cc["ComplianceResourceId"] = resource_id
    eval_cc["ComplianceType"] = compliance_type
    eval_cc["OrderingTimestamp"] = str(json.loads(event["invokingEvent"])["notificationCreationTime"])
    return eval_cc


def lambda_handler(event, context):
    LOGGER.info(event)
    global AWS_CONFIG_CLIENT

    evaluations = []
    rule_parameters = {}
    resource_count = 0
    max_count = 0

    invoking_event = json.loads(event["invokingEvent"])
    if "ruleParameters" in event:
        rule_parameters = json.loads(event["ruleParameters"])

    valid_rule_parameters = evaluate_parameters(rule_parameters)

    compliance_value = "NOT_APPLICABLE"

    AWS_CONFIG_CLIENT = get_client("config", event)
    if is_scheduled_notification(invoking_event["messageType"]):
        result_resource_count = count_resource_types(valid_rule_parameters["applicableResourceType"], "", resource_count)

    if valid_rule_parameters.get("maxCount"):
        max_count = valid_rule_parameters["maxCount"]
        LOGGER.info(f"maxCount set to: {max_count} from rule parameter")
    else:
        LOGGER.info(f"maxCount set to: {max_count} as default")

    LOGGER.info(f"result resource count: {result_resource_count}")
    compliance_value = evaluate_compliance(max_count, result_resource_count)
    evaluations.append(build_evaluation(event["accountId"], compliance_value, event, resource_type=DEFAULT_RESOURCE_TYPE))
    response = AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
