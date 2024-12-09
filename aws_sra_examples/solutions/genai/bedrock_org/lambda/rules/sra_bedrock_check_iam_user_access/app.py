from typing import Any
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

# Define the AWS Config rule parameters
RULE_NAME = "sra-bedrock-check-iam-user-access"
SERVICE_NAME = "bedrock.amazonaws.com"

# Create a session and IAM client
session = boto3.Session()
iam_client = session.client("iam")


def evaluate_compliance(event: dict, context: Any) -> dict:
    """
    Evaluates compliance for the given AWS Config event.
    """
    LOGGER.info(f"eval compliance event: {event}")
    # Fetch IAM users
    iam_users = iam_client.list_users()["Users"]

    # Iterate over each IAM user
    non_compliant_users = []
    for user in iam_users:
        user_name = user["UserName"]
        LOGGER.info(f"user: {user_name}")
        user_policies = iam_client.list_user_policies(UserName=user_name)["PolicyNames"]
        user_groups = iam_client.list_groups_for_user(UserName=user_name)["Groups"]
        managed_policies = iam_client.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]

        # Check if the user has access to the Bedrock service
        has_access = False
        for policy in user_policies:
            LOGGER.info(f"policy: {policy}")
            policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy)["PolicyDocument"]
            if check_policy_document(policy_document): # type: ignore
                LOGGER.info("User policy has access")
                has_access = True
                break

        for group in user_groups:
            group_policies = iam_client.list_group_policies(GroupName=group["GroupName"])["PolicyNames"]
            for policy in group_policies:
                policy_document = iam_client.get_group_policy(GroupName=group["GroupName"], PolicyName=policy)["PolicyDocument"]
                if check_policy_document(policy_document): # type: ignore
                    LOGGER.info("Group policy has access")
                    has_access = True
                    break

        for managed_policy in managed_policies:
            LOGGER.info(f"managed policy: {managed_policy}")
            managed_policy_version = iam_client.get_policy(PolicyArn=managed_policy["PolicyArn"])["Policy"]["DefaultVersionId"]
            managed_policy_document = iam_client.get_policy_version(PolicyArn=managed_policy["PolicyArn"], VersionId=managed_policy_version)["PolicyVersion"]["Document"]
            if check_policy_document(managed_policy_document): # type: ignore
                LOGGER.info("Managed policy has access")
                has_access = True
                break

        if has_access:
            non_compliant_users.append(user_name)

    # Prepare the evaluation result
    if non_compliant_users:
        compliance_type = "NON_COMPLIANT"
        annotation = "The following IAM users have access to the Amazon Bedrock service: " + ", ".join(non_compliant_users)
    else:
        compliance_type = "COMPLIANT"
        annotation = "No IAM users have access to the Amazon Bedrock service."

    LOGGER.info(f"account id: {event['awsAccountId']}")
    evaluation_result = {
        "ComplianceType": compliance_type,
        "Annotation": annotation,
        "EvaluationResultIdentifier": {"EvaluationResultQualifier": {"ResourceId": event["awsAccountId"]}},
    }

    return evaluation_result


def check_policy_document(policy_document: dict) -> bool:
    """
    Checks if the given policy document allows access to the Bedrock service.
    """
    statements = policy_document["Statement"]
    for statement in statements:
        LOGGER.info(f"policy statement: {statement}")
        if statement["Effect"] == "Allow":
            resources = statement.get("Resource", [])
            LOGGER.info(f"resources: {resources}")
            actions = statement.get("Action", [])
            LOGGER.info(f"actions: {actions}")
            if any(action.startswith("bedrock:") for action in actions):
                return True

    return False


def lambda_handler(event: dict, context: Any) -> dict:
    """
    AWS Lambda function entry point.
    """
    LOGGER.info(f"Event: {event}")
    # Parse the event
    invoking_event = json.loads(event["invokingEvent"])
    result_token = event.get("resultToken")

    # Evaluate compliance
    evaluation_result = evaluate_compliance(invoking_event, context)

    # Send the evaluation result to AWS Config
    config_client = boto3.client("config")
    config_client.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": DEFAULT_RESOURCE_TYPE,
                "ComplianceResourceId": invoking_event["awsAccountId"],
                "ComplianceType": evaluation_result["ComplianceType"],
                "Annotation": evaluation_result["Annotation"],
                "OrderingTimestamp": invoking_event["notificationCreationTime"],
            }
        ],
        ResultToken=result_token,
    )

    # Return the evaluation result
    return evaluation_result
