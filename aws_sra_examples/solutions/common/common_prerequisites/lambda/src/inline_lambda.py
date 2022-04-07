# type: ignore
"""Custom Resource to get AWS Organization ID.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging
import os

import boto3
import cfnresponse

LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)


def get_org_id():
    """Get AWS Organization ID.

    Returns:
        Response data for custom resource
    """
    management_account_session = boto3.Session()
    org_client = management_account_session.client("organizations")
    response = org_client.describe_organization()["Organization"]
    LOGGER.debug({"API_Call": "organizations:DescribeOrganization", "API_Response": response})
    return {"OrganizationId": response["Id"]}


def lambda_handler(event, context):
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information
    """
    try:
        data = get_org_id()
        cfnresponse.send(event, context, cfnresponse.SUCCESS, data, data["OrganizationId"])
    except Exception:
        LOGGER.exception("Unexpected!")
        reason = f"See the details in CloudWatch Log Stream: '{context.log_group_name}'"
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, data["OrganizationId"], reason=reason)
