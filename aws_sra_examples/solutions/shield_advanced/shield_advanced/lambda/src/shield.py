"""This script performs operations to enable, configure, and disable shield.

Version: 1.0
'shield_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep
from typing import TYPE_CHECKING, Any, Literal, Sequence

import boto3
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_route53 import Route53Client
    from mypy_boto3_route53.type_defs import ListHostedZonesResponseTypeDef
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_shield import ShieldClient
    from mypy_boto3_shield.type_defs import (
        CreateProtectionResponseTypeDef,
        DescribeEmergencyContactSettingsResponseTypeDef,
        DescribeProtectionResponseTypeDef,
        DescribeSubscriptionResponseTypeDef,
        EmergencyContactTypeDef,
        ProtectionTypeDef,
    )


LOGGER = logging.getLogger("sra")

log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)


UNEXPECTED = "Unexpected!"
RESOURCES_BY_ACCOUNT: dict = {}
SHIELD_DRT_POLICY = "arn:aws:iam::aws:policy/service-role/AWSShieldDRTAccessPolicy"

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def get_friendly_name(arn: str) -> str:
    """Parse friendly name from ARN.

    Args:
        arn: AWS ARN

    Returns:
        friendly name from arn
    """
    last_colon_index = arn.rfind(":")

    return arn[last_colon_index + 1 :].strip().replace("/", "").replace("-", "")  # noqa ECE001


def build_resources_by_account(account_session: boto3.Session, params: dict, account_id: str) -> None:
    """Build object to map resources to accounts.

    Args:
        account_session: the session for the account
        params: environment variables
        account_id: AWS Account Id to map the resources
    """
    buckets: list = get_buckets_to_protect(account_session, params["SHIELD_DRT_LOG_BUCKETS"].split(","))
    check_if_key_in_object("buckets", RESOURCES_BY_ACCOUNT[account_id], "list")
    RESOURCES_BY_ACCOUNT[account_id]["buckets"] = buckets
    check_if_key_in_object("resources_to_protect", RESOURCES_BY_ACCOUNT[account_id], "list")
    hosted_zones: list = get_route_53_hosted_zones(account_session)
    RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"] = hosted_zones
    resources_to_protect: list = get_resources_to_protect_in_account(account_id, params["RESOURCES_TO_PROTECT"].split(","))
    RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"].extend(resources_to_protect)


def get_resources_to_protect_in_account(account: str, resource_arns: list) -> list:
    """Get resources in account.

    Args:
        account: AWS Account id
        resource_arns: resource arns

    Returns:
        list of resources arns
    """
    resources_in_account: list = []
    for resource in resource_arns:
        if check_account_in_arn(account, resource):
            LOGGER.info(f"Resource {resource} is in account {account}")
            resources_in_account.append(resource)
    return resources_in_account


def get_route_53_hosted_zones(account_session: boto3.Session) -> list:
    """Get route53 hosted zones.

    Args:
        account_session: session for the AWS account

    Returns:
        a list of route53 hosted zones
    """
    route53_client: Route53Client = account_session.client("route53")
    hosted_zones: ListHostedZonesResponseTypeDef = route53_client.list_hosted_zones()
    LOGGER.info("[INFO] Listing hosted zones from the Route53")
    marker: bool = True
    hosted_zone_arns: list = []
    while marker:
        for hosted_zone in hosted_zones["HostedZones"]:
            hosted_zone_arn = f"arn:aws:route53:::{hosted_zone['Id']}"
            if hosted_zone_arn not in hosted_zone_arns:
                hosted_zone_arns.append(hosted_zone_arn)
            else:
                LOGGER.info(f"Hosted zone {hosted_zone_arn} already exists in object")
        if "Marker" in hosted_zones:
            hosted_zones = route53_client.list_hosted_zones(Marker=hosted_zones["Marker"])
        else:
            marker = False
    return hosted_zone_arns


def check_account_in_arn(account: str, arn: str) -> bool:
    """Check if account id in arn.

    Args:
        account: AWS account id
        arn: AWS arn

    Returns:
        True or False
    """
    return account in arn


def list_protections(shield_client: ShieldClient) -> list[ProtectionTypeDef]:
    """List of protections in an account.

    Args:
        shield_client: AWS Shield Client

    Returns:
        list of protections in an account
    """
    LOGGER.info("[INFO] Listing Shield Protections\n\n")
    marker: bool = True
    protected_resource_arns: list = []
    response = shield_client.list_protections()
    while marker:
        for resource in response["Protections"]:
            if resource["ResourceArn"] not in protected_resource_arns:
                protected_resource_arns.append(resource["ResourceArn"])
            else:
                LOGGER.info(f"{resource['ResourceArn']} already exists in object")
        if "NextToken" in response:
            response = shield_client.list_protections(NextToken=response["NextToken"])
        else:
            marker = False
    return protected_resource_arns


def build_emergency_contacts(params: dict) -> Sequence[EmergencyContactTypeDef]:
    """Build list of emergency contacts.

    Args:
        params: Parameters

    Returns:
        List of emergency contacts
    """
    emergency_contacts: Sequence[EmergencyContactTypeDef] = [
        {
            "EmailAddress": params["SHIELD_PROACTIVE_ENGAGEMENT_EMAIL"],
            "PhoneNumber": params["SHIELD_PROACTIVE_ENGAGEMENT_PHONE_NUMBER"],
            "ContactNotes": params["SHIELD_PROACTIVE_ENGAGEMENT_NOTES"],
        }
    ]
    return emergency_contacts


def update_emergency_contacts(shield_client: ShieldClient, params: dict, is_delete: bool = False) -> None:
    """Update emergency contacts in the shield client.

    Args:
        shield_client: Shield Client
        params: params
        is_delete: Flag for deletion. Defaults to False.
    """
    emergency_contacts: Sequence[EmergencyContactTypeDef] = []
    if not is_delete:
        emergency_contacts = build_emergency_contacts(params)
        LOGGER.info(f"Updating emergency contacts to {emergency_contacts}")
        shield_client.update_emergency_contact_settings(EmergencyContactList=emergency_contacts)
    else:
        LOGGER.info(f"Updating emergency contacts to {emergency_contacts}")
        shield_client.update_emergency_contact_settings(EmergencyContactList=emergency_contacts)


def check_if_key_in_object(key: str, obj: dict, var_type: str) -> None:
    """Check if key in  object.

    Args:
        key: key
        obj: object
        var_type: type

    Raises:
        ValueError: Non supported type
    """
    LOGGER.info(f"Adding key {key} of type {var_type} to object")
    if key not in obj:
        if var_type.lower() == "string":
            obj[key] = ""
            return
        if var_type.lower() == "list":
            obj[key] = []
            return
        if var_type.lower() == "dict":
            obj[key] = {}
        else:
            raise ValueError(f"Type {var_type} is not supported")
    else:
        LOGGER.info(f"Key {key} already exists in object")


def get_buckets_to_protect(account_session: boto3.Session, buckets_in_account: list) -> list[str]:
    """Get all buckets in the account.

    Args:
        account_session: account session
        buckets_in_account: list of buckets in account

    Returns:
        list of buckets

    """
    LOGGER.info("Getting all buckets")
    buckets: list = []
    try:
        s3_client: S3Client = account_session.client("s3")
        response: Any = s3_client.list_buckets()
        api_call_details = {"API_Call": "s3:ListBuckets", "API_Response": response}
        LOGGER.info(api_call_details)
        for bucket in response["Buckets"]:
            if bucket["Name"] in buckets_in_account:
                buckets.append(bucket["Name"])
        return buckets
    except s3_client.exceptions.ClientError as error:
        LOGGER.info(f"Failed to get all buckets: {error}")
        raise


def check_if_shield_enabled(shield_client: ShieldClient) -> bool:
    """Check if shield is enabled in the account.

    Args:
        shield_client: Shield client

    Returns:
        bool: True if shield is enabled, False otherwise
    """
    try:
        shield_client.describe_subscription()
        return True
    except shield_client.exceptions.ResourceNotFoundException:
        return False


def create_subscription(shield_client: ShieldClient) -> None:
    """Create Shield Subscription.

    Args:
        shield_client: shield client
    """
    subscription_enabled: bool = check_if_shield_enabled(shield_client)
    if subscription_enabled:
        LOGGER.info("Shield Advanced Subscription is already enabled")
    else:
        enable_shield_response = shield_client.create_subscription()
        api_call_details = {"API_Call": "shield:CreateSubscription", "API_Response": enable_shield_response}
        LOGGER.info(api_call_details)


def detach_drt_role_policy(account_session: boto3.Session, role_name: str) -> None:
    """Detach DRT role policy.

    Args:
        account_session: Boto3 session
        role_name: DRT role name
    """
    try:
        LOGGER.info("detaching DRT role policy")
        iam_client: IAMClient = account_session.client("iam")
        detach_policy_response = iam_client.detach_role_policy(RoleName=role_name, PolicyArn=SHIELD_DRT_POLICY)
        api_call_details = {"API_Call": "iam:DetachRolePolicy", "API_Response": detach_policy_response}
        LOGGER.info(api_call_details)
    except iam_client.exceptions.NoSuchEntityException as nse:
        LOGGER.info(f"NoSuchEntityException {nse}")
        LOGGER.info("Continuing...")


def delete_drt_role(account_session: boto3.Session, role_name: str) -> None:
    """Delete the IAM role used by the DRT.

    Args:
        account_session: account session
        role_name: name of role
    """
    try:
        LOGGER.info("deleting DRT role")
        iam_client: IAMClient = account_session.client("iam")
        detach_drt_role_policy(account_session, role_name)
        delete_role_response = iam_client.delete_role(RoleName=role_name)
        api_call_details = {"API_Call": "iam:DeleteRole", "API_Response": delete_role_response}
        LOGGER.info(api_call_details)
    except iam_client.exceptions.NoSuchEntityException as nse:
        LOGGER.info(f"NoSuchEntityException {nse}")
        LOGGER.info("Continuing...")


def check_if_role_exists(iam_client: IAMClient, role_name: str) -> str:
    """Check if role exists.

    Args:
        iam_client: IAM client
        role_name: Role name

    Returns:
        role arn or empty string
    """
    try:
        response = iam_client.get_role(RoleName=role_name)
        return response["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        return ""


def create_drt_role(account: str, role_name: str, account_session: boto3.Session) -> str:
    """Create IAM role used by the DRT.

    Args:
        account: account id
        role_name: name of role
        account_session: account session

    Returns:
        str: role arn
    """
    LOGGER.info(f"creating DRT role for account {account}")
    create_role_response = None

    iam_client: IAMClient = account_session.client("iam")
    role_exists = check_if_role_exists(iam_client, role_name)
    role_arn: str = ""
    if role_exists == "":
        create_role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument="""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "drt.shield.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }""",
        )
        attach_policy_response = iam_client.attach_role_policy(PolicyArn=SHIELD_DRT_POLICY, RoleName=role_name)
        role_arn = create_role_response["Role"]["Arn"]
    else:
        role_arn = role_exists
        attach_policy_response = iam_client.attach_role_policy(PolicyArn=SHIELD_DRT_POLICY, RoleName=role_name)

    api_call_details = {"API_Call": "iam:AttachRolePolicy", "API_Response": attach_policy_response}
    LOGGER.info(api_call_details)

    LOGGER.info(f"finished creating DRT role for account {account}")
    return role_arn  # noqa R504


def associate_drt_role(shield_client: ShieldClient, role_arn: str) -> None:
    """Associates DRT role.

    Args:
        shield_client: shield client
        role_arn: arn of the role to allow the DRT
    """
    associate_drt_response = shield_client.associate_drt_role(RoleArn=role_arn)
    api_call_details = {"API_Call": "shield:AssociateDRTRole", "API_Response": associate_drt_response}
    LOGGER.info(api_call_details)


def get_protection_id(shield_client: ShieldClient, arn: str) -> str:
    """Get protection id.

    Args:
        shield_client: shield client
        arn: ARN of the resource

    Returns:
        the protection id of the resource
    """
    try:
        describe_protection_response: DescribeProtectionResponseTypeDef = shield_client.describe_protection(ResourceArn=arn)
        api_call_details = {"API_Call": "shield:DescribeProtection", "API_Response": describe_protection_response}
        LOGGER.info(api_call_details)
        return describe_protection_response["Protection"]["Id"]
    except shield_client.exceptions.ResourceNotFoundException:
        return ""


def delete_protection(shield_client: ShieldClient, resource_arn: str) -> None:
    """Delete a protection.

    Args:
        shield_client: Shield client
        resource_arn: resource arn
    """
    protection_id: str = get_protection_id(shield_client, resource_arn)
    if protection_id != "":
        LOGGER.info(f"Deleting protection for {resource_arn} and protectionId {protection_id}")
        delete_protection_response = shield_client.delete_protection(ProtectionId=protection_id)
        api_call_details = {"API_Call": "shield:DeleteProtection", "API_Response": delete_protection_response}
        LOGGER.info(api_call_details)
    else:
        LOGGER.info(f"Protection not found for {resource_arn}")
        LOGGER.info("Continuing...")


def associate_drt_log_bucket(shield_client: ShieldClient, log_bucket: str) -> None:
    """Allow bucket access for DRT.

    Args:
        shield_client: shield client
        log_bucket: bucket to grant access via bucket policy
    """
    associate_drt_log_response = shield_client.associate_drt_log_bucket(LogBucket=log_bucket)
    api_call_details = {"API_Call": "shield:AssociateDRTLogBucket", "API_Response": associate_drt_log_response}
    LOGGER.info(api_call_details)


def disassociate_drt_log_bucket(shield_client: ShieldClient, log_bucket: str) -> None:
    """Disassociate DRT access.

    Args:
        shield_client: shield client
        log_bucket: bucket to update the policy
    """
    disassociate_drt_log_response = shield_client.disassociate_drt_log_bucket(LogBucket=log_bucket)
    api_call_details = {"API_Call": "shield:DisassociateDRTLogBucket", "API_Response": disassociate_drt_log_response}
    LOGGER.info(api_call_details)


def create_protection(shield_client: ShieldClient, resource_arn: str) -> None:
    """Create a protection.

    Args:
        shield_client: shield client
        resource_arn: arn of the resource to protect
    """
    create_protection_response: CreateProtectionResponseTypeDef = shield_client.create_protection(
        Name=get_friendly_name(resource_arn), ResourceArn=resource_arn, Tags=[{"Key": "sra-shield-advanced", "Value": "protected"}]
    )
    api_call_details = {"API_Call": "shield:CreateProtection", "API_Response": create_protection_response}
    LOGGER.info(api_call_details)


def disassociate_drt_role(account_session: boto3.Session) -> None:
    """Disassociate DRT role.

    Args:
        account_session: boto3 seession for the account
    """
    shield_client: ShieldClient = account_session.client("shield")
    disassociate_drt_response = shield_client.disassociate_drt_role()
    api_call_details = {"API_Call": "shield:DisassociateDRTRole", "API_Response": disassociate_drt_response}
    LOGGER.info(api_call_details)


def check_proactive_engagement_enabled(shield_client: ShieldClient, params: dict, retry: int = 0) -> bool:  # noqa CFQ004
    """Check status of proacvtive engagement.

    Args:
        shield_client: shield client
        params: Lambda Environment Variables
        retry: Retry counter, defaults to 0.

    Returns:
        bool
    """
    if retry < 4:
        describe_subscription_response: DescribeSubscriptionResponseTypeDef = shield_client.describe_subscription()
        if "ProactiveEngagementStatus" not in describe_subscription_response["Subscription"]:
            return False
        proactive_engagement_status: str = describe_subscription_response["Subscription"]["ProactiveEngagementStatus"]
        if proactive_engagement_status == "ENABLED":  # noqa R505
            return True
        elif proactive_engagement_status == "DISABLED":
            return True
        elif proactive_engagement_status == "PENDING":
            sleep(5)
            check_proactive_engagement_enabled(shield_client, params, retry + 1)
        return False
    else:
        return False
    return False


def check_if_protection_group_exists(shield_client: ShieldClient, protection_group_id: str) -> bool:
    """Check if a protection group exist.

    Args:
        shield_client: shield client
        protection_group_id: protection group id

    Returns:
        bool
    """
    try:
        shield_client.describe_protection_group(ProtectionGroupId=protection_group_id)
        return True
    except Exception as e:
        LOGGER.error(f"Error describing protection group {protection_group_id}: {e}")
        return False


def delete_protection_group(shield_client: ShieldClient, params: dict, account_id: str) -> None:
    """Delete an existing protection group.

    Args:
        shield_client: shield client
        params: environment variables
        account_id: AWS account id
    """
    for i in range(0, 5):
        pg_id: str = params[f"PROTECTION_GROUP_{i}_ID"]
        if account_id == params[f"PROTECTION_GROUP_{i}_ACCOUNT_ID"]:
            if pg_id != "":
                delete_protection_group_response = shield_client.delete_protection_group(ProtectionGroupId=pg_id)
                api_call_details = {"API_Call": "shield:DeleteProtectionGroup", "API_Response": delete_protection_group_response}
                LOGGER.info(api_call_details)
            else:
                LOGGER.info(f"No protection group PROTECTION_GROUP_{i}_ID found for account {account_id}")


def update_protection_group(
    shield_client: ShieldClient,
    pg_id: str,
    pg_aggregation: Literal["SUM", "MEAN", "MAX"],
    pg_pattern: Literal["ALL", "ARBITRARY", "BY_RESOURCE_TYPE"],
    pg_resource_type: Literal[
        "CLOUDFRONT_DISTRIBUTION",
        "ROUTE_53_HOSTED_ZONE",
        "ELASTIC_IP_ALLOCATION",
        "CLASSIC_LOAD_BALANCER",
        "APPLICATION_LOAD_BALANCER",
        "GLOBAL_ACCELERATOR",
    ],
    pg_members: str,
) -> None:
    """Update an existing protection group.

    Args:
        shield_client: Shield client
        pg_id: protection group id
        pg_aggregation: protection group aggregation type
        pg_pattern: protection group pattern
        pg_resource_type: protection group resource type
        pg_members: protection group members
    """
    if pg_pattern == "BY_RESOURCE_TYPE":
        protection_group_response = shield_client.update_protection_group(
            ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern, ResourceType=pg_resource_type
        )
    elif pg_pattern == "ARBITRARY":
        protection_group_response = shield_client.update_protection_group(
            ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern, Members=pg_members.split(",")
        )
    else:
        protection_group_response = shield_client.update_protection_group(ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern)
    api_call_details = {"API_Call": "shield:UpdateProtectionGroup", "API_Response": protection_group_response}
    LOGGER.info(api_call_details)


def create_protection_group(shield_client: ShieldClient, params: dict, account_id: str) -> None:
    """Create a protection group.

    Args:
        shield_client: shield client
        params: environment variables
        account_id: AWS account id
    """
    for i in range(0, 5):
        pg_id: str = params[f"PROTECTION_GROUP_{i}_ID"]
        pg_account_id: str = params[f"PROTECTION_GROUP_{i}_ACCOUNT_ID"]
        pg_aggregation: Literal["SUM", "MEAN", "MAX"] = params[f"PROTECTION_GROUP_{i}_AGGREGATION"]
        pg_pattern: Literal["ALL", "ARBITRARY", "BY_RESOURCE_TYPE"] = params[f"PROTECTION_GROUP_{i}_PATTERN"]
        pg_resource_type: Literal[
            "CLOUDFRONT_DISTRIBUTION",
            "ROUTE_53_HOSTED_ZONE",
            "ELASTIC_IP_ALLOCATION",
            "CLASSIC_LOAD_BALANCER",
            "APPLICATION_LOAD_BALANCER",
            "GLOBAL_ACCELERATOR",
        ] = params[f"PROTECTION_GROUP_{i}_RESOURCE_TYPE"]
        pg_members: str = params[f"PROTECTION_GROUP_{i}_MEMBERS"]
        if pg_id != "" and pg_account_id == account_id:
            if check_if_protection_group_exists(shield_client, pg_id):
                LOGGER.info(f"Protection_Group_{i} already exists in {account_id}")
                update_protection_group(shield_client, pg_id, pg_aggregation, pg_pattern, pg_resource_type, pg_members)
                break
            LOGGER.info(f"Creating Protection_Group_{i} in {account_id}")
            if pg_pattern == "BY_RESOURCE_TYPE":
                protection_group_response = shield_client.create_protection_group(
                    ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern, ResourceType=pg_resource_type
                )
            elif pg_pattern == "ARBITRARY":
                protection_group_response = shield_client.create_protection_group(
                    ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern, Members=pg_members.split(",")
                )
            else:
                protection_group_response = shield_client.create_protection_group(
                    ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern
                )
            api_call_details = {"API_Call": "shield:CreateProtectionGroup", "API_Response": protection_group_response}
            LOGGER.info(api_call_details)
        else:
            LOGGER.info(f"PROTECTION_GROUP_{i} is empty")


def check_emergency_contacts(shield_client: ShieldClient) -> bool:
    """Check for emergency contacts.

    Args:
        shield_client: shield client

    Returns:
        bool
    """
    try:
        emergency_contacts_response: DescribeEmergencyContactSettingsResponseTypeDef = shield_client.describe_emergency_contact_settings()
        api_call_details = {"API_Call": "shield:DescribeEmergencyContactSettings", "API_Response": emergency_contacts_response}
        LOGGER.info(api_call_details)
        if "EmergencyContactList" in emergency_contacts_response and len(emergency_contacts_response["EmergencyContactList"]) > 0:
            return True

        return False
    except shield_client.exceptions.ResourceNotFoundException:
        return False


def enable_proactive_engagement(shield_client: ShieldClient, params: dict) -> None:
    """Enable the DRT team to reach out to the contact.

    Args:
        shield_client: shield client
        params: environment variables
    """
    if params["SHIELD_ENABLE_PROACTIVE_ENGAGEMENT"] == "true":
        if check_proactive_engagement_enabled(shield_client, params):
            update_emergency_contacts(shield_client, params)
            shield_client.enable_proactive_engagement()
        else:
            if check_emergency_contacts(shield_client):
                update_emergency_contacts(shield_client, params)
                shield_client.enable_proactive_engagement()
            else:
                associate_proactive_engagement_details(shield_client, params)

    else:
        LOGGER.info(f"SHIELD_ENABLE_PROACTIVE_ENGAGEMENT is set to {params['SHIELD_ENABLE_PROACTIVE_ENGAGEMENT']}")


def associate_proactive_engagement_details(shield_client: ShieldClient, params: dict) -> None:
    """Allow the DRT to use the contact information.

    Args:
        shield_client: shield client
        params: environment variables
    """
    associate_proactive_engagement_response = shield_client.associate_proactive_engagement_details(
        EmergencyContactList=[
            {
                "EmailAddress": params["SHIELD_PROACTIVE_ENGAGEMENT_EMAIL"],
                "PhoneNumber": params["SHIELD_PROACTIVE_ENGAGEMENT_PHONE_NUMBER"],
                "ContactNotes": params["SHIELD_PROACTIVE_ENGAGEMENT_NOTES"],
            },
        ]
    )
    api_call_details = {"API_Call": "shield:AssociateProactiveEngagementDetails", "API_Response": associate_proactive_engagement_response}
    LOGGER.info(api_call_details)


def disable_proactive_engagement(shield_client: ShieldClient) -> None:
    """Disable the DRT to use the contact details.

    Args:
        shield_client: Shield client

    Raises:
        e: Client Error
    """
    try:
        disable_proactive_engagement_response = shield_client.disable_proactive_engagement()
        api_call_details = {"API_Call": "shield:DisableProactiveEngagement", "API_Response": disable_proactive_engagement_response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidOperationException":
            LOGGER.exception(e)
        else:
            raise
