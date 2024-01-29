"""This script performs operations to enable, configure, and disable shield.

Version: 1.0
'shield_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import time
from time import sleep
from typing import TYPE_CHECKING, Any, Literal, Sequence

import boto3
import common

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_iam.type_defs import (
        AttachRolePolicyResponseTypeDef,
        CreateRoleResponseTypeDef,
        DeleteRoleRequestRequestTypeDef,
        DetachRolePolicyRequestPolicyDetachRoleTypeDef,
    )
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_route53 import Route53Client
    from mypy_boto3_route53.type_defs import ListHostedZonesResponseTypeDef
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_shield import ShieldClient
    from mypy_boto3_shield.type_defs import (
        AssociateDRTLogBucketRequestRequestTypeDef,
        AssociateProactiveEngagementDetailsRequestRequestTypeDef,
        CreateProtectionGroupRequestRequestTypeDef,
        CreateProtectionGroupResponseTypeDef,
        CreateProtectionResponseTypeDef,
        CreateSubscriptionRequestRequestTypeDef,
        CreateSubscriptionResponseTypeDef,
        DeleteProtectionGroupRequestRequestTypeDef,
        DeleteProtectionGroupResponseTypeDef,
        DeleteProtectionRequestRequestTypeDef,
        DescribeEmergencyContactSettingsResponseTypeDef,
        DescribeProtectionResponseTypeDef,
        DescribeSubscriptionResponseTypeDef,
        DisableApplicationLayerAutomaticResponseRequestRequestTypeDef,
        DisassociateDRTLogBucketRequestRequestTypeDef,
        EmergencyContactTypeDef,
        ProtectionTypeDef,
        UpdateEmergencyContactSettingsRequestRequestTypeDef,
        UpdateEmergencyContactSettingsResponseTypeDef,
        UpdateProtectionGroupRequestRequestTypeDef,
    )


LOGGER = logging.getLogger("sra")

log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)


UNEXPECTED = "Unexpected!"
# shield_THROTTLE_PERIOD: float = 0.2
ENABLE_RETRY_ATTEMPTS: int = 10
ENABLE_RETRY_SLEEP_INTERVAL: int = 10
RESOURCES_BY_ACCOUNT: dict = {}

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def get_friendly_name(arn: str) -> str:
    """takes an arn and returns the friendly name of the resource

    Args:
        arn: AWS ARN

    Returns:
        friendly name from arn
    """
    last_colon_index = arn.rfind(":")
    name = arn[last_colon_index + 1 :].strip()
    name = name.replace("/", "")
    name = name.replace("-", "")
    return name


def build_resources_by_account(account_session: boto3.Session, params: dict, account_id: str) -> None:
    """Builds an object that maps resources to accounts

    Args:
        account_session: the session for the account
        params: environment variables
        account_id: AWS Account Id to map the resources
    """
    buckets: list = get_buckets_to_protect(account_session, params["SHIELD_DRT_LOG_BUCKETS"].split(","))
    check_if_key_in_object("buckets", RESOURCES_BY_ACCOUNT[account_id], "list")
    RESOURCES_BY_ACCOUNT[account_id]["buckets"]: list = buckets
    check_if_key_in_object("resources_to_protect", RESOURCES_BY_ACCOUNT[account_id], "list")
    hosted_zones: list = get_route_53_hosted_zones(account_session)
    RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"]: list = hosted_zones
    resources_to_protect: list = get_resources_to_protect_in_account(account_id, params["RESOURCES_TO_PROTECT"].split(","))
    RESOURCES_BY_ACCOUNT[account_id]["resources_to_protect"].extend(resources_to_protect)


def get_resources_to_protect_in_account(account: str, resource_arns: list) -> list:
    """
    gets a list of resources that are in the AWS Account passed in
    Args:
        account: AWS account number
        resource_arns: a list of resource arns

    Returns:
        a list of resources that are in the account passed in
    """
    resources_in_account: list = []
    for resource in resource_arns:
        if check_account_in_arn(account, resource):
            LOGGER.info(f"Resource {resource} is in account {account}")
            resources_in_account.append(resource)
    return resources_in_account


def get_route_53_hosted_zones(account_session: boto3.Session) -> list:
    """gets all the route53 hosted zones

    Args:
        account_session: session for the AWS account

    Returns:
        a list of route53 hosted zones
    """
    route53_client: Route53Client = account_session.client("route53")
    hosted_zones: ListHostedZonesResponseTypeDef = route53_client.list_hosted_zones()
    LOGGER.info("[INFO] Listing hosted zones from the Route53\n\n")
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
    """
    @account account id
    @arn arn of the resource

    Returns True if the account id is in the arn, False otherwise
    """
    return account in arn


def list_protections(shield_client: ShieldClient) -> list[ProtectionTypeDef]:
    """Gets a list of protections in an account

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
        shield_client: Shield client
        emergency_contacts: List of emergency contacts
    """
    emergency_contacts: Sequence[EmergencyContactTypeDef] = []
    if not is_delete:
        emergency_contacts: Sequence[EmergencyContactTypeDef] = build_emergency_contacts(params)
        LOGGER.info(f"Updating emergency contacts to {emergency_contacts}")
        shield_client.update_emergency_contact_settings(EmergencyContactList=emergency_contacts)
    else:
        LOGGER.info(f"Updating emergency contacts to {emergency_contacts}")
        shield_client.update_emergency_contact_settings(EmergencyContactList=emergency_contacts)


def check_if_key_in_object(key: str, obj: dict, t: str) -> None:
    """Check if key in object and add the key if not.

    Args:
        obj: Object
        key: Key
    """
    LOGGER.info(f"Adding key {key} of type {t} to object")
    if key not in obj:
        if t.lower() == "string":
            obj[key] = ""
            return
        if t.lower() == "list":
            obj[key] = []
            return
        if t.lower() == "dict":
            obj[key] = {}
            return
        else:
            raise ValueError(f"Type {t} is not supported")
    else:
        LOGGER.info(f"Key {key} already exists in object")


def get_buckets_to_protect(account_session: boto3.Session, buckets_in_account: list) -> list[str]:
    """Get all buckets in the account.

    Args:
        s3_client: S3 client

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
        raise error


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
    """Enable shield in the given account in the given region.

    Args:
        shield_client: shield client
        account_id: Account ID
        region: Region
        scan_components: list of scan components
    """
    subscription_enabled: bool = check_if_shield_enabled(shield_client)
    if subscription_enabled:
        LOGGER.info("Shield Advanced Subscription is already enabled")
    else:
        enable_shield_response: CreateSubscriptionResponseTypeDef = shield_client.create_subscription()
        api_call_details = {"API_Call": "shield:CreateSubscription", "API_Response": enable_shield_response}
        LOGGER.info(api_call_details)


def disable_shield_region(account_session: boto3.Session, region: str) -> None:
    """Disable shield for the given account.

    Args:
        regions: list of regions

    Returns:
        DisableResponseTypeDef: shield client api response
    """
    shield_client: ShieldClient = account_session.client("shield", region)
    disable_shield_response = shield_client.delete_subscription()
    api_call_details = {"API_Call": "shield:DeleteSubscription", "API_Response": disable_shield_response}
    LOGGER.info(api_call_details)
    LOGGER.info("Disabled shield")


def detach_drt_role_policy(account_session: boto3.Session, role_name: str) -> None:
    """Detach DRT role policy.

    Args:
        account_session: Boto3 session
        role_name: DRT role name
    """
    try:
        LOGGER.info("detaching DRT role policy")
        iam_client: IAMClient = account_session.client("iam")
        detach_policy_response: DetachRolePolicyRequestPolicyDetachRoleTypeDef = iam_client.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSShieldDRTAccessPolicy"
        )
        api_call_details = {"API_Call": "iam:DetachRolePolicy", "API_Response": detach_policy_response}
        LOGGER.info(api_call_details)
    except iam_client.exceptions.NoSuchEntityException as nse:
        LOGGER.info(f"NoSuchEntityException {nse}")
        LOGGER.info(f"Continuing...")


def delete_drt_role(account_session: boto3.Session, role_name: str) -> None:
    """Deletes the IAM role used by the DRT

    Args:
        account_session: _description_
        role_name: _description_
    """
    try:
        LOGGER.info("deleting DRT role")
        iam_client: IAMClient = account_session.client("iam")
        detach_drt_role_policy(account_session, role_name)
        delete_role_response: DeleteRoleRequestRequestTypeDef = iam_client.delete_role(RoleName=role_name)
        api_call_details = {"API_Call": "iam:DeleteRole", "API_Response": delete_role_response}
        LOGGER.info(api_call_details)
    except iam_client.exceptions.NoSuchEntityException as nse:
        LOGGER.info(f"NoSuchEntityException {nse}")
        LOGGER.info(f"Continuing...")


def check_if_role_exists(iam_client: IAMClient, role_name: str) -> str:
    """Check if role exists.

    Args:
        iam_client: IAM client
        role_name: Role name

    Returns:
        bool: True if role exists, False otherwise
    """
    try:
        response = iam_client.get_role(RoleName=role_name)
        return response["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        return ""


def create_drt_role(account: str, role_name: str, account_session: boto3.Session) -> str:
    """Create DRT role in the given account.

    Args:
        account (str): Account ID
        role_name (str): IAM role name
    """
    LOGGER.info(f"creating DRT role for account {account}")
    create_role_response = None

    iam_client: IAMClient = account_session.client("iam")
    role_exists = check_if_role_exists(iam_client, role_name)
    role_arn = ""
    if role_exists == "":
        create_role_response: CreateRoleResponseTypeDef = iam_client.create_role(
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
        attach_policy_response: AttachRolePolicyResponseTypeDef = iam_client.attach_role_policy(
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSShieldDRTAccessPolicy", RoleName=role_name
        )
        role_arn: str = create_role_response["Role"]["Arn"]
    else:
        role_arn = role_exists
        attach_policy_response: AttachRolePolicyResponseTypeDef = iam_client.attach_role_policy(
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSShieldDRTAccessPolicy", RoleName=role_name
        )

    api_call_details = {"API_Call": "iam:AttachRolePolicy", "API_Response": attach_policy_response}
    LOGGER.info(api_call_details)

    LOGGER.info(f"finished creating DRT role for account {account}")
    return role_arn


def associate_drt_role(shield_client: ShieldClient, role_arn: str) -> None:
    """Creates a trust policy that allows DRT to assume the role

    Args:
        shield_client: shield client
        role_arn: arn of the role to allow the DRT
    """
    associate_drt_response = shield_client.associate_drt_role(RoleArn=role_arn)
    api_call_details = {"API_Call": "shield:AssociateDRTRole", "API_Response": associate_drt_response}
    LOGGER.info(api_call_details)


def get_protection_id(shield_client: ShieldClient, arn: str) -> str:
    """Gets the protection id for a given resource

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
    """Deletes the protection for the given resource.
    Args:
        shield_client: shield client
        resource_arn: arn of the resource to delete the protection
    """
    protection_id: str = get_protection_id(shield_client, resource_arn)
    if protection_id != "":
        LOGGER.info(f"Deleting protection for {resource_arn} and protectionId {protection_id}")
        delete_protection_response: DeleteProtectionRequestRequestTypeDef = shield_client.delete_protection(ProtectionId=protection_id)
        api_call_details = {"API_Call": "shield:DeleteProtection", "API_Response": delete_protection_response}
        LOGGER.info(api_call_details)
    else:
        LOGGER.info(f"Protection not found for {resource_arn}")
        LOGGER.info("Continuing...")


def associate_drt_log_bucket(shield_client: ShieldClient, log_bucket: str) -> None:
    """Allowsbucket access for DRT

    Args:
        shield_client: shield client
        log_bucket: bucket to grant access via bucket policy
    """
    associate_drt_log_response: AssociateDRTLogBucketRequestRequestTypeDef = shield_client.associate_drt_log_bucket(LogBucket=log_bucket)
    api_call_details = {"API_Call": "shield:AssociateDRTLogBucket", "API_Response": associate_drt_log_response}
    LOGGER.info(api_call_details)


def disassociate_drt_log_bucket(shield_client: ShieldClient, log_bucket: str) -> None:
    """Removes the bucket policy allowing DRT access

    Args:
        shield_client: shield client
        log_bucket: bucket to update the policy
    """
    disassociate_drt_log_response: DisassociateDRTLogBucketRequestRequestTypeDef = shield_client.disassociate_drt_log_bucket(LogBucket=log_bucket)
    api_call_details = {"API_Call": "shield:DisassociateDRTLogBucket", "API_Response": disassociate_drt_log_response}
    LOGGER.info(api_call_details)


def create_protection(shield_client: ShieldClient, resource_arn: str) -> None:
    """Creates a protection for the given resource. The resource can be an Amazon S3 bucket, an AWS resource, or an Amazon CloudFront distribution.""

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
    """Removes access for the DRT to assume the role

    Args:
        account_session: boto3 seession for the account
    """
    shield_client: ShieldClient = account_session.client("shield")
    disassociate_drt_response = shield_client.disassociate_drt_role()
    api_call_details = {"API_Call": "shield:DisassociateDRTRole", "API_Response": disassociate_drt_response}
    LOGGER.info(api_call_details)


def check_proactive_engagement_enabled(shield_client: ShieldClient, params: dict, retry: int = 0) -> bool:
    """Checks the status of proacvtive engagement

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
        if proactive_engagement_status == "ENABLED":
            return True
        elif proactive_engagement_status == "DISABLED":
            return False
        elif proactive_engagement_status == "PENDING":
            time.sleep(5)
            check_proactive_engagement_enabled(shield_client, params, retry + 1)
    else:
        # TODO take a look at this and see if I should raise an error instead
        return True


def check_if_protection_group_exists(shield_client: ShieldClient, protection_group_id: str) -> bool:
    """Checks if a protection group exists. If it does, returns True. If it does not, returns False.
    If an exception is raised, returns False.
    Args:
        shield_client: shield client
        protection_group_id: protection group id

    Returns:
        bool, True if the protection group exist, False if it doesn't
    """
    try:
        shield_client.describe_protection_group(ProtectionGroupId=protection_group_id)
        return True
    except shield_client.exceptions.InvalidParameterException:
        return False
    except shield_client.exceptions.InternalErrorException:
        return False
    except shield_client.exceptions.OptimisticLockException:
        return False
    except shield_client.exceptions.AccessDeniedException:
        return False
    except shield_client.exceptions.ResourceNotFoundException:
        return False
    except shield_client.exceptions.InvalidOperationException:
        return False
    except shield_client.exceptions.ResourceAlreadyExistsException:
        return False
    except shield_client.exceptions.InvalidPaginationTokenException:
        return False


def delete_protection_group(shield_client: ShieldClient, params: dict, account_id: str) -> None:
    """Deletes an existing protection group

    Args:
        shield_client: shield client
        params: environment variables
        account_id: AWS account id
    """
    for i in range(0, 5):
        pg_id: str = params[f"PROTECTION_GROUP_{i}_ID"]
        if account_id == params[f"PROTECTION_GROUP_{i}_ACCOUNT_ID"]:
            if pg_id != "":
                delete_protection_group_response: DeleteProtectionGroupResponseTypeDef = shield_client.delete_protection_group(
                    ProtectionGroupId=pg_id
                )
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
    pg_members: list,
) -> None:
    """Updates an existing protection group

    Args:
        shield_client: shield client
        pg_id: protection group id
        pg_aggregation: protection group aggregation pattern
        pg_pattern: protection group pattern
        pg_resource_type: protection group resource type
        pg_members: protection group members
    """
    if pg_pattern == "BY_RESOURCE_TYPE":
        protection_group_response: UpdateProtectionGroupRequestRequestTypeDef = shield_client.update_protection_group(
            ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern, ResourceType=pg_resource_type
        )
    elif pg_pattern == "ARBITRARY":
        protection_group_response: UpdateProtectionGroupRequestRequestTypeDef = shield_client.update_protection_group(
            ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern, Members=pg_members.split(",")
        )
    else:
        protection_group_response: UpdateProtectionGroupRequestRequestTypeDef = shield_client.update_protection_group(
            ProtectionGroupId=pg_id, Aggregation=pg_aggregation, Pattern=pg_pattern
        )
    api_call_details = {"API_Call": "shield:UpdateProtectionGroup", "API_Response": protection_group_response}
    LOGGER.info(api_call_details)


def create_protection_group(shield_client: ShieldClient, params: dict, account_id: str) -> None:
    """Creates a protection group

    Args:
        shield_client: shield client
        params: environment variablrd
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

        pg_members: list = params[f"PROTECTION_GROUP_{i}_MEMBERS"]
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
    """Checks if there are emergency contacts

    Args:
        shield_client: shield client
    """
    try:
        emergency_contacts_response: DescribeEmergencyContactSettingsResponseTypeDef = shield_client.describe_emergency_contact_settings()
        api_call_details = {"API_Call": "shield:DescribeEmergencyContactSettings", "API_Response": emergency_contacts_response}
        LOGGER.info(api_call_details)
        return True
    except shield_client.exceptions.ResourceNotFoundException:
        return False


def enable_proactive_engagement(shield_client: ShieldClient, params: dict) -> None:
    """Enables the DRT team to reach out to the contacts

    Args:
        shield_client: shield client
        params: environment variables
    """
    if params["SHIELD_ENABLE_PROACTIVE_ENGAGEMENT"] == "true":
        if check_proactive_engagement_enabled(shield_client, params):
            update_emergency_contacts(shield_client, params)
        else:
            if check_emergency_contacts(shield_client):
                update_emergency_contacts(shield_client, params)
                shield_client.enable_proactive_engagement()
            else:
                associate_proactive_engagement_details(shield_client, params)

    else:
        LOGGER.info(f"SHIELD_ENABLE_PROACTIVE_ENGAGEMENT is set to {params['SHIELD_ENABLE_PROACTIVE_ENGAGEMENT']}")


def associate_proactive_engagement_details(shield_client: ShieldClient, params: dict):
    """Allow the DRT to use the contact information to reach out to the contacts

    Args:
        shield_client: shield client
        params: environment variables
    """
    associate_proactive_engagement_response: AssociateProactiveEngagementDetailsRequestRequestTypeDef = (
        shield_client.associate_proactive_engagement_details(
            EmergencyContactList=[
                {
                    "EmailAddress": params["SHIELD_PROACTIVE_ENGAGEMENT_EMAIL"],
                    "PhoneNumber": params["SHIELD_PROACTIVE_ENGAGEMENT_PHONE_NUMBER"],
                    "ContactNotes": params["SHIELD_PROACTIVE_ENGAGEMENT_NOTES"],
                },
            ]
        )
    )
    api_call_details = {"API_Call": "shield:AssociateProactiveEngagementDetails", "API_Response": associate_proactive_engagement_response}
    LOGGER.info(api_call_details)


def disable_proactive_engagement(shield_client: ShieldClient) -> None:
    """disallow the DRT to use the contact details

    Args:
        shield_client: shield client
    """
    disable_proactive_engagement_response: DisableApplicationLayerAutomaticResponseRequestRequestTypeDef = (
        shield_client.disable_proactive_engagement()
    )
    api_call_details = {"API_Call": "shield:DisableProactiveEngagement", "API_Response": disable_proactive_engagement_response}
    LOGGER.info(api_call_details)
