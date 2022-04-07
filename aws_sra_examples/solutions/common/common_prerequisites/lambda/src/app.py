"""Custom Resource to gather data and create SSM paramters in the Control Tower management account.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Literal, Sequence, Union

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from crhelper import CfnResource

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_ssm.type_defs import TagTypeDef

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.ERROR)
LOGGER.setLevel(log_level)

# Global Variables
CLOUDFORMATION_THROTTLE_PERIOD = 0.2
CLOUDFORMATION_PAGE_SIZE = 100
SSM_DELETE_PARAMETERS_MAX = 10
SRA_CONTROL_TOWER_SSM_PATH = "/sra/control-tower"
SRA_REGIONS_SSM_PATH = "/sra/regions"
SRA_SSM_PARAMETERS = [
    "/sra/control-tower/root-organizational-unit-id",
    "/sra/control-tower/organization-id",
    "/sra/control-tower/management-account-id",
    "/sra/control-tower/home-region",
    "/sra/control-tower/audit-account-id",
    "/sra/control-tower/log-archive-account-id",
    "/sra/regions/enabled-regions",
    "/sra/regions/enabled-regions-without-home-region",
    "/sra/regions/customer-control-tower-regions",
    "/sra/regions/customer-control-tower-regions-without-home-region",
]
UNEXPECTED = "Unexpected!"
EMPTY_VALUE = "NONE"

# Initialize the helper
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    CFN_CLIENT: CloudFormationClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


def add_tags_to_ssm_parameter(ssm_client: SSMClient, resource_id: str, tags: Sequence[TagTypeDef]) -> None:
    """Add tags to SSM parameter.

    Args:
        ssm_client: Boto3 SSM client
        resource_id: SSM parameter name
        tags: Tags to apply to SSM parameter
    """
    response = ssm_client.add_tags_to_resource(ResourceType="Parameter", ResourceId=resource_id, Tags=tags)
    LOGGER.debug({"API_Call": "ssm:AddTagsToResource", "API_Response": response})


def create_ssm_parameter(ssm_client: SSMClient, name: str, value: str, parameter_type: Union[Literal["String"], Literal["StringList"]]) -> None:
    """Create SSM parameter.

    Args:
        ssm_client: Boto3 SSM client
        name: SSM parameter name
        value: SSM parameter value
        parameter_type: SSM parameter type
    """
    if not value:
        value = EMPTY_VALUE
    response = ssm_client.put_parameter(Name=name, Value=value, Type=parameter_type, Overwrite=True)
    LOGGER.debug({"API_Call": "ssm:PutParameter", "API_Response": response})


def delete_ssm_parameters(ssm_client: SSMClient, names: list) -> None:
    """Delete SSM parameters.

    Args:
        ssm_client: Boto3 SSM client
        names: SSM parameter names
    """
    response = ssm_client.delete_parameters(Names=names)
    LOGGER.debug({"API_Call": "ssm:DeleteParameters", "API_Response": response})


def get_customer_control_tower_regions() -> list:  # noqa: CCR001
    """Query 'AWSControlTowerBP-BASELINE-CLOUDWATCH' CloudFormation stack to identify customer regions.

    Returns:
        Customer regions chosen in Control Tower
    """
    paginator = CFN_CLIENT.get_paginator("list_stack_instances")
    customer_regions = []
    aws_account = ""
    all_regions_identified = False
    for page in paginator.paginate(StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH", PaginationConfig={"PageSize": CLOUDFORMATION_PAGE_SIZE}):
        for instance in page["Summaries"]:
            if not aws_account:
                aws_account = instance["Account"]
                customer_regions.append(instance["Region"])
                continue
            if aws_account == instance["Account"]:
                customer_regions.append(instance["Region"])
                continue
            all_regions_identified = True
            break
        if all_regions_identified:
            break
        sleep(CLOUDFORMATION_THROTTLE_PERIOD)

    return customer_regions


def get_enabled_regions() -> list:  # noqa: CCR001
    """Query STS to identify enabled regions.

    Raises:
        EndpointConnectionError: region is not valid.

    Returns:
        Enabled regions
    """
    # available_regions = management_account_session.get_available_regions("sts") # noqa: E800
    default_available_regions = [
        "eu-central-1",
        "ap-northeast-1",
        "sa-east-1",
        "ap-southeast-1",
        "us-east-1",
        "us-east-2",
        "ca-central-1",
        "us-west-2",
        "us-west-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "ap-south-1",
        "eu-west-2",
        "eu-north-1",
        "eu-west-1",
        "ap-southeast-2",
        "eu-west-3",
    ]
    LOGGER.info({"Default_Available_Regions": default_available_regions})

    enabled_regions = []
    disabled_regions = []
    region_session = boto3.Session()
    for region in default_available_regions:
        try:
            sts_client = region_session.client("sts", endpoint_url=f"https://sts.{region}.amazonaws.com", region_name=region)
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except EndpointConnectionError:
            LOGGER.error(f"Region: '{region}' is not valid.")
            raise
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidClientTokenId":
                disabled_regions.append(region)
                continue
            raise

    LOGGER.info({"Disabled_Regions": disabled_regions})
    return enabled_regions


def get_org_ssm_parameter_info(path: str) -> dict:
    """Query AWS Organizations, and get info needed to create the SSM parameters.

    Args:
        path: SSM parameter hierarchy path

    Returns:
        Info needed to create SSM parameters and helper data for custom resource
    """
    ssm_data: dict = {"info": []}
    org = ORG_CLIENT.describe_organization()["Organization"]
    root_id = ORG_CLIENT.list_roots()["Roots"][0]["Id"]

    ssm_data["info"].append({"name": f"{path}/root-organizational-unit-id", "value": root_id, "parameter_type": "String"})
    ssm_data["info"].append({"name": f"{path}/organization-id", "value": org["Id"], "parameter_type": "String"})
    ssm_data["info"].append({"name": f"{path}/management-account-id", "value": org["MasterAccountId"], "parameter_type": "String"})
    ssm_data["helper"] = {"ManagementAccountId": org["MasterAccountId"], "OrganizationId": org["Id"], "RootOrganizationalUnitId": root_id}
    LOGGER.info(ssm_data["helper"])
    return ssm_data


def get_cloudformation_ssm_parameter_info(path: str) -> dict:  # noqa: CCR001
    """Query AWS CloudFormation stacksets, and get info needed to create the SSM parameters.

    Args:
        path: SSM parameter hierarchy path

    Returns:
        Info needed to create SSM parameters and helper data for custom resource
    """
    ssm_data: dict = {"info": [], "helper": {}}
    response = CFN_CLIENT.describe_stack_set(StackSetName="AWSControlTowerBP-BASELINE-CONFIG")
    for parameter in response["StackSet"]["Parameters"]:
        if parameter["ParameterKey"] == "HomeRegionName":
            ssm_data["info"].append({"name": f"{path}/home-region", "value": parameter["ParameterValue"], "parameter_type": "String"})
            ssm_data["helper"]["HomeRegion"] = parameter["ParameterValue"]
        if parameter["ParameterKey"] == "SecurityAccountId":
            ssm_data["info"].append({"name": f"{path}/audit-account-id", "value": parameter["ParameterValue"], "parameter_type": "String"})
            ssm_data["helper"]["AuditAccountId"] = parameter["ParameterValue"]

    paginator = CFN_CLIENT.get_paginator("list_stack_instances")
    for page in paginator.paginate(StackSetName="AWSControlTowerLoggingResources", PaginationConfig={"PageSize": CLOUDFORMATION_PAGE_SIZE}):
        for instance in page["Summaries"]:
            ssm_data["info"].append({"name": f"{path}/log-archive-account-id", "value": instance["Account"], "parameter_type": "String"})
            ssm_data["helper"]["LogArchiveAccountId"] = instance["Account"]
        sleep(CLOUDFORMATION_THROTTLE_PERIOD)

    LOGGER.info(ssm_data["helper"])
    return ssm_data


def get_enabled_regions_ssm_parameter_info(home_region: str, path: str) -> dict:  # noqa: CCR001
    """Query STS for enabled regions, and get info needed to create the SSM parameters.

    Args:
        home_region: Control Tower home region
        path: SSM parameter hierarchy path

    Returns:
        Info needed to create SSM parameters and helper data for custom resource
    """
    ssm_data: dict = {"info": []}
    enabled_regions = get_enabled_regions()
    enabled_regions_without_home_region = enabled_regions.copy()
    enabled_regions_without_home_region.remove(home_region)

    ssm_data["info"].append({"name": f"{path}/enabled-regions", "value": ",".join(enabled_regions), "parameter_type": "StringList"})
    ssm_data["info"].append(
        {
            "name": f"{path}/enabled-regions-without-home-region",
            "value": ",".join(enabled_regions_without_home_region),
            "parameter_type": "StringList",
        }
    )

    ssm_data["helper"] = {"EnabledRegions": enabled_regions, "EnabledRegionsWithoutHomeRegion": enabled_regions_without_home_region}
    LOGGER.info(ssm_data["helper"])
    return ssm_data


def get_customer_control_tower_regions_ssm_parameter_info(home_region: str, path: str) -> dict:
    """Query customer regions chosen in Control Tower, and get info needed to create the SSM parameters.

    Args:
        home_region: Control Tower home region
        path: SSM parameter hierarchy path

    Returns:
        Info needed to create SSM parameters and helper data for custom resource
    """
    ssm_data: dict = {"info": []}
    customer_regions = get_customer_control_tower_regions()
    customer_regions_without_home_region = customer_regions.copy()
    customer_regions_without_home_region.remove(home_region)

    ssm_data["info"].append({"name": f"{path}/customer-control-tower-regions", "value": ",".join(customer_regions), "parameter_type": "StringList"})
    ssm_data["info"].append(
        {
            "name": f"{path}/customer-control-tower-regions-without-home-region",
            "value": ",".join(customer_regions_without_home_region),
            "parameter_type": "StringList",
        }
    )

    ssm_data["helper"] = {
        "CustomerControlTowerRegions": customer_regions,
        "CustomerControlTowerRegionsWithoutHomeRegion": customer_regions_without_home_region,
    }
    LOGGER.info(ssm_data["helper"])
    return ssm_data


def create_ssm_parameters_in_regions(ssm_parameters: list, tags: Sequence[TagTypeDef], regions: list) -> None:
    """Create SSM parameters in regions.

    Args:
        ssm_parameters: Info for the SSM parameters
        tags: Tags to be applied to the SSM parameters
        regions: Regions
    """
    parameters_created = set()
    for region in regions:
        region_ssm_client: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm", region_name=region)
        for parameter in ssm_parameters:
            create_ssm_parameter(region_ssm_client, name=parameter["name"], value=parameter["value"], parameter_type=parameter["parameter_type"])
            add_tags_to_ssm_parameter(region_ssm_client, resource_id=parameter["name"], tags=tags)
            parameters_created.add(parameter["name"])

        LOGGER.info(f"Completed the creation of SSM Parameters for '{region}' region.")
    LOGGER.info({"Created Parameters": list(parameters_created)})


def delete_ssm_parameters_in_regions(regions: list) -> None:  # noqa: CCR001
    """Delete SSM parameters in regions.

    Args:
        regions: Regions
    """
    for region in regions:
        region_ssm_client: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm", region_name=region)

        parameters_to_delete = []
        count = 0
        for parameter in SRA_SSM_PARAMETERS:
            count += 1  # noqa: SIM113
            if count <= SSM_DELETE_PARAMETERS_MAX:
                parameters_to_delete.append(parameter)
            if count == SSM_DELETE_PARAMETERS_MAX:
                count = 0
                delete_ssm_parameters(region_ssm_client, parameters_to_delete)
                parameters_to_delete = []
        if parameters_to_delete:
            delete_ssm_parameters(region_ssm_client, parameters_to_delete)

        LOGGER.info(f"Completed the deletion of SSM Parameters for '{region}' region.")
    LOGGER.info({"Deleted Parameters": SRA_SSM_PARAMETERS})


def parameter_pattern_validator(parameter_name: str, parameter_value: Union[str, None], pattern: str) -> None:
    """Validate CloudFormation Custom Resource Parameters.

    Args:
        parameter_name: CloudFormation custom resource parameter name
        parameter_value: CloudFormation custom resource parameter value
        pattern: REGEX pattern to validate against.

    Raises:
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern
    """
    if not parameter_value:
        raise ValueError(f"'{parameter_name}' parameter is missing.")
    elif not re.match(pattern, parameter_value):
        raise ValueError(f"'{parameter_name}' parameter with value of '{parameter_value}' does not follow the allowed pattern: {pattern}.")


def get_validated_parameters(event: CloudFormationCustomResourceEvent) -> dict:
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    params = event["ResourceProperties"].copy()
    parameter_pattern_validator("TAG_KEY", params["TAG_KEY"], pattern=r"^.{1,128}$")
    parameter_pattern_validator("TAG_VALUE", params["TAG_VALUE"], pattern=r"^.{1,256}$")

    return params


@helper.create
@helper.update
def create_update_event(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa: U100
    """Create/Update Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters(event)
    tags: Sequence[TagTypeDef] = [{"Key": params["TAG_KEY"], "Value": params["TAG_VALUE"]}]

    ssm_data1 = get_org_ssm_parameter_info(path=SRA_CONTROL_TOWER_SSM_PATH)
    ssm_data2 = get_cloudformation_ssm_parameter_info(path=SRA_CONTROL_TOWER_SSM_PATH)
    ssm_data3 = get_customer_control_tower_regions_ssm_parameter_info(ssm_data2["helper"]["HomeRegion"], path=SRA_REGIONS_SSM_PATH)
    ssm_data4 = get_enabled_regions_ssm_parameter_info(ssm_data2["helper"]["HomeRegion"], path=SRA_REGIONS_SSM_PATH)

    ssm_parameters = ssm_data1["info"] + ssm_data2["info"] + ssm_data3["info"] + ssm_data4["info"]
    create_ssm_parameters_in_regions(ssm_parameters, tags, ssm_data4["helper"]["EnabledRegions"])

    helper.Data = ssm_data1["helper"] | ssm_data2["helper"] | ssm_data3["helper"] | ssm_data4["helper"]
    return "MANAGEMENT-ACCOUNT-PARAMETERS"


@helper.delete
def delete_event(event: CloudFormationCustomResourceEvent, context: Context) -> None:  # noqa: U100
    """Delete Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    LOGGER.info("SRA SSM Parameters are being retained.")
    # delete_ssm_parameters_in_regions(get_enabled_regions())  # noqa: E800


def lambda_handler(event: CloudFormationCustomResourceEvent, context: Context) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    try:
        helper(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"See the details in CloudWatch Log Stream: '{context.log_group_name}'") from None
