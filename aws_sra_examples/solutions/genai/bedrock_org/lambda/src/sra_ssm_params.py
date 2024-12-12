"""Custom Resource to gather data and create SSM paramters in the management account.

Version: 1.0

SSM Params module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, List, Literal, Optional, Sequence, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

if TYPE_CHECKING:
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_ssm.type_defs import TagTypeDef


class SRASSMParams:
    """Class to manage SSM Parameters."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    # Global Variables
    CONTROL_TOWER: str = ""
    OTHER_REGIONS: str = ""
    OTHER_SECURITY_ACCT: str = ""
    OTHER_LOG_ARCHIVE_ACCT: str = ""
    RESOURCE_TYPE: str = ""
    CLOUDFORMATION_THROTTLE_PERIOD = 0.2
    CLOUDFORMATION_PAGE_SIZE = 100
    SSM_DELETE_PARAMETERS_MAX = 10
    SRA_CONTROL_TOWER_SSM_PATH = "/sra/control-tower"
    SRA_REGIONS_SSM_PATH = "/sra/regions"
    SRA_ROOT_SSM_PATH = "/sra"
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
        "/sra/staging-s3-bucket-name",
    ]

    SRA_STAGING_BUCKET: str = ""
    UNEXPECTED = "Unexpected!"
    EMPTY_VALUE = "NONE"
    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    SRA_SECURITY_ACCT: str = ""
    SRA_ORG_ID: str = ""
    SSM_SECURITY_ACCOUNT_ID: str = ""
    SSM_LOG_ARCHIVE_ACCOUNT: str = ""

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
        CFN_CLIENT: CloudFormationClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudformation", config=BOTO3_CONFIG)
        STS_CLIENT = boto3.client("sts")
        HOME_REGION = MANAGEMENT_ACCOUNT_SESSION.region_name
        LOGGER.info(f"Detected home region: {HOME_REGION}")
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error.") from None

    try:
        MANAGEMENT_ACCOUNT = STS_CLIENT.get_caller_identity().get("Account")
        LOGGER.info(f"Detected management account (current account): {MANAGEMENT_ACCOUNT}")
    except ClientError as error:
        if error.response["Error"]["Code"] == "ExpiredToken":
            LOGGER.info(f"Error getting management account: {error.response['Error']['Code']}")
        else:
            LOGGER.exception(f"Unexpected error getting management account: {error.response['Error']['Code']}")
            raise ValueError("Unexpected error.") from None

    def add_tags_to_ssm_parameter(self, ssm_client: SSMClient, resource_id: str, tags: Sequence[TagTypeDef]) -> None:
        """Add tags to SSM parameter.

        Args:
            ssm_client: Boto3 SSM client
            resource_id: SSM parameter name
            tags: Tags to apply to SSM parameter
        """
        response = ssm_client.add_tags_to_resource(ResourceType="Parameter", ResourceId=resource_id, Tags=tags)
        self.LOGGER.debug({"API_Call": "ssm:AddTagsToResource", "API_Response": response})

    def create_ssm_parameter(
        self, ssm_client: SSMClient, name: str, value: str, parameter_type: Union[Literal["String"], Literal["StringList"]]
    ) -> None:
        """Create SSM parameter.

        Args:
            ssm_client: Boto3 SSM client
            name: SSM parameter name
            value: SSM parameter value
            parameter_type: SSM parameter type
        """
        if not value:
            value = self.EMPTY_VALUE
        response = ssm_client.put_parameter(Name=name, Value=value, Type=parameter_type, Overwrite=True)
        self.LOGGER.debug({"API_Call": "ssm:PutParameter", "API_Response": response})

    def delete_ssm_parameters(self, ssm_client: SSMClient, names: list) -> None:
        """Delete SSM parameters.

        Args:
            ssm_client: Boto3 SSM client
            names: SSM parameter names
        """
        response = ssm_client.delete_parameters(Names=names)
        self.LOGGER.debug({"API_Call": "ssm:DeleteParameters", "API_Response": response})

    def get_customer_control_tower_regions(self) -> list:  # noqa: CCR001
        """Query 'AWSControlTowerBP-BASELINE-CLOUDWATCH' CloudFormation stack to identify customer regions.

        Returns:
            Customer regions chosen in Control Tower
        """
        paginator = self.CFN_CLIENT.get_paginator("list_stack_instances")
        customer_regions = []
        aws_account = ""
        all_regions_identified = False
        for page in paginator.paginate(
            StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH", PaginationConfig={"PageSize": self.CLOUDFORMATION_PAGE_SIZE}
        ):
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
            sleep(self.CLOUDFORMATION_THROTTLE_PERIOD)

        return customer_regions

    def get_customer_other_regions(self) -> list:  # noqa: CCR001
        """Query [something else] to identify customer regions.

        Returns:
            Customer regions chosen
        """
        customer_regions = []
        for region in self.OTHER_REGIONS.split(","):
            customer_regions.append(region)

        return customer_regions

    def get_enabled_regions(self) -> list:  # noqa: CCR001
        """Query AWS account to identify enabled regions.

        Raises:
            EndpointConnectionError: region is not valid.

        Returns:
            Enabled regions
        """
        default_available_regions: List[str] = [
            region["RegionName"] for region in boto3.client("account").list_regions(
                RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"]
            )["Regions"]
        ]
        self.LOGGER.info({"Default_Available_Regions": default_available_regions})

        enabled_regions = []
        disabled_regions = []
        region_session = boto3.Session()
        for region in default_available_regions:
            self.LOGGER.info(f"testing region: {region}")
            try:
                sts_client = region_session.client(
                    "sts", endpoint_url=f"https://sts.{region}.amazonaws.com", region_name=region, config=self.BOTO3_CONFIG
                )
                sts_client.get_caller_identity()
                enabled_regions.append(region)
            except EndpointConnectionError:
                self.LOGGER.error(f"Region: '{region}' is not valid.")
                raise
            except ClientError as error:
                if error.response["Error"]["Code"] == "InvalidClientTokenId":
                    disabled_regions.append(region)
                    continue
                raise

        self.LOGGER.info({"Disabled_Regions": disabled_regions})
        return enabled_regions

    def get_staging_bucket_ssm_parameter_info(self, path: str) -> dict:
        """Get info needed to create the staging bucket SSM parameter.

        Args:
            path: SSM parameter hierarchy path

        Returns:
            Info needed to create SSM parameters and helper data for custom resource
        """
        ssm_data: dict = {"info": []}

        ssm_data["info"].append(
            {
                "name": f"{path}/staging-s3-bucket-name",
                "value": self.SRA_STAGING_BUCKET,
                "parameter_type": "String",
                "description": "staging bucket name parameter",
            }
        )
        ssm_data["helper"] = {"StagingBucketName": self.SRA_STAGING_BUCKET}
        self.LOGGER.info(ssm_data["helper"])
        return ssm_data

    def get_org_ssm_parameter_info(self, path: str) -> dict:
        """Query AWS Organizations, and get info needed to create the SSM parameters.

        Args:
            path: SSM parameter hierarchy path

        Returns:
            Info needed to create SSM parameters and helper data for custom resource
        """
        ssm_data: dict = {"info": []}
        org = self.ORG_CLIENT.describe_organization()["Organization"]
        root_id = self.ORG_CLIENT.list_roots()["Roots"][0]["Id"]

        ssm_data["info"].append(
            {"name": f"{path}/root-organizational-unit-id", "value": root_id, "parameter_type": "String", "description": "root ou parameter"}
        )
        ssm_data["info"].append(
            {"name": f"{path}/organization-id", "value": org["Id"], "parameter_type": "String", "description": "organization id parameter"}
        )
        self.SRA_ORG_ID = org["Id"]
        ssm_data["info"].append(
            {
                "name": f"{path}/management-account-id",
                "value": org["MasterAccountId"],
                "parameter_type": "String",
                "description": "management account parameter",
            }
        )
        ssm_data["helper"] = {
            "ManagementAccountId": org["MasterAccountId"],
            "OrganizationId": org["Id"],
            "RootOrganizationalUnitId": root_id,
        }
        self.LOGGER.info(ssm_data["helper"])
        return ssm_data

    def get_cloudformation_ssm_parameter_info(self, path: str) -> dict:  # noqa: CCR001
        """Query AWS CloudFormation stacksets, and get info needed to create the SSM parameters from AWS control tower environments.

        Args:
            path: SSM parameter hierarchy path

        Returns:
            Info needed to create SSM parameters and helper data for custom resource
        """
        ssm_data: dict = {"info": [], "helper": {}}
        response = self.CFN_CLIENT.describe_stack_set(StackSetName="AWSControlTowerBP-BASELINE-CONFIG")
        for parameter in response["StackSet"]["Parameters"]:
            if parameter["ParameterKey"] == "HomeRegionName":
                ssm_data["info"].append(
                    {
                        "name": f"{path}/home-region",
                        "value": parameter["ParameterValue"],
                        "parameter_type": "String",
                        "description": "home region parameter",
                    }
                )
                ssm_data["helper"]["HomeRegion"] = parameter["ParameterValue"]
            if parameter["ParameterKey"] == "SecurityAccountId":
                ssm_data["info"].append(
                    {
                        "name": f"{path}/audit-account-id",
                        "value": parameter["ParameterValue"],
                        "parameter_type": "String",
                        "description": "security tooling account parameter",
                    }
                )
                ssm_data["helper"]["AuditAccountId"] = parameter["ParameterValue"]
                self.SRA_SECURITY_ACCT = parameter["ParameterValue"]

        paginator = self.CFN_CLIENT.get_paginator("list_stack_instances")
        for page in paginator.paginate(StackSetName="AWSControlTowerLoggingResources", PaginationConfig={"PageSize": self.CLOUDFORMATION_PAGE_SIZE}):
            for instance in page["Summaries"]:
                ssm_data["info"].append(
                    {
                        "name": f"{path}/log-archive-account-id",
                        "value": instance["Account"],
                        "parameter_type": "String",
                        "description": "log archive account parameter",
                    }
                )
                ssm_data["helper"]["LogArchiveAccountId"] = instance["Account"]
            sleep(self.CLOUDFORMATION_THROTTLE_PERIOD)

        self.LOGGER.info(ssm_data["helper"])
        return ssm_data

    def get_other_ssm_parameter_info(self, path: str) -> dict:  # noqa: CCR001
        """Get info needed to create the SSM parameters for non-control tower environments.

        Args:
            path: SSM parameter hierarchy path

        Returns:
            Info needed to create SSM parameters and helper data for custom resource
        """
        self.LOGGER.info("Not using AWS Control Tower...")
        ssm_data: dict = {"info": [], "helper": {}}
        # home region parameter
        ssm_data["info"].append(
            {"name": f"{path}/home-region", "value": self.HOME_REGION, "parameter_type": "String", "description": "home region parameter"}
        )
        ssm_data["helper"]["HomeRegion"] = self.HOME_REGION
        # security tooling account id parameter
        ssm_data["info"].append(
            {
                "name": f"{path}/audit-account-id",
                "value": self.OTHER_SECURITY_ACCT,
                "parameter_type": "String",
                "description": "security tooling account parameter",
            }
        )
        ssm_data["helper"]["AuditAccountId"] = self.OTHER_SECURITY_ACCT
        self.SRA_SECURITY_ACCT = self.OTHER_SECURITY_ACCT
        # log archive account id parameter
        ssm_data["info"].append(
            {
                "name": f"{path}/log-archive-account-id",
                "value": self.OTHER_LOG_ARCHIVE_ACCT,
                "parameter_type": "String",
                "description": "log archive account parameter",
            }
        )
        ssm_data["helper"]["LogArchiveAccountId"] = self.OTHER_LOG_ARCHIVE_ACCT

        self.LOGGER.info(ssm_data["helper"])
        return ssm_data

    def get_enabled_regions_ssm_parameter_info(self, home_region: str, path: str) -> dict:  # noqa: CCR001
        """Query STS for enabled regions, and get info needed to create the SSM parameters.

        Args:
            home_region: Control Tower home region
            path: SSM parameter hierarchy path

        Returns:
            Info needed to create SSM parameters and helper data for custom resource
        """
        ssm_data: dict = {"info": []}
        enabled_regions = self.get_enabled_regions()
        enabled_regions_without_home_region = enabled_regions.copy()
        enabled_regions_without_home_region.remove(home_region)

        ssm_data["info"].append(
            {
                "name": f"{path}/enabled-regions",
                "value": ",".join(enabled_regions),
                "parameter_type": "StringList",
                "description": "all enabled regions parameter",
            }
        )
        ssm_data["info"].append(
            {
                "name": f"{path}/enabled-regions-without-home-region",
                "value": ",".join(enabled_regions_without_home_region),
                "parameter_type": "StringList",
                "description": "all enabled regions without home region parameter",
            }
        )

        ssm_data["helper"] = {"EnabledRegions": enabled_regions, "EnabledRegionsWithoutHomeRegion": enabled_regions_without_home_region}
        self.LOGGER.info(ssm_data["helper"])
        return ssm_data

    def get_customer_control_tower_regions_ssm_parameter_info(self, home_region: str, path: str) -> dict:
        """Query customer regions chosen in Control Tower, and get info needed to create the SSM parameters.

        Args:
            home_region: Control Tower home region
            path: SSM parameter hierarchy path

        Returns:
            Info needed to create SSM parameters and helper data for custom resource
        """
        self.LOGGER.info(home_region)
        ssm_data: dict = {"info": []}
        if self.CONTROL_TOWER == "true":
            customer_regions = self.get_customer_control_tower_regions()
        else:
            customer_regions = self.get_customer_other_regions()
            self.LOGGER.info(f"customer regions: {customer_regions}")
        customer_regions_without_home_region = customer_regions.copy()
        customer_regions_without_home_region.remove(home_region)
        self.LOGGER.info(f"customer_regions_without_home_region: {customer_regions_without_home_region}")

        ssm_data["info"].append(
            {
                "name": f"{path}/customer-control-tower-regions",
                "value": ",".join(customer_regions),
                "parameter_type": "StringList",
                "description": "governed regions parameter",
            }
        )
        ssm_data["info"].append(
            {
                "name": f"{path}/customer-control-tower-regions-without-home-region",
                "value": ",".join(customer_regions_without_home_region),
                "parameter_type": "StringList",
                "description": "governed regions without home region parameter",
            }
        )

        ssm_data["helper"] = {
            "CustomerControlTowerRegions": customer_regions,
            "CustomerControlTowerRegionsWithoutHomeRegion": customer_regions_without_home_region,
        }
        self.LOGGER.info(f"ssm_data helper: {ssm_data['helper']}")
        return ssm_data

    def create_ssm_parameters_in_regions(self, ssm_parameters: list, tags: Sequence[TagTypeDef], regions: list) -> None:
        """Create SSM parameters in regions.

        Args:
            ssm_parameters: Info for the SSM parameters
            tags: Tags to be applied to the SSM parameters
            regions: Regions
        """
        parameters_created = set()
        for region in regions:
            region_ssm_client: SSMClient = self.MANAGEMENT_ACCOUNT_SESSION.client("ssm", region_name=region, config=self.BOTO3_CONFIG)
            for parameter in ssm_parameters:
                ssm_param_found, ssm_param_value = self.get_ssm_parameter(self.MANAGEMENT_ACCOUNT_SESSION, region, parameter["name"])
                if ssm_param_found is False:
                    self.LOGGER.info(f"Creating SSM parameter '{parameter['name']}' with value '{parameter['value']}'...")
                    self.create_ssm_parameter(
                        region_ssm_client, name=parameter["name"], value=parameter["value"], parameter_type=parameter["parameter_type"]
                    )
                    self.add_tags_to_ssm_parameter(region_ssm_client, resource_id=parameter["name"], tags=tags)
                    parameters_created.add(parameter["name"])
                else:
                    if ssm_param_value != parameter["value"]:
                        self.LOGGER.info(f"Updating SSM parameter '{parameter['name']}' with value '{parameter['value']}'...")
                        self.update_ssm_parameter(region_ssm_client, name=parameter["name"], value=parameter["value"])
                        self.add_tags_to_ssm_parameter(region_ssm_client, resource_id=parameter["name"], tags=tags)
                        parameters_created.add(parameter["name"])
            self.LOGGER.info(f"Completed the creation of SSM Parameters for '{region}' region.")
        self.LOGGER.info({"Created Parameters": list(parameters_created)})

    def update_ssm_parameter(self, ssm_client: Any, name: str, value: str) -> None:
        """Update SSM parameter.

        Args:
            ssm_client: SSM client
            name: SSM parameter name
            value: SSM parameter value
        """
        try:
            ssm_client.put_parameter(
                Name=name,
                Value=value,
                Type="String",
                Overwrite=True,
            )
        except ClientError as error:
            self.LOGGER.error(f"Error updating SSM parameter '{name}': {error}")

    def delete_ssm_parameters_in_regions(self, regions: list) -> None:  # noqa: CCR001
        """Delete SSM parameters in regions.

        Args:
            regions: Regions
        """
        for region in regions:
            region_ssm_client: SSMClient = self.MANAGEMENT_ACCOUNT_SESSION.client("ssm", region_name=region, config=self.BOTO3_CONFIG)

            parameters_to_delete = []
            count = 0  # noqa: SIM113
            for parameter in self.SRA_SSM_PARAMETERS:
                count += 1  # noqa: SIM113
                if count <= self.SSM_DELETE_PARAMETERS_MAX:
                    parameters_to_delete.append(parameter)
                if count == self.SSM_DELETE_PARAMETERS_MAX:
                    count = 0
                    self.delete_ssm_parameters(region_ssm_client, parameters_to_delete)
                    parameters_to_delete = []
            if parameters_to_delete:
                self.delete_ssm_parameters(region_ssm_client, parameters_to_delete)

            self.LOGGER.info(f"Completed the deletion of SSM Parameters for '{region}' region.")
        self.LOGGER.info({"Deleted Parameters": self.SRA_SSM_PARAMETERS})

    def parameter_pattern_validator(self, parameter_name: str, parameter_value: Optional[str], pattern: str) -> None:
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

    def get_validated_parameters(self, event: CloudFormationCustomResourceEvent) -> dict:
        """Validate AWS CloudFormation parameters.

        Args:
            event: event data

        Returns:
            Validated parameters
        """
        params = event["ResourceProperties"].copy()
        self.parameter_pattern_validator("TAG_KEY", params["TAG_KEY"], pattern=r"^.{1,128}$")
        self.parameter_pattern_validator("TAG_VALUE", params["TAG_VALUE"], pattern=r"^.{1,256}$")

        return params

    def get_ssm_parameter(self, session: Any, region: str, parameter: str) -> tuple[bool, str]:
        """Get SSM parameter value.

        Args:
            session: boto3 session
            region: region
            parameter: parameter name

        Returns:
            True and parameter value if found, otherwise False and empty string
        """
        self.LOGGER.info(f"Getting SSM parameter '{parameter}'...")
        ssm_client: SSMClient = session.client("ssm", region_name=region, config=self.BOTO3_CONFIG)

        try:
            response = ssm_client.get_parameter(Name=parameter)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                self.LOGGER.info(f"SSM parameter '{parameter}' not found.")
                return False, ""
            self.LOGGER.info(f"Error getting SSM parameter '{parameter}': {e.response['Error']['Message']}")
            return False, ""
        self.LOGGER.info(f"SSM parameter '{parameter}' found.")
        return True, response["Parameter"]["Value"]
