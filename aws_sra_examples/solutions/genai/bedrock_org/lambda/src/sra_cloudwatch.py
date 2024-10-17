"""Custom Resource to setup SRA Config resources in the organization.

Version: 0.1

CloudWatch module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
from time import sleep

from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import json

import cfnresponse

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_oam import CloudWatchObservabilityAccessManagerClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef
    from mypy_boto3_cloudwatch.type_defs import MetricFilterTypeDef, GetMetricDataResponseTypeDef
    from mypy_boto3_logs.type_defs import FilteredLogEventTypeDef, GetLogEventsResponseTypeDef


class sra_cloudwatch:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    SINK_NAME = "sra-oam-sink"
    SOLUTION_NAME: str = "sra-set-solution-name"
    SINK_POLICY = ""
    CROSS_ACCOUNT_ROLE_NAME = "CloudWatch-CrossAccountSharingRole"

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        CLOUDWATCH_CLIENT: CloudWatchClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudwatch", config=BOTO3_CONFIG)
        CWLOGS_CLIENT: CloudWatchLogsClient = MANAGEMENT_ACCOUNT_SESSION.client("logs", config=BOTO3_CONFIG)
        CWOAM_CLIENT: CloudWatchObservabilityAccessManagerClient = MANAGEMENT_ACCOUNT_SESSION.client("oam", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def find_metric_filter(self, log_group_name: str, filter_name: str) -> bool:
        try:
            response = self.CWLOGS_CLIENT.describe_metric_filters(logGroupName=log_group_name, filterNamePrefix=filter_name)
            if response["metricFilters"]:
                return True
            else:
                return False
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            else:
                self.LOGGER.info(self.UNEXPECTED)
                raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_metric_filter(
        self, log_group_name: str, filter_name: str, filter_pattern: str, metric_name: str, metric_namespace: str, metric_value: str
    ) -> None:
        try:
            if not self.find_metric_filter(log_group_name, filter_name):
                # TODO(liamschn): finalize what parameters should be setup for this create_metric_filter function
                self.CWLOGS_CLIENT.put_metric_filter(
                    logGroupName=log_group_name,
                    filterName=filter_name,
                    filterPattern=filter_pattern,
                    metricTransformations=[
                        {
                            "metricName": metric_name,
                            "metricNamespace": metric_namespace,
                            "metricValue": metric_value,
                            "unit": "Count",
                            "defaultValue": 0,
                        }
                    ],
                )
        except ClientError as e:
            self.LOGGER.info(f"{self.UNEXPECTED} error: {e}")
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def delete_metric_filter(self, log_group_name: str, filter_name: str) -> None:
        try:
            if self.find_metric_filter(log_group_name, filter_name):
                self.CWLOGS_CLIENT.delete_metric_filter(logGroupName=log_group_name, filterName=filter_name)
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def update_metric_filter(
        self, log_group_name: str, filter_name: str, filter_pattern: str, metric_name: str, metric_namespace: str, metric_value: str
    ) -> None:
        try:
            self.delete_metric_filter(log_group_name, filter_name)
            self.create_metric_filter(log_group_name, filter_name, filter_pattern, metric_name, metric_namespace, metric_value)
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def find_metric_alarm(self, alarm_name: str) -> bool:
        try:
            response = self.CLOUDWATCH_CLIENT.describe_alarms(AlarmNames=[alarm_name])
            if response["MetricAlarms"]:
                return True
            else:
                return False
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            else:
                self.LOGGER.info(self.UNEXPECTED)
                raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_metric_alarm(
        self,
        alarm_name: str,
        alarm_description: str,
        metric_name: str,
        metric_namespace: str,
        metric_statistic: str,
        metric_period: int,
        metric_threshold: float,
        metric_comparison_operator: str,
        metric_evaluation_periods: int,
        metric_treat_missing_data: str,
        alarm_actions: list,
    ) -> None:
        self.LOGGER.info(f"DEBUG: Alarm actions: {alarm_actions}")
        try:
            if not self.find_metric_alarm(alarm_name):
                self.CLOUDWATCH_CLIENT.put_metric_alarm(
                    AlarmName=alarm_name,
                    AlarmDescription=alarm_description,
                    MetricName=metric_name,
                    Namespace=metric_namespace,
                    Statistic=metric_statistic,
                    Period=metric_period,
                    Threshold=metric_threshold,
                    ComparisonOperator=metric_comparison_operator,
                    EvaluationPeriods=metric_evaluation_periods,
                    TreatMissingData=metric_treat_missing_data,
                    AlarmActions=alarm_actions,
                )
        except ClientError as e:
            self.LOGGER.info(f"{self.UNEXPECTED} error: {e}")

    def delete_metric_alarm(self, alarm_name: str) -> None:
        try:
            if self.find_metric_alarm(alarm_name):
                self.CLOUDWATCH_CLIENT.delete_alarms(AlarmNames=[alarm_name])
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)

    def update_metric_alarm(
        self,
        alarm_name: str,
        alarm_description: str,
        metric_name: str,
        metric_namespace: str,
        metric_statistic: str,
        metric_period: int,
        metric_threshold: float,
        metric_comparison_operator: str,
        metric_evaluation_periods: int,
        metric_treat_missing_data: str,
        alarm_actions: list,
    ) -> None:
        try:
            self.delete_metric_alarm(alarm_name)
            self.create_metric_alarm(
                alarm_name,
                alarm_description,
                metric_name,
                metric_namespace,
                metric_statistic,
                metric_period,
                metric_threshold,
                metric_comparison_operator,
                metric_evaluation_periods,
                metric_treat_missing_data,
                alarm_actions,
            )
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)

    def find_oam_sink(self) -> tuple[bool, str, str]:
        """Find the Observability Access Manager sink for SRA in the organization.

        Args:
            None

        Raises:
            ValueError: unexpected error

        Returns:
            tuple[bool, str, str]: True if the sink is found, False if not, and the sink ARN and name
        """
        try:
            response = self.CWOAM_CLIENT.list_sinks()
            for sink in response["sinks"]:
                self.LOGGER.info(f"Observability access manager sink found: {sink}")
                return True, sink["Arn"], sink["Name"]
            self.LOGGER.info("Observability access manager sink not found")
            return False, "", ""
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"Observability access manager sink not found. Error code: {error.response['Error']['Code']}")
                return False, "", ""
            else:
                self.LOGGER.info(self.UNEXPECTED)
                raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_oam_sink(self, sink_name: str) -> str:
        """Create the Observability Access Manager sink for SRA in the organization.

        Args:
            sink_name (str): name of the sink

        Returns:
            str: ARN of the created sink
        """
        try:
            response = self.CWOAM_CLIENT.create_sink(Name=sink_name, Tags={"sra-solution": self.SOLUTION_NAME})
            self.LOGGER.info(f"Observability access manager sink {sink_name} created: {response['Arn']}")
            return response["Arn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConflictException":
                self.LOGGER.info(f"Observability access manager sink {sink_name} already exists")
                return self.find_oam_sink()[1]
            else:
                self.LOGGER.error(f"{self.UNEXPECTED} error: {e}")
                raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def delete_oam_sink(self, sink_arn: str) -> None:
        """Delete the Observability Access Manager sink for SRA in the organization.

        Args:
            sink_arn (str): ARN of the sink

        Returns:
            None
        """
        try:
            self.CWOAM_CLIENT.delete_sink(Identifier=sink_arn)
            self.LOGGER.info(f"Observability access manager sink {sink_arn} deleted")
        except ClientError as e:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def find_oam_sink_policy(self, sink_arn: str) -> tuple[bool, dict]:
        """Check if the Observability Access Manager sink policy for SRA in the organization exists.

        Args:
            sink_arn (str): ARN of the sink

        Returns:
            tuple[bool, dict]: True if the policy is found, False if not, and the policy
        """
        try:
            policy = self.CWOAM_CLIENT.get_sink_policy(SinkIdentifier=sink_arn)
            self.LOGGER.info(f"Observability access manager sink policy for {sink_arn} found")
            self.LOGGER.info({"Sink Policy": json.loads(policy["Policy"])})
            return True, json.loads(policy["Policy"])
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"Observability access manager sink policy for {sink_arn} not found")
                return False, {}
            else:
                self.LOGGER.info(self.UNEXPECTED)
                raise ValueError(f"Unexpected error executing Lambda function. {error}") from None

    def compare_oam_sink_policy(self, existing_policy: dict, new_policy: dict) -> bool:
        """Compare the existing Observability Access Manager sink policy with the new policy.

        Args:
            existing_policy (dict): existing policy
            new_policy (dict): new policy

        Returns:
            bool: True if the policies are the same, False if not
        """
        if existing_policy == new_policy:
            self.LOGGER.info("New observability access manager sink policy is the same")
            return True
        else:
            self.LOGGER.info("New observability access manager sink policy is different")
            return False

    def put_oam_sink_policy(self, sink_arn: str, sink_policy: dict) -> None:
        """Put the Observability Access Manager sink policy for SRA in the organization.

        Args:
            sink_arn (str): ARN of the sink
            sink_policy (dict): policy for the sink

        Returns:
            None
        """
        try:
            self.CWOAM_CLIENT.put_sink_policy(SinkIdentifier=sink_arn, Policy=json.dumps(sink_policy))
            self.LOGGER.info(f"Observability access manager sink policy for {sink_arn} created/updated")
        except ClientError as e:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def find_oam_link(self, sink_arn: str) -> tuple[bool, str]:
        """Find the Observability Access Manager link for SRA in the organization.

        Args:
            sink_arn (str): ARN of the sink

        Returns:
            tuple[bool, str]: True if the link is found, False if not, and the link ARN
        """
        try:
            response = self.CWOAM_CLIENT.list_links()
            for link in response["Items"]:
                if link["SinkArn"] == sink_arn:
                    self.LOGGER.info(f"Observability access manager link for {sink_arn} found: {link['Arn']}")
                    return True, link["Arn"]
            self.LOGGER.info(f"Observability access manager link for {sink_arn} not found")
            return False, ""
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"Observability access manager link for {sink_arn} not found. Error code: {error.response['Error']['Code']}")
                return False, ""
            else:
                self.LOGGER.info(self.UNEXPECTED)
                raise ValueError(f"Unexpected error executing Lambda function. {error}") from None