"""Lambda function module to setup SRA Cloudwatch resources in the organization.

Version: 1.0

CloudWatch module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Literal

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_logs import CloudWatchLogsClient
    from mypy_boto3_oam import CloudWatchObservabilityAccessManagerClient


class SRACloudWatch:
    """Class to setup SRA Cloudwatch resources in the organization."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    SINK_NAME = "sra-oam-sink"
    SOLUTION_NAME: str = "sra-set-solution-name"
    SINK_POLICY: dict = {}
    CROSS_ACCOUNT_ROLE_NAME: str = "CloudWatch-CrossAccountSharingRole"
    CROSS_ACCOUNT_TRUST_POLICY: dict = {}

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        CLOUDWATCH_CLIENT: CloudWatchClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudwatch", config=BOTO3_CONFIG)
        CWLOGS_CLIENT: CloudWatchLogsClient = MANAGEMENT_ACCOUNT_SESSION.client("logs", config=BOTO3_CONFIG)
        CWOAM_CLIENT: CloudWatchObservabilityAccessManagerClient = MANAGEMENT_ACCOUNT_SESSION.client("oam", config=BOTO3_CONFIG)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def find_metric_filter(self, log_group_name: str, filter_name: str) -> bool:
        """Find metric filter.

        Args:
            log_group_name (str): Log group name to search for metric filter
            filter_name (str): Metric filter name to search for

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.

        Returns:
            bool: True if metric filter is found, False if not found
        """
        try:
            response = self.CWLOGS_CLIENT.describe_metric_filters(logGroupName=log_group_name, filterNamePrefix=filter_name)
            if response["metricFilters"]:
                return True
            return False
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            self.LOGGER.info(f"{self.UNEXPECTED} error finding metric filter: {error}")
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_metric_filter(
        self, log_group_name: str, filter_name: str, filter_pattern: str, metric_name: str, metric_namespace: str, metric_value: str
    ) -> None:
        """Create metric filter.

        Args:
            log_group_name (str): Log group name to create metric filter
            filter_name (str): Metric filter name to create
            filter_pattern (str): Metric filter pattern to create
            metric_name (str): Metric name to create
            metric_namespace (str): Metric namespace to create
            metric_value (str): Metric value to create

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.
        """
        try:
            if not self.find_metric_filter(log_group_name, filter_name):
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
        """Delete metric filter.

        Args:
            log_group_name (str): Log group name to delete metric filter
            filter_name (str): Metric filter name to delete

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.
        """
        try:
            if self.find_metric_filter(log_group_name, filter_name):
                self.CWLOGS_CLIENT.delete_metric_filter(logGroupName=log_group_name, filterName=filter_name)
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def update_metric_filter(
        self, log_group_name: str, filter_name: str, filter_pattern: str, metric_name: str, metric_namespace: str, metric_value: str
    ) -> None:
        """Update metric filter.

        Args:
            log_group_name (str): Log group name to update metric filter
            filter_name (str): Metric filter name to update
            filter_pattern (str): Metric filter pattern to update
            metric_name (str): Metric name to update
            metric_namespace (str): Metric namespace to update
            metric_value (str): Metric value to update

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.
        """
        try:
            self.delete_metric_filter(log_group_name, filter_name)
            self.create_metric_filter(log_group_name, filter_name, filter_pattern, metric_name, metric_namespace, metric_value)
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def find_metric_alarm(self, alarm_name: str) -> bool:
        """Find metric alarm.

        Args:
            alarm_name (str): Alarm name to search for

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.

        Returns:
            bool: True if metric alarm is found, False if not found
        """
        try:
            response = self.CLOUDWATCH_CLIENT.describe_alarms(AlarmNames=[alarm_name])
            if response["MetricAlarms"]:
                return True
            return False
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_metric_alarm(  # noqa: CFQ002
        self,
        alarm_name: str,
        alarm_description: str,
        metric_name: str,
        metric_namespace: str,
        metric_statistic: Literal["Average", "Maximum", "Minimum", "SampleCount", "Sum"],
        metric_period: int,
        metric_threshold: float,
        metric_comparison_operator: Literal[
            "GreaterThanOrEqualToThreshold",
            "GreaterThanThreshold",
            "GreaterThanUpperThreshold",
            "LessThanLowerOrGreaterThanUpperThreshold",
            "LessThanLowerThreshold",
            "LessThanOrEqualToThreshold",
            "LessThanThreshold",
        ],
        metric_evaluation_periods: int,
        metric_treat_missing_data: str,
        alarm_actions: list,
    ) -> None:
        """Create metric alarm.

        Args:
            alarm_name (str): Alarm name to create
            alarm_description (str): Alarm description to create
            metric_name (str): Metric name to create
            metric_namespace (str): Metric namespace to create
            metric_statistic (Literal['Average', 'Maximum', 'Minimum', 'SampleCount', 'Sum']): Metric statistic to create
            metric_period (int): Metric period to create
            metric_threshold (float): Metric threshold to create
            metric_comparison_operator (Literal['GreaterThanOrEqualToThreshold', 'GreaterThanThreshold', 'GreaterThanUpperThreshold',
                    'LessThanLowerOrGreaterThanUpperThreshold', 'LessThanLowerThreshold', 'LessThanOrEqualToThreshold',
                    'LessThanThreshold']): Metric comparison operator to create
            metric_evaluation_periods (int): Metric evaluation periods to create
            metric_treat_missing_data (str): Metric treat missing data to create
            alarm_actions (list): Alarm actions to create
        """
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
        """Delete metric alarm.

        Args:
            alarm_name (str): Alarm name to delete
        """
        try:
            if self.find_metric_alarm(alarm_name):
                self.CLOUDWATCH_CLIENT.delete_alarms(AlarmNames=[alarm_name])
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)

    def update_metric_alarm(  # noqa: CFQ002
        self,
        alarm_name: str,
        alarm_description: str,
        metric_name: str,
        metric_namespace: str,
        metric_statistic: Literal["Average", "Maximum", "Minimum", "SampleCount", "Sum"],
        metric_period: int,
        metric_threshold: float,
        metric_comparison_operator: Literal[
            "GreaterThanOrEqualToThreshold",
            "GreaterThanThreshold",
            "GreaterThanUpperThreshold",
            "LessThanLowerOrGreaterThanUpperThreshold",
            "LessThanLowerThreshold",
            "LessThanOrEqualToThreshold",
            "LessThanThreshold",
        ],
        metric_evaluation_periods: int,
        metric_treat_missing_data: str,
        alarm_actions: list,
    ) -> None:
        """Update metric alarm.

        Args:
            alarm_name (str): Alarm name to update
            alarm_description (str): Alarm description to update
            metric_name (str): Metric name to update
            metric_namespace (str): Metric namespace to update
            metric_statistic (Literal['Average', 'Maximum', 'Minimum', 'SampleCount', 'Sum']): Metric statistic to update
            metric_period (int): Metric period to update
            metric_threshold (float): Metric threshold to update
            metric_comparison_operator (Literal['GreaterThanOrEqualToThreshold', 'GreaterThanThreshold', 'GreaterThanUpperThreshold',
                        'LessThanLowerOrGreaterThanUpperThreshold', 'LessThanLowerThreshold', 'LessThanOrEqualToThreshold',
                        'LessThanThreshold']): Metric comparison operator to create
            metric_evaluation_periods (int): Metric evaluation periods to update
            metric_treat_missing_data (str): Metric treat missing data to update
            alarm_actions (list): Alarm actions to update
        """
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
            for sink in response["Items"]:
                self.LOGGER.info(f"Observability access manager sink found: {sink}")
                return True, sink["Arn"], sink["Name"]
            self.LOGGER.info("Observability access manager sink not found")
            return False, "", ""
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"Observability access manager sink not found. Error code: {error.response['Error']['Code']}")
                return False, "", ""
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def create_oam_sink(self, sink_name: str) -> str:
        """Create the Observability Access Manager sink for SRA in the organization.

        Args:
            sink_name (str): name of the sink

        Raises:
            ValueError: unexpected error

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
            self.LOGGER.error(f"{self.UNEXPECTED} error: {e}")
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def find_oam_sink_policy(self, sink_arn: str) -> tuple[bool, dict]:
        """Check if the Observability Access Manager sink policy for SRA in the organization exists.

        Args:
            sink_arn (str): ARN of the sink

        Raises:
            ValueError: unexpected error

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
        self.LOGGER.info("New observability access manager sink policy is different")
        return False

    def put_oam_sink_policy(self, sink_arn: str, sink_policy: dict) -> None:
        """Put the Observability Access Manager sink policy for SRA in the organization.

        Args:
            sink_arn (str): ARN of the sink
            sink_policy (dict): policy for the sink

        Raises:
            ValueError: unexpected error
        """
        try:
            self.CWOAM_CLIENT.put_sink_policy(SinkIdentifier=sink_arn, Policy=json.dumps(sink_policy))
            self.LOGGER.info(f"Observability access manager sink policy for {sink_arn} created/updated")
        except ClientError as e:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def delete_oam_sink(self, sink_arn: str) -> None:
        """Delete the Observability Access Manager sink for SRA in the organization.

        Args:
            sink_arn (str): ARN of the sink

        Raises:
            ValueError: unexpected error
        """
        try:
            self.CWOAM_CLIENT.delete_sink(Identifier=sink_arn)
            self.LOGGER.info(f"Observability access manager sink {sink_arn} deleted")
        except ClientError as e:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def find_oam_link(self, sink_arn: str) -> tuple[bool, str]:
        """Find the Observability Access Manager link for SRA in the organization.

        Args:
            sink_arn (str): ARN of the sink

        Raises:
            ValueError: unexpected error

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
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {error}") from None

    def create_oam_link(self, sink_arn: str) -> str:
        """Create the Observability Access Manager link for SRA in the organization.

        Args:
            sink_arn (str): ARN of the sink

        Raises:
            ValueError: unexpected error

        Returns:
            str: ARN of the created link
        """
        try:
            response = self.CWOAM_CLIENT.create_link(
                LabelTemplate="$AccountName",
                ResourceTypes=[
                    "AWS::ApplicationInsights::Application",
                    "AWS::InternetMonitor::Monitor",
                    "AWS::Logs::LogGroup",
                    "AWS::CloudWatch::Metric",
                    "AWS::XRay::Trace",
                ],
                SinkIdentifier=sink_arn,
                Tags={"sra-solution": self.SOLUTION_NAME},
            )
            self.LOGGER.info(f"Observability access manager link for {sink_arn} created: {response['Arn']}")
            return response["Arn"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "ConflictException":
                self.LOGGER.info(f"Observability access manager link for {sink_arn} already exists")
                return self.find_oam_link(sink_arn)[1]
            if error.response["Error"]["Code"] == "InvalidParameterException":
                self.LOGGER.info(f"Arn validation may have failed for {sink_arn}")
                return "error"
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {error}") from None

    def delete_oam_link(self, link_arn: str) -> None:
        """Delete the Observability Access Manager link for SRA in the organization.

        Args:
            link_arn (str): ARN of the link

        Raises:
            ValueError: unexpected error
        """
        try:
            self.CWOAM_CLIENT.delete_link(Identifier=link_arn)
            self.LOGGER.info(f"Observability access manager link for {link_arn} deleted")
        except ClientError as e:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def find_dashboard(self, dashboard_name: str) -> tuple[bool, str]:
        """Find the CloudWatch dashboard for SRA in the organization.

        Args:
            dashboard_name (str): name of the dashboard

        Raises:
            ValueError: unexpected error

        Returns:
            tuple[bool, str]: True if the dashboard is found, False if not, and the dashboard ARN
        """
        try:
            response = self.CLOUDWATCH_CLIENT.list_dashboards()
            for dashboard in response["DashboardEntries"]:
                if dashboard["DashboardName"] == dashboard_name:
                    self.LOGGER.info(f"CloudWatch dashboard {dashboard_name} found: {dashboard['DashboardArn']}")
                    return True, dashboard["DashboardArn"]
            self.LOGGER.info(f"CloudWatch dashboard {dashboard_name} not found")
            return False, ""
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"CloudWatch dashboard {dashboard_name} not found. Error code: {error.response['Error']['Code']}")
                return False, ""
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {error}") from None

    def create_dashboard(self, dashboard_name: str, dashboard_body: dict) -> str:
        """Create the CloudWatch dashboard for SRA in the organization.

        Args:
            dashboard_name (str): name of the dashboard
            dashboard_body (dict): body of the dashboard

        Raises:
            ValueError: unexpected error

        Returns:
            str: ARN of the created dashboard
        """
        try:
            self.LOGGER.info(f"Creating CloudWatch dashboard {dashboard_name} as: {json.dumps(dashboard_body)}")
            self.LOGGER.info({"dashboard json": dashboard_body})
            response = self.CLOUDWATCH_CLIENT.put_dashboard(DashboardName=dashboard_name, DashboardBody=json.dumps(dashboard_body))
            self.LOGGER.info(f"CloudWatch dashboard {dashboard_name} created: {response['DashboardValidationMessages']}")
            return self.find_dashboard(dashboard_name)[1]
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceAlreadyExistsException":
                self.LOGGER.info(f"CloudWatch dashboard {dashboard_name} already exists")
                return self.find_dashboard(dashboard_name)[1]
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {error}") from None

    def delete_dashboard(self, dashboard_name: str) -> None:
        """Delete the CloudWatch dashboard for SRA in the organization.

        Args:
            dashboard_name (str): Name of the dashboard

        Raises:
            ValueError: Unexpected error
        """
        try:
            self.CLOUDWATCH_CLIENT.delete_dashboards(DashboardNames=[dashboard_name])
            self.LOGGER.info(f"CloudWatch dashboard {dashboard_name} deleted")
        except ClientError as e:
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {e}") from None

    def find_log_group(self, log_group_name: str) -> tuple[bool, str]:
        """Find the CloudWatch log group for SRA in the organization.

        Args:
            log_group_name (str): name of the log group

        Raises:
            ValueError: unexpected error

        Returns:
            tuple[bool, str]: True if the log group is found, False if not, and the log group ARN
        """
        try:
            response = self.CWLOGS_CLIENT.describe_log_groups(logGroupNamePrefix=log_group_name)
            for log_group in response["logGroups"]:
                if log_group["logGroupName"] == log_group_name:
                    self.LOGGER.info(f"CloudWatch log group {log_group_name} found: {log_group['arn']}")
                    return True, log_group["arn"]
            self.LOGGER.info(f"CloudWatch log group {log_group_name} not found")
            return False, ""
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                self.LOGGER.info(f"CloudWatch log group {log_group_name} not found. Error code: {error.response['Error']['Code']}")
                return False, ""
            self.LOGGER.info(self.UNEXPECTED)
            raise ValueError(f"Unexpected error executing Lambda function. {error}") from None
