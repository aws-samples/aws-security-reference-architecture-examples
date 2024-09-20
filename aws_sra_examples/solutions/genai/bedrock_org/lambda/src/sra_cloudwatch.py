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

# import re
# from time import sleep
from typing import TYPE_CHECKING

# , Literal, Optional, Sequence, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# import urllib.parse
import json

import cfnresponse

if TYPE_CHECKING:
    # from mypy_boto3_cloudformation import CloudFormationClient
    # from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_logs import CloudWatchLogsClient
    # from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef
    from mypy_boto3_cloudwatch.type_defs import MetricFilterTypeDef, GetMetricDataResponseTypeDef
    # from mypy_boto3_cloudwatch.paginators import GetMetricDataPaginator
    from mypy_boto3_logs.type_defs import FilteredLogEventTypeDef, GetLogEventsResponseTypeDef


class sra_cloudwatch:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    UNEXPECTED = "Unexpected!"

    try:
        MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
        # ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations", config=BOTO3_CONFIG)
        CLOUDWATCH_CLIENT: CloudWatchClient = MANAGEMENT_ACCOUNT_SESSION.client("cloudwatch", config=BOTO3_CONFIG)
        CWLOGS_CLIENT: CloudWatchLogsClient = MANAGEMENT_ACCOUNT_SESSION.client("logs", config=BOTO3_CONFIG)
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
    
    def create_metric_filter(self, log_group_name: str, filter_name: str, filter_pattern: str, metric_name: str, metric_namespace: str, metric_value: str) -> None:
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
                            "defaultValue": 0
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
    
    def update_metric_filter(self, log_group_name: str, filter_name: str, filter_pattern: str, metric_name: str, metric_namespace: str, metric_value: str) -> None:
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
    
    def create_metric_alarm(self, alarm_name: str, alarm_description: str, metric_name: str, metric_namespace: str, metric_statistic: str, metric_period: int, metric_threshold: float, metric_comparison_operator: str, metric_evaluation_periods: int, metric_treat_missing_data: str, alarm_actions: list) -> None:
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
    
    def update_metric_alarm(self, alarm_name: str, alarm_description: str, metric_name: str, metric_namespace: str, metric_statistic: str, metric_period: int, metric_threshold: float, metric_comparison_operator: str, metric_evaluation_periods: int, metric_treat_missing_data: str, alarm_actions: list) -> None:
        try:
            self.delete_metric_alarm(alarm_name)
            self.create_metric_alarm(alarm_name, alarm_description, metric_name, metric_namespace, metric_statistic, metric_period, metric_threshold, metric_comparison_operator, metric_evaluation_periods, metric_treat_missing_data, alarm_actions)
        except ClientError:
            self.LOGGER.info(self.UNEXPECTED)
