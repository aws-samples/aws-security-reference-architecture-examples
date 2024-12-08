import logging
import os
from typing import Any

import boto3
import botocore
from botocore.config import Config
import botocore.exceptions

class sra_sts:
    PROFILE = "default"

    UNEXPECTED = "Unexpected!"
    # TODO(liamschn): this needs to be made into an SSM parameter
    CONFIGURATION_ROLE: str = ""
    BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
    PARTITION: str = ""
    HOME_REGION: str = ""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    def __init__(self, profile: str="default") -> None:
        self.PROFILE = profile
        print(f"STS PROFILE INFO: {self.PROFILE}")

        try:
            if self.PROFILE != "default":
                self.MANAGEMENT_ACCOUNT_SESSION = boto3.Session(profile_name=self.PROFILE)
                print(f"STS INFO: {self.MANAGEMENT_ACCOUNT_SESSION.client('sts').get_caller_identity()}")
            else:
                print(f"STS PROFILE AGAIN: {self.PROFILE}")
                self.MANAGEMENT_ACCOUNT_SESSION = boto3.Session()

            self.STS_CLIENT = self.MANAGEMENT_ACCOUNT_SESSION.client("sts")
            self.HOME_REGION = self.MANAGEMENT_ACCOUNT_SESSION.region_name
            self.LOGGER.info(f"STS detected home region: {self.HOME_REGION}")
            self.PARTITION = self.MANAGEMENT_ACCOUNT_SESSION.get_partition_for_region(self.HOME_REGION)
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "ExpiredToken":
                self.LOGGER.info("Token has expired, please re-run with proper credentials set.")
                self.MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
                self.STS_CLIENT = self.MANAGEMENT_ACCOUNT_SESSION.client("sts")
                self.HOME_REGION = self.MANAGEMENT_ACCOUNT_SESSION.region_name
                self.PARTITION = self.MANAGEMENT_ACCOUNT_SESSION.get_partition_for_region(self.HOME_REGION)

            else:
                self.LOGGER.info(f"Error: {error}")
                raise error

        try:
            self.MANAGEMENT_ACCOUNT = self.STS_CLIENT.get_caller_identity().get("Account")
        except botocore.exceptions.NoCredentialsError:
            self.LOGGER.info("No credentials found, please re-run with proper credentials set.")
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "ExpiredToken":
                self.LOGGER.info("Token has expired, please re-run with proper credentials set.")
            else:
                self.LOGGER.info(f"Error: {error}")
                raise error

    def assume_role(self, account: str, role_name: str, service: str, region_name: str) -> Any:
        """Get boto3 client assumed into an account for a specified service.

        Args:
            account: aws account id
            service: aws service
            region_name: aws region

        Returns:
            client: boto3 client
        """
        self.LOGGER.info(f"ASSUME ROLE CALLER ID INFO: {self.MANAGEMENT_ACCOUNT_SESSION.client('sts').get_caller_identity()}")
        self.LOGGER.info(f"ASSUME ROLE ACCOUNT (CLIENT): {account}; ROLE NAME: {role_name}; SERVICE: {service}; REGION: {region_name}")
        client = self.MANAGEMENT_ACCOUNT_SESSION.client("sts")
        if account != self.MANAGEMENT_ACCOUNT:
            sts_response = client.assume_role(
                RoleArn="arn:" + self.PARTITION + ":iam::" + account + ":role/" + role_name,
                RoleSessionName="SRA-AssumeCrossAccountRole",
                DurationSeconds=900,
            )
            assumed_client = self.MANAGEMENT_ACCOUNT_SESSION.client(
                service, # type: ignore
                region_name=region_name,
                aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                aws_session_token=sts_response["Credentials"]["SessionToken"],
            )
            return assumed_client
        else:
            assumed_client = self.MANAGEMENT_ACCOUNT_SESSION.client(
                service, # type: ignore
                region_name=region_name, 
                config=self.BOTO3_CONFIG)
            return assumed_client


    def assume_role_resource(self, account: str, role_name: str, service: str, region_name: str) -> Any:
        """Get boto3 resource assumed into an account for a specified service.

        Args:
            account: aws account id
            service: aws service
            region_name: aws region

        Returns:
            client: boto3 client
        """
        self.LOGGER.info(f"ASSUME ROLE CALLER ID INFO: {self.MANAGEMENT_ACCOUNT_SESSION.client('sts').get_caller_identity()}")
        self.LOGGER.info(f"ASSUME ROLE ACCOUNT (RESOURCE): {account}; ROLE NAME: {role_name}; SERVICE: {service}; REGION: {region_name}")
        client = self.MANAGEMENT_ACCOUNT_SESSION.client("sts")
        sts_response = client.assume_role(
            RoleArn="arn:" + self.PARTITION + ":iam::" + account + ":role/" + role_name,
            RoleSessionName="SRA-AssumeCrossAccountRole",
            DurationSeconds=900,
        )
        assumed_resource = self.MANAGEMENT_ACCOUNT_SESSION.resource(
            service, # type: ignore
            region_name=region_name,
            aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
            aws_session_token=sts_response["Credentials"]["SessionToken"],
        )
        return assumed_resource

    def get_lambda_execution_role(self) -> str:
        try:
            response = self.STS_CLIENT.get_caller_identity()
            return response["Arn"]
        except Exception:
            self.LOGGER.exception(self.UNEXPECTED)
            raise ValueError("Unexpected error getting caller identity.") from None
