"""Lambda module to setup SRA DynamoDB resources in the organization.

Version: 1.0

DynamoDb module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import logging
import os
import random
import string
from datetime import datetime
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Sequence

import boto3
from boto3.session import Session

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.client import DynamoDBClient
    from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource
    from mypy_boto3_dynamodb.type_defs import AttributeDefinitionTypeDef, KeySchemaElementTypeDef, ProvisionedThroughputTypeDef


class SRADynamoDB:
    """Class for DynamoDB functions for SRA."""

    PROFILE = "default"
    UNEXPECTED = "Unexpected!"

    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    try:
        MANAGEMENT_ACCOUNT_SESSION: Session = boto3.Session()
    except Exception as error:
        LOGGER.exception(f"Error creating boto3 session: {error}")
        raise ValueError(f"Error creating boto3 session: {error}") from None

    try:
        DYNAMODB_CLIENT: "DynamoDBClient" = MANAGEMENT_ACCOUNT_SESSION.client("dynamodb")
        DYNAMODB_RESOURCE: "DynamoDBServiceResource" = MANAGEMENT_ACCOUNT_SESSION.resource("dynamodb")
        LOGGER.info("DynamoDB resource and client created successfully.")
    except Exception as error:
        LOGGER.info(f"Error creating boto3 dymanodb resource and/or client: {error}")
        raise ValueError(f"Error creating boto3 dymanodb resource and/or client: {error}") from None

    def __init__(self, profile: str = "default") -> None:
        """Initialize class object.

        Args:
            profile (str): AWS profile name. Defaults to "default".

        Raises:
            ValueError: Unexpected error executing Lambda function. Review CloudWatch logs for details.
        """
        self.PROFILE = profile
        try:
            if self.PROFILE != "default":
                self.MANAGEMENT_ACCOUNT_SESSION = boto3.Session(profile_name=self.PROFILE)
            else:
                self.MANAGEMENT_ACCOUNT_SESSION = boto3.Session()

            self.DYNAMODB_RESOURCE = self.MANAGEMENT_ACCOUNT_SESSION.resource("dynamodb")
            self.DYNAMODB_CLIENT = self.MANAGEMENT_ACCOUNT_SESSION.client("dynamodb")
        except Exception:
            self.LOGGER.exception(self.UNEXPECTED)
            raise ValueError("Unexpected error!") from None

    def create_table(self, table_name: str) -> None:
        """Create DynamoDB table.

        Args:
            table_name (str): DynamoDB table name
        """
        # Define table schema
        key_schema: Sequence[KeySchemaElementTypeDef] = [
            {"AttributeName": "solution_name", "KeyType": "HASH"},
            {"AttributeName": "record_id", "KeyType": "RANGE"},
        ]  # Hash key  # Range key
        attribute_definitions: Sequence[AttributeDefinitionTypeDef] = [
            {"AttributeName": "solution_name", "AttributeType": "S"},  # String type
            {"AttributeName": "record_id", "AttributeType": "S"},  # String type
        ]
        provisioned_throughput: ProvisionedThroughputTypeDef = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}

        # Create table
        try:
            self.DYNAMODB_CLIENT.create_table(
                TableName=table_name, KeySchema=key_schema, AttributeDefinitions=attribute_definitions, ProvisionedThroughput=provisioned_throughput
            )
            self.LOGGER.info(f"{table_name} dynamodb table created successfully.")
        except Exception as e:
            self.LOGGER.info("Error creating table:", e)
        # wait for the table to become active
        while True:
            wait_response = self.DYNAMODB_CLIENT.describe_table(TableName=table_name)
            if wait_response["Table"]["TableStatus"] == "ACTIVE":
                self.LOGGER.info(f"{table_name} dynamodb table is active")
                break
            else:
                self.LOGGER.info(f"{table_name} dynamodb table is not active yet. Status is '{wait_response['Table']['TableStatus']}'  Waiting...")
                # TODO(liamschn): need to add a maximum retry mechanism here
                sleep(5)

    def table_exists(self, table_name: str) -> bool:
        """Check if DynamoDB table exists.

        Args:
            table_name (str): DynamoDB table name

        Returns:
            bool: True if table exists, False if not
        """
        # Check if table exists
        try:
            self.DYNAMODB_CLIENT.describe_table(TableName=table_name)
            self.LOGGER.info(f"{table_name} dynamodb table  already exists...")
            return True
        except self.DYNAMODB_CLIENT.exceptions.ResourceNotFoundException:
            self.LOGGER.info(f"{table_name} dynamodb table  does not exist...")
            return False

    def generate_id(self) -> str:
        """Generate a random string of 8 characters.

        Args:
            None

        Returns:
            str: random string of 8 characters
        """
        return str("".join(random.choice(string.ascii_letters + string.digits + "-_") for ch in range(8)))  # noqa: S311, DUO102

    def get_date_time(self) -> str:
        """Get current date and time.

        Args:
            None

        Returns:
            str: current date and time in format YYYYMMDDHHMMSS
        """
        now = datetime.now()
        return now.strftime("%Y%m%d%H%M%S")

    def insert_item(self, table_name: str, solution_name: str) -> tuple[str, str]:
        """Insert an item into the dynamodb table.

        Args:
            table_name: dynamodb table name
            solution_name: solution name

        Returns:
            record_id: record id
            date_time: date time
        """
        self.LOGGER.info(f"Inserting {solution_name} into {table_name} dynamodb table")
        table = self.DYNAMODB_RESOURCE.Table(table_name)
        record_id = self.generate_id()
        date_time = self.get_date_time()
        table.put_item(
            Item={
                "solution_name": solution_name,
                "record_id": record_id,
                "date_time": date_time,
            }
        )
        return record_id, date_time

    def update_item(self, table_name: str, solution_name: str, record_id: str, attributes_and_values: dict) -> Any:
        """Update an item in the dynamodb table.

        Args:
            table_name: dynamodb table name
            solution_name: solution name
            record_id: record id
            attributes_and_values: attributes and values to update

        Returns:
            dynamodb response
        """
        self.LOGGER.info(f"Updating {table_name} dynamodb table with {attributes_and_values}")
        table = self.DYNAMODB_RESOURCE.Table(table_name)
        update_expression = ""
        expression_attribute_values = {}
        for attribute in attributes_and_values:
            if update_expression == "":
                update_expression = "set " + attribute + "=:" + attribute
            else:
                update_expression = update_expression + ", " + attribute + "=:" + attribute
            expression_attribute_values[":" + attribute] = attributes_and_values[attribute]
        return table.update_item(
            Key={
                "solution_name": solution_name,
                "record_id": record_id,
            },
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW",
        )

    def find_item(self, table_name: str, solution_name: str, additional_attributes: dict) -> tuple[bool, dict]:
        """Find an item in the dynamodb table based on the solution name and additional attributes.

        Args:
            table_name: dynamodb table name
            solution_name: solution name
            additional_attributes: additional attributes to search for

        Returns:
            True and the item if found, otherwise False and empty dict
        """
        self.LOGGER.info(f"Searching for {additional_attributes} in {table_name} dynamodb table")
        table = self.DYNAMODB_RESOURCE.Table(table_name)
        expression_attribute_values = {":solution_name": solution_name}

        filter_expression = " AND ".join([f"{attr} = :{attr}" for attr in additional_attributes.keys()])

        expression_attribute_values.update({f":{attr}": value for attr, value in additional_attributes.items()})

        query_params: Dict[str, Any] = {}

        query_params = {
            "KeyConditionExpression": "solution_name = :solution_name",
            "ExpressionAttributeValues": expression_attribute_values,
            "FilterExpression": filter_expression,
        }

        response = table.query(**query_params)

        if len(response["Items"]) > 1:
            self.LOGGER.info(
                f"Found more than one record that matched solution name {solution_name}: {additional_attributes}."
                + f"Review {table_name} dynamodb table to determine cause."
            )
        elif len(response["Items"]) < 1:
            return False, {}
        self.LOGGER.info(f"Found record id {response['Items'][0]}")
        return True, response["Items"][0]

    def get_unique_values_from_list(self, list_of_values: list) -> list:
        """Get unique values from a list.

        Args:
            list_of_values: list of values

        Returns:
            list of unique values
        """
        self.LOGGER.info(f"Getting unique values from {list_of_values}")
        unique_values = []
        for value in list_of_values:
            if value not in unique_values:
                unique_values.append(value)
        return unique_values

    def get_distinct_solutions_and_accounts(self, table_name: str) -> tuple[list, list]:
        """Get distinct solutions and accounts from the dynamodb table.

        Args:
            table_name: dynamodb table name

        Returns:
            list of distinct solutions and accounts
        """
        self.LOGGER.info(f"Getting distinct solutions and accounts from {table_name} dynamodb table")
        table = self.DYNAMODB_RESOURCE.Table(table_name)
        response = table.scan()
        solution_names = [item["solution_name"] for item in response["Items"]]
        solution_names = self.get_unique_values_from_list(solution_names)
        accounts = [item["account"] for item in response["Items"]]
        accounts = self.get_unique_values_from_list(accounts)
        return solution_names, accounts

    def get_resources_for_solutions_by_account(self, table_name: str, solutions: list, account: str) -> dict:
        """Get resources for solutions by account from the dynamodb table.

        Args:
            table_name: dynamodb table name
            solutions: list of solutions
            account: account id

        Returns:
            dict of resources for solutions by account
        """
        self.LOGGER.info(f"Getting resources for solutions by account from {table_name} dynamodb table")
        table = self.DYNAMODB_RESOURCE.Table(table_name)
        query_results = {}
        for solution in solutions:
            query_params: Dict[str, Any] = {
                "KeyConditionExpression": "solution_name = :solution_name",
                "ExpressionAttributeValues": {":solution_name": solution, ":account": account},
                "FilterExpression": "account = :account",
            }
            response = table.query(**query_params)
            self.LOGGER.info(f"response: {response}")
            query_results[solution] = response
        return query_results

    def delete_item(self, table_name: str, solution_name: str, record_id: str) -> Any:
        """Delete an item from the dynamodb table.

        Args:
            table_name (str): dynamodb table name
            solution_name (str): solution name
            record_id (str): record id

        Returns:
            response from dynamodb delete_item
        """
        self.LOGGER.info(f"Deleting {record_id} from {table_name} dynamodb table")
        table = self.DYNAMODB_RESOURCE.Table(table_name)
        return table.delete_item(Key={"solution_name": solution_name, "record_id": record_id})
