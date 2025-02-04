"""Amazon CFNResponse Module."""
# mypy: ignore-errors
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from __future__ import print_function

import json

import urllib3

SUCCESS = "SUCCESS"
FAILED = "FAILED"

http = urllib3.PoolManager()


def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False, reason=None):  # noqa: N803, D103
    responseUrl = event["ResponseURL"]  # noqa: N806

    print(responseUrl)  # noqa: T201

    responseBody = {  # noqa: N806
        "Status": responseStatus,
        "Reason": reason or "See the details in CloudWatch Log Stream: {}".format(context.log_stream_name),  # noqa: FS002
        "PhysicalResourceId": physicalResourceId or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": noEcho,
        "Data": responseData,
    }

    json_responseBody = json.dumps(responseBody)  # noqa: N806

    print("Response body:")  # noqa: T201
    print(json_responseBody)  # noqa: T201

    headers = {"content-type": "", "content-length": str(len(json_responseBody))}

    try:
        response = http.request("PUT", responseUrl, headers=headers, body=json_responseBody)
        print("Status code:", response.status)  # noqa: T201

    except Exception as e:
        print("send(..) failed executing http.request(..):", e)  # noqa: T201
