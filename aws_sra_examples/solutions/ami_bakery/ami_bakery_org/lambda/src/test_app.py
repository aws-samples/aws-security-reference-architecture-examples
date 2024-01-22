"""
    This script tests operations to create and delete AMI Bakery resources from app.py file.
    To run this script, you must have:
    1. A role that your current identity is able to assume.
    2. Environmental variables defined for CONFIGURATION_ROLE_NAME (the above role) and
    AMI_BAKERY_ACCOUNT_ID (the account where the role exists).
"""
from __future__ import annotations

import os
from typing import Any, Dict

from app import create, delete
from aws_lambda_typing.context import Context

event: Dict[str, Any] = {}
context: Context = Context()

params = {}

os.environ["AMI_BAKERY_ACCOUNT_ID"] = "111111111111"  # Replace the value with your account ID for testing
os.environ["CONFIGURATION_ROLE_NAME"] = "test-role"  # Replace the value with your role (preferable admin role) for testing
params["AWS_PARTITION"] = "aws"
params["AMI_BAKERY_REGION"] = "us-east-1"
params["BUCKET_NAME"] = "sra-ami-bakery-org-pipeline" + "-" + os.environ["AMI_BAKERY_ACCOUNT_ID"] + "-" + params["AMI_BAKERY_REGION"]
params["BRANCH_NAME"] = "main"
params["CODEPIPELINE_POLICY_NAME"] = "sra-ami-bakery-org-codepipeline-policy"
params["CLOUDFORMATION_POLICY_NAME"] = "sra-ami-bakery-org-cloudformation-policy"
params["CODEPIPELINE_ROLE_NAME"] = "sra-ami-bakery-org-codepipeline-role"
params["CLOUDFORMATION_ROLE_NAME"] = "sra-ami-bakery-org-cloudformation-role"
params["IMAGEBUILDER_ROLE_NAME"] = "sra-ami-bakery-org-ec2-imagebuilder-role"
params["LIFECYCLE_ROLE_NAME"] = "sra-ami-bakery-org-image-lifecycle-role"
params["FILE_NAME"] = "sra-ami-bakery-org-stig-hardened.yaml"
params["PIPELINE_NAME"] = "sra-ami-bakery-org-pipeline"
params["REPO_DESCRIPTION"] = "SRA AMI Bakery repo for storing EC2 Image Builder cloudformation template"
params["REPO_NAME"] = "sra-ami-bakery-org-repo"
params["STACK_NAME"] = "sra-ami-bakery-org-cloudformation-stack"

for param in params:
    os.environ[param] = params[param]

print("Creating Pipeline...")
create(event, context)
print("Deleting pipeline...")
delete(event, context)
