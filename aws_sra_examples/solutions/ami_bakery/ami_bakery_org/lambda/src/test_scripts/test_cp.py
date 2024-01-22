"""
    This script test creation and deletion of CodeCommit and CodePipeline resources from codepipeline.py
"""

import boto3
from codepipeline import add_file_to_repo, create_codepipeline, create_repo, delete_codepipeline, delete_repo

session = boto3.session.Session()
account_id = "111111111111"  # Replace the value with your account ID for testing
repo_name = "sra-ami-bakery-org-repo"
description = "SRA AMI Bakery repo for storing EC2 Image Builder cloudformation template"
branch_name = "main"
params = {}
params["AWS_PARTITION"] = "aws"
params["AMI_BAKERY_ACCOUNT_ID"] = "111111111111"  # Replace the value with your account ID for testing
params["CLOUDFORMATION_ROLE_NAME"] = "sra-ami-bakery-org-cloudformation-role"
params["CODEPIPELINE_ROLE_NAME"] = "sra-ami-bakery-org-codepipeline-role"
bucket_name = "sra-ami-bakery-org-pipeline-" + params["AMI_BAKERY_ACCOUNT_ID"]
file_name = "sra-ami-bakery-org-stig-hardened.yaml"
pipeline_name = "sra-ami-bakery-org-pipeline"
stack_name = "sra-ami-bakery-org-cloudformation-stack"
cp_role_arn = "arn:aws:cp_role_arn = iam::" + account_id + ":policy/" + params["CODEPIPELINE_ROLE_NAME"]


print("Create Repo...")
create_repo(session, repo_name, description)
print("Add file to repo...")
add_file_to_repo(session, repo_name, branch_name, file_name)
print("Creating Codepipeline...")
create_codepipeline(session, bucket_name, file_name, pipeline_name, repo_name, stack_name, params)


print("Delete repository...")
delete_repo(session, repo_name)
print("Delete CodePipeline...")
delete_codepipeline(session, pipeline_name)
