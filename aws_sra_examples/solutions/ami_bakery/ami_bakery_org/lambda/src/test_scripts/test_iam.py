"""
    This script tests creation and deletion of IAM roles/policies from iam.py file
"""
import json

import boto3
from iam import attach_policy, create_policy, create_role, delete_policy, delete_role, detach_policy

account_id = "111111111111"  # Replace the value with your account ID for testing
region = "us-east-1"
account_ph = "ACCOUNT_ID"
region_ph = "REGION"
bucket_ph = "BUCKET_NAME"
repo_ph = "REPO_NAME"
stack_ph = "STACK_NAME"
bucket_name = "sra-ami-bakery-org-pipeline-" + account_id
repo_name = "sra-ami-bakery-org-repo"
stack_name = "sra-ami-bakery-org-cloudformation-stack"
cfn_role_ph = "CLOUDFORMATION_ROLE_NAME"
imagebuilder_role_ph = "IMAGEBUILDER_ROLE_NAME"
lifecycle_role_ph = "LIFECYCLE_ROLE_NAME"
cp_role_name = "sra-ami-bakery-org-codepipeline-role"
cfn_role_name = "sra-ami-bakery-org-cloudformation-role"
imagebuilder_role_name = "sra-ami-bakery-org-ec2-imagebuilder-role"
lifecycle_role_name = "sra-ami-bakery-org-image-lifecycle-role"
cp_policy_name = "sra-ami-bakery-org-codepipeline-policy"
cfn_policy_name = "sra-ami-bakery-org-cloudformation-policy"
cp_policy_arn = "arn:aws:iam::" + account_id + ":policy/" + cp_policy_name
cfn_policy_arn = "arn:aws:iam::" + account_id + ":policy/" + cfn_policy_name
session = boto3.session.Session()

print("Create Codepipeline role...")
with open("cp_trust_relationship.json", "r") as codepipeline_trust_file:
    cp_trust_policy = json.load(codepipeline_trust_file)
create_role(session, cp_role_name, cp_trust_policy)

print("Create CloudFormation role...")
with open("cfn_trust_relationship.json", "r") as cloudformation_trust_file:
    cfn_trust_policy = json.load(cloudformation_trust_file)
create_role(session, cfn_role_name, cfn_trust_policy)

print("Create CodePipeline policy...")
with open("codepipeline_policy.json", "r") as codepipeline_policy_file:
    cp_policy_document = json.load(codepipeline_policy_file)
cp_policy = (
    json.dumps(cp_policy_document)
    .replace(account_ph, account_id)
    .replace(bucket_ph, bucket_name)
    .replace(region_ph, region)
    .replace(repo_ph, repo_name)
    .replace(cfn_role_ph, cfn_role_name)
    .replace(stack_ph, stack_name)
)
create_policy(session, cp_policy_name, cp_policy)

print("Create CloudFormation policy...")
with open("cloudformation_policy.json", "r") as cloudformation_policy_file:
    cfn_policy_document = json.load(cloudformation_policy_file)
cfn_policy = (
    json.dumps(cfn_policy_document)
    .replace(account_ph, account_id)
    .replace(region_ph, region)
    .replace(imagebuilder_role_ph, imagebuilder_role_name)
    .replace(lifecycle_role_ph, lifecycle_role_name)
)
create_policy(session, cfn_policy_name, cfn_policy)

print("Attach CodePipeline Policy...")
attach_policy(session, cp_role_name, cp_policy_name, cp_policy)
print("Attach CloudFormation Policy...")
attach_policy(session, cfn_role_name, cfn_policy_name, cfn_policy)

print("Detach CodePipeline policy...")
detach_policy(session, cp_role_name, cp_policy_name)
print("Detach CloudFormation policy...")
detach_policy(session, cfn_role_name, cfn_policy_name)

print("Delete CodePipeline Policy")
delete_policy(session, cp_policy_arn)
print("Delete CloudFormation Policy")
delete_policy(session, cfn_policy_arn)

print("Delete CodePipeline role...")
delete_role(session, cp_role_name)
print("Delete CloudFormation role...")
delete_role(session, cfn_role_name)
