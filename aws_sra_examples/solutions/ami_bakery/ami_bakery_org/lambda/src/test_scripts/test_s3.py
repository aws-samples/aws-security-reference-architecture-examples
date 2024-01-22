"""
    This script tests creation and deletion of S3 resource from s3.py file
"""

import json

import boto3
from s3 import add_bucket_policy, create_s3_bucket, delete_objects_from_s3, delete_s3_bucket, delete_s3_bucket_policy, enable_bucket_versioning

account_id = "111111111111"  # Replace the value with your account ID for testing
region = "us-east-1"
b_place_holder = "BUCKET_NAME"
bucket_name = "sra-ami-bakery-org-pipeline-" + account_id + "-" + region
file_name = "sra-ami-bakery-org-stig-hardened.yaml"

with open("s3_bucket_policy.json", "r") as bucket_policy_file:
    bucket_policy_document = json.load(bucket_policy_file)
s3_policy = json.dumps(bucket_policy_document).replace(b_place_holder, bucket_name)

session = boto3.session.Session()


print("Create s3 bucket: ")
create_s3_bucket(session, bucket_name, region)

print("Enable bucket versioning")
enable_bucket_versioning(session, bucket_name)

print("Put a policy to a bucket")
add_bucket_policy(session, bucket_name, s3_policy)

print("Delete objects")
delete_objects_from_s3(session, bucket_name)

print("Delete bucket policy")
delete_s3_bucket_policy(session, bucket_name)

print("Delete Bucket")
delete_s3_bucket(session, bucket_name)
