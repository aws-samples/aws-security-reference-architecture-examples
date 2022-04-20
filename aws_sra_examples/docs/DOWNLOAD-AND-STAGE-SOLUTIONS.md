# Download and Stage the AWS SRA Solutions<!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

---

## Steps<!-- omit in toc -->

1. [Install the prerequisites](#install-the-prerequisites).
2. [Download the SRA examples code from GitHub](#download-the-sra-examples-code-from-github).

   ```bash
   git clone https://github.com/aws-samples/aws-security-reference-architecture-examples.git $HOME/aws-sra-examples
   cd $HOME/aws-sra-examples
   ```

3. [Authenticate to the AWS management account](#authenticate-to-the-aws-management-account).
4. In the `management account (home region)`, launch an AWS CloudFormation **Stack** using the [sra-common-prerequisites-staging-s3-bucket.yaml](../solutions/common/common_prerequisites/templates/sra-common-prerequisites-staging-s3-bucket.yaml)
   template file as the source.

   ```bash
   aws cloudformation deploy --template-file $HOME/aws-sra-examples/aws_sra_examples/solutions/common/common_prerequisites/templates/sra-common-prerequisites-staging-s3-bucket.yaml --stack-name sra-common-prerequisites-staging-s3-bucket --capabilities CAPABILITY_NAMED_IAM
   ```

5. Package and stage all the AWS SRA example solutions. For more information see [Staging script details](#staging-script-details).
   <!-- markdownlint-disable-next-line MD031 -->

   ```bash
   # Package and stage the SRA solutions with current or default AWS CLI profile
   sh $HOME/aws-sra-examples/aws_sra_examples/utils/packaging_scripts/stage_solution.sh
   ```

   ```bash
   # Package and stage the SRA solutions with AWS CLI profile
   sh $HOME/aws-sra-examples/aws_sra_examples/utils/packaging_scripts/stage_solution.sh --profile <AWS_MANAGEMENT_ACCOUNT_PROFILE>
   ```

6. Return to the [Common Prerequisites Solution Deployment](../solutions/common/common_prerequisites#solution-deployment)

## Install the prerequisites<!-- omit in toc -->

1. Configure [AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-with-control-tower.html) within a new or existing AWS account (management account).
2. Install and setup [git](https://git-scm.com/downloads) following the [GitHub setup instructions](https://docs.github.com/en/get-started/quickstart/set-up-git).
3. Install the latest version of [AWS Command Line Interface (AWS CLI)](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html). Validate via `aws --version`.
   1. Install/Update following the [installation instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
   2. Setup the `AWS management account` profile via `aws configure --profile sra-management`. See
      [Quick configuration with aws configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-config).
4. For Windows OS, Install [7-Zip](https://www.7-zip.org/)

## Download the SRA examples code from GitHub<!-- omit in toc -->

Clone the AWS SRA GitHub repository to your local machine `$HOME/aws-sra-examples` directory

```bash
git clone https://github.com/aws-samples/aws-security-reference-architecture-examples.git $HOME/aws-sra-examples
cd $HOME/aws-sra-examples
```

- If you get the following error, `fatal: destination path '/Users/<user>/aws-sra-examples' already exists and is not an empty directory.`

  - Option 1 - Pull the latest updated files from GitHub into the existing `$HOME/aws-sra-examples` directory

    ```bash
    cd $HOME/aws-sra-examples
    git pull
    ```

  - Option 2 - Remove the existing directory and clone the GitHub repository into the `$HOME/aws-sra-examples` directory

    ```bash
    cd $HOME && rm -rf aws-sra-examples
    git clone https://github.com/aws-samples/aws-security-reference-architecture-examples.git $HOME/aws-sra-examples
    cd $HOME/aws-sra-examples
    ```

## Authenticate to the AWS management account<!-- omit in toc -->

See [IAM permissions required for staging solutions](#iam-permissions-required-for-staging-solutions), if you are [creating an IAM role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html#roles-creatingrole-user-console).

### Export an existing AWS CLI profile<!-- omit in toc -->

```bash
export AWS_PROFILE=sra-management
```

### Assume a management account IAM role and export the credentials<!-- omit in toc -->

```bash
# An existing AWS CLI session is required.
# Depends on the jq library. Install with `brew install jq`.
export ROLE_ARN_TO_ASSUME=arn:aws:iam::<aws_account_number>:role/<role_name>
export ROLE_SESSION_NAME=sra-management-session
TEMP_ROLE=$(aws sts assume-role \
                    --role-arn "$ROLE_ARN_TO_ASSUME" \
                    --role-session-name "$ROLE_SESSION_NAME") \
export AWS_ACCESS_KEY_ID=$(echo $TEMP_ROLE | jq -r .Credentials.AccessKeyId) \
export AWS_SECRET_ACCESS_KEY=$(echo $TEMP_ROLE | jq -r .Credentials.SecretAccessKey) \
export AWS_SESSION_TOKEN=$(echo $TEMP_ROLE | jq -r .Credentials.SessionToken)
```

### [Configuring a named profile to use AWS SSO](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html#sso-configure-profile)

---

## IAM permissions required for staging solutions<!-- omit in toc -->

- Summary
  - Lambda (Restricted to functions starting with `sra-*`)
    - lambda:GetFunction
    - lambda:UpdateFunctionCode
  - S3 (Restricted to buckets starting with `sra-staging-<ACCOUNT_ID>-*`)
    - s3:GetBucketAcl
    - s3:GetObject
    - s3:PutObject
  - SSM (Restricted to the `sra/staging-s3-bucket-name` parameter)
    - ssm:GetParameter
- Example IAM Policy. Replace <ACCOUNT_ID> with the deployment account ID (e.g. Management Account ID).

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "LambdaAccess",
        "Effect": "Allow",
        "Action": ["lambda:GetFunction", "lambda:UpdateFunctionCode"],
        "Resource": "arn:aws:lambda:*:<ACCOUNT_ID>:function:sra-*"
      },
      {
        "Sid": "S3Access",
        "Effect": "Allow",
        "Action": ["s3:GetBucketAcl", "s3:GetObject", "s3:PutObject"],
        "Resource": ["arn:aws:s3:::sra-staging-<ACCOUNT_ID>-*", "arn:aws:s3:::sra-staging-<ACCOUNT_ID>-*/*"]
      },
      {
        "Sid": "SSMAccess",
        "Effect": "Allow",
        "Action": "ssm:GetParameter",
        "Resource": "arn:aws:ssm:*:<ACCOUNT_ID>:parameter/sra/staging-s3-bucket-name"
      }
    ]
  }
  ```

---

## Staging script details<!-- omit in toc -->

The AWS SRA staging script is written in bash using AWS CLI and it works in Linux, OSX, and Windows (using git-bash). The script packages all AWS SRA example solutions Lambda code, stages the Lambda zip files, and stages the CloudFormation templates
to an AWS S3 staging bucket.

### Script logic<!-- omit in toc -->

1. Get the S3 staging bucket name from the SSM parameter `/sra/staging-s3-bucket-name` value.
2. Create a new folder `sra_staging_manual_upload` within the code repository root directory to store all files uploaded to the S3 bucket.
3. For each solution within the `$HOME/aws-sra-examples/aws_sra_examples/solutions` directory
   1. Copy the solution template files to `sra_staging_manual_upload/solution-name/templates` folder.
   2. Determine the number of Lambda code folders for zip file naming.
   3. For each Lambda code folder within the solution directory.
      1. Create a new temporary folder `tmp-sra-lambda-src-XXXX` within the $HOME directory to stage the files and libraries for packaging.
      2. Copy of the files within the provided Lambda source folder (e.g. `app.py` and `requirements.txt`) to the temporary folder `tmp-sra-lambda-src-XXXX`.
      3. Download the libraries within the `requirements.txt` file using pip3 to the temporary folder `tmp-sra-lambda-src-XXXX`.
      4. Create a zip file with the contents of the temporary folder `tmp-sra-lambda-src-XXXX` and saves it to the `sra_staging_manual_upload/solution-name/lambda_code` folder.
         - If there is one Lambda code folder, the Lambda zip file name will only include the solution name (e.g. `solution-name.zip`).
         - If there is more than one Lambda code folder, each Lambda zip file name will be the solution name and the Lambda code folder with dashes (e.g. `solution-name-<lambda-folder>.zip`).
      5. Remove the temporary folder `tmp-sra-lambda-src-XXXX` after the zip file is created.
   4. Upload the templates and Lambda code from the `sra_staging_manual_upload/solution-name' folder to the S3 staging bucket.
   5. If the Lambda functions already exist within the `management account`, update each one with the code from the S3 staging bucket.

### Optional script parameters<!-- omit in toc -->

- `--profile <aws-cli-profile>`
  - AWS CLI profile to use when staging the solutions.
- `--staging_bucket_name <staging-s3-bucket-name>`
  - AWS S3 Staging Bucket to upload files used by the solution deployments.
  - Example = sra-staging-123456789012-us-east-1
  - Logic
    - The provided S3 staging bucket name is used for staging files instead of the SSM.parameter `/sra/staging-s3-bucket-name`.
- `--solution_directory <solution_directory_absolute_path>`
  - SRA solution directory absolute path
  - Example = $HOME/aws-sra-examples/aws_sra_examples/solutions/cloudtrail/cloudtrail_org"
  - Logic
    - All solutions within the [common directory](../solutions/common) are packaged, staged, and uploaded to the S3 staging bucket for reuse with other solutions.
    - The provided solution is packaged, staged, and uploaded to the S3 staging bucket.
