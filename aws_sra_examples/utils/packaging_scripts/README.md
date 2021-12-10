# Packaging Scripts

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

---

## package-lambda.sh

- Script to package solution Lambda code and stage it within an AWS S3 bucket
- Inputs
  - `--file_name` [required] Lambda zip file
  - `--src_dir` [required] Lambda source directory
  - `--bucket` [optional] S3 bucket name for lambda source
- Logic
  - Creates a new folder `dist-xxxx` within the calling directory to hold the Lambda zip file, if the S3 bucket is not provide or the script cannot access it
  - Creates a new temporary folder `tmp-sra-lambda-src-XXXX` within the $HOME directory to stage the files and libraries for packaging
  - Copies of the files within the provided Lambda source folder (e.g. `app.py` and `requirements.txt`) to the temporary folder `tmp-sra-lambda-src-XXXX`
  - Downloads the libraries within the `requirements.txt` file using pip3 to the temporary folder `tmp-sra-lambda-src-XXXX`
  - Creates a zip file with the contents of the temporary folder `tmp-sra-lambda-src-XXXX` and saves it to the `dist-xxxx` folder
  - Removes the temporary folder `tmp-sra-lambda-src-XXXX` after the zip file is created
  - If an AWS S3 bucket is provided, the zip file is uploaded to the S3 bucket
  - The `dist-xxxx` folder is removed, if the upload to S3 is successful

## stage_solution.sh

- Script to package solution Lambda code, stage the Lambda zip, and stage the CloudFormation templates to an AWS S3 staging bucket
- Inputs
  - `--staging_bucket_name` [required] Staging S3 bucket name
  - `--solution_directory` [required] SRA solution directory path
- Logic
  - Creates a new folder `sra_staging_manual_upload` within the code repository root directory to store all files uploaded to the S3 bucket
  - Copies the solution template files to `sra_staging_manual_upload/solution-name/templates` folder
  - Determines the number of Lambda code folders
  - For each Lambda code folder within the solution directory
    - Creates a new temporary folder `tmp-sra-lambda-src-XXXX` within the $HOME directory to stage the files and libraries for packaging
    - Copies of the files within the provided Lambda source folder (e.g. `app.py` and `requirements.txt`) to the temporary folder `tmp-sra-lambda-src-XXXX`
    - Downloads the libraries within the `requirements.txt` file using pip3 to the temporary folder `tmp-sra-lambda-src-XXXX`
    - Creates a zip file with the contents of the temporary folder `tmp-sra-lambda-src-XXXX` and saves it to the `sra_staging_manual_upload/solution-name/lambda_code` folder
    - Removes the temporary folder `tmp-sra-lambda-src-XXXX` after the zip file is created
    - If there is one Lambda code folder, the Lambda zip file name will only include the solution name (e.g. `solution-name.zip`)
    - If there is more than one Lambda code folder, each Lambda zip file name will be the solution name and the Lambda code folder (e.g. `solution-name-lambda-folder.zip`)
  - Uploads the templates and Lambda code from the `sra_staging_manual_upload/solution-name' folder to the staging S3 bucket
  - Update each Lambda function with the new code, if the Lambda function already exists within the `management account`
