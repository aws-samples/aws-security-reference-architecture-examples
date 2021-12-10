#!/usr/bin/env bash
set -e

###########################################################################################
# Purpose: This script stages the solution Lambda function zip and CloudFormation templates by:
#          1. Creating an S3 bucket to hold the deployment resources
#          2. Packaging and uploading Lambda code to the S3 bucket lambda_code folder
#          4. Uploading the CloudFormation templates to the S3 bucket templates folder
# Usage:   ~/aws-security-reference-architecture-examples/aws_sra_examples/utils/packaging_scripts/stage_solution.sh \
#           --staging_bucket_name <sra staging s3 bucket name> \
#           --solution_directory <path to the solution directory>
# Example: ~/aws-security-reference-architecture-examples/aws_sra_examples/utils/packaging_scripts/stage_solution.sh \
#          --staging_bucket_name sra-staging-123456789012-us-east-1 \
#          --solution_directory ~/aws-security-reference-architecture-examples/aws_sra_examples/solutions/cloudtrail/cloudtrail_org
###########################################################################################
# shellcheck disable=SC2086
usage="$(basename $0) [-h] [--staging_bucket_name s] <--solution_directory s> ---script stage solution Lambda code and CloudFormation templates

where:
    -h  show this help text
    --staging_bucket_name [optional] S3 Staging Bucket to upload files, example = sra-staging-123456789012-us-east-1
    --solution_directory <required> SRA Solution Directory Path, example = ~/aws-security-reference-architecture-examples/aws_sra_examples/solutions/cloudtrail/cloudtrail_org"

if [[ $1 == "-h" ]]; then
    echo "$usage"
    exit 1
fi

staging_bucket_name=${staging_bucket_name:-none}
solution_directory=${solution_directory:-none}

# read input parameters
while [ $# -gt 0 ]; do

    if [[ $1 == *"--"* ]]; then
        param="${1/--/}"
        declare "$param"="$2"
        # echo $1 $2 // Optional to see the parameter:value result
    fi

    shift
done

if [ "$solution_directory" != "none" ]; then
    ###########################################################################################
    # Configuration Parameters
    ###########################################################################################
    HERE="${PWD}"
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
    cd "$solution_directory" || exit 1          # change directory into solution directory
    SOLUTION_NAME_SNAKE_CASE=$(basename "$PWD") # get the solution name from the directory name
    SOLUTION_NAME="sra-"$(tr '_' '-' <<<"$SOLUTION_NAME_SNAKE_CASE")

    LAMBDA_S3_PREFIX="$SOLUTION_NAME/lambda_code"
    TEMPLATES_S3_PREFIX="$SOLUTION_NAME/templates"
    STAGING_BUCKET="$staging_bucket_name"
    SRA_STAGING_FOLDER_NAME="sra_staging_manual_upload"
    TMP_FOLDER_NAME="$HOME/temp_sra_lambda_src_XXXX" # will be cleaned
    ###########################################################################################
    # End Configuration Parameters
    ###########################################################################################

    # create the staging folder
    echo "...Creating the $SRA_STAGING_FOLDER_NAME folder"
    cd "$SCRIPT_DIR" || exit 1
    cd ../../../ || exit 1                        # change directory into the base folder of the sra code
    mkdir -p "$SRA_STAGING_FOLDER_NAME" || exit 1 # create staging folder, if it doesn't exist

    cd "$SRA_STAGING_FOLDER_NAME" || exit 1
    STAGING_FOLDER="${PWD}"
    mkdir -p "$TEMPLATES_S3_PREFIX" || exit 1 # create the staging templates folder
    mkdir -p "$LAMBDA_S3_PREFIX" || exit 1    # create the staging lambda folder

    STAGING_TEMPLATES_FOLDER="$STAGING_FOLDER/$TEMPLATES_S3_PREFIX" || exit 1
    STAGING_LAMBDA_FOLDER="$STAGING_FOLDER/$LAMBDA_S3_PREFIX" || exit 1

    # CloudFormation Stacks
    echo "## Stage CloudFormation Templates"
    cd "$solution_directory" || exit 1 # change directory into solution directory

    cp -r ./templates/* "$STAGING_TEMPLATES_FOLDER/" || exit 1 # copy CloudFormation templates to staging folder

    # Package and Stage Lambda Code
    echo "## Package and Stage Lambda Code"
    lambda_folder_count=0
    for dir in "$solution_directory"/lambda/*/; do
        lambda_folder_count=$((lambda_folder_count + 1))
    done
    for dir in "$solution_directory"/lambda/*/; do
        lambda_dir="${dir%"${dir##*[!/]}"}"
        lambda_dir="${lambda_dir##*/}" # remove everything before the last /

        cd "$dir" || exit 1
        has_python=$(find ./*.py 2>/dev/null | wc -l)
        has_requirements=$(find requirements.txt 2>/dev/null | wc -l)

        if [ "$has_python" -ne 0 ] && [ "$has_requirements" -ne 0 ]; then
            echo "...Creating the temporary packaging folder (tmp_sra_lambda_src_XXXX)"
            TMP_FOLDER=$(mktemp -d "$TMP_FOLDER_NAME") || exit 1 # create the temp folder
            cp -r "$dir"* "$TMP_FOLDER" || exit 1                # copy lambda source to temp source folder
            pip3 --disable-pip-version-check install -t "$TMP_FOLDER" -r "$TMP_FOLDER/requirements.txt" -q ||
                {
                    rm -rf "$TMP_FOLDER"
                    echo "---> Error: Python3 is required"
                    exit 1
                }

            cd "$LAMBDA_STAGING_FOLDER" || exit 1 # change directory into staging folder
            if [ "$lambda_folder_count" -gt "1" ]; then
                LAMBDA_ZIP_FILE="$STAGING_LAMBDA_FOLDER/$SOLUTION_NAME-$lambda_dir.zip"
            else
                LAMBDA_ZIP_FILE="$STAGING_LAMBDA_FOLDER/$SOLUTION_NAME.zip"
            fi
            rm -f "$LAMBDA_ZIP_FILE" # remove zip file, if exists

            # create zip file in the dist folder
            echo "...Creating zip file from the temp folder contents"
            cd "$TMP_FOLDER" || exit 1 # changed directory to temp folder
            zip -r -q "$LAMBDA_ZIP_FILE" . -x "*.DS_Store" -x "inline_*" ||
                7z a -tzip "$LAMBDA_ZIP_FILE" ||
                {
                    echo "---> ERROR: Zip and 7zip are not available. Manually create the zip file with the $STAGING_LAMBDA_FOLDER folder contents."
                    exit 1
                }                # zip source with packages
            cd "$HERE" || exit 1 # change directory to the original directory

            echo "...Removing Temporary Folder $TMP_FOLDER"
            rm -rf "$TMP_FOLDER"
        else
            echo "---> ERROR: Lambda folder '$lambda_dir' does not have any python files and a requirements.txt file"
        fi
    done

    if [[ "$STAGING_BUCKET" != "none" ]]; then

        # Upload CloudFormation templates to S3 Staging Bucket
        if aws s3 cp "$STAGING_TEMPLATES_FOLDER/" s3://"$STAGING_BUCKET/$TEMPLATES_S3_PREFIX/" --recursive --exclude "*" --include "*.yaml" 2>&1 | grep -q "failed"; then
            echo "---> ERROR: CloudFormation templates upload to S3 staging bucket failed"
        else
            echo "...CloudFormation templates uploaded to $STAGING_BUCKET/$SOLUTION_NAME/templates/"
        fi

        # upload the lambda zip file to S3
        if aws s3 cp "$STAGING_LAMBDA_FOLDER/" s3://"$STAGING_BUCKET/$LAMBDA_S3_PREFIX/" --recursive --exclude "*" --include "*.zip" 2>&1 | grep -q "failed"; then
            echo "---> ERROR: S3 upload failed. Manually upload the Lambda zip files from the staging folder: $STAGING_LAMBDA_FOLDER"
        else
            echo "...Uploaded Lambda zip files to $STAGING_BUCKET/$LAMBDA_S3_PREFIX/"
        fi

        cd "$STAGING_LAMBDA_FOLDER" || exit 1
        for filename in *.zip; do
            lambda_name="${filename%.zip}"

            if aws lambda get-function --function-name "$lambda_name" 2>&1 | grep -q "ResourceNotFoundException"; then
                echo "...Lambda function $lambda_name not found to update"
            else
                # update Lambda code
                if aws lambda update-function-code --function-name "$lambda_name" --s3-key "$LAMBDA_S3_PREFIX/$filename" --s3-bucket "$STAGING_BUCKET" 2>&1 | grep -q "error"; then
                    echo "---> ERROR: Lambda update failed"
                else
                    echo "...Lambda function $lambda_name updated"
                fi
            fi
        done

        cd "$HERE" || exit 1 # return to the calling directory
    fi

    if [[ "$STAGING_BUCKET" != "none" ]]; then
        echo "### SRA STAGING S3 BUCKET NAME: $STAGING_BUCKET"
    fi
    echo "### SRA STAGING UPLOADS FOLDER: $STAGING_FOLDER"
    echo "### CLOUDFORMATION TEMPLATES FOLDER: $TEMPLATES_S3_PREFIX"
    echo "### S3 LAMBDA CODE FOLDER: $LAMBDA_S3_PREFIX"
    # echo "### LAMBDA ZIP FILE: $SOLUTION_NAME.zip"
    # cd "$STAGING_LAMBDA_FOLDER" || exit 1
    # echo -e "### LAMBDA ZIP FILE SIZE:  $(du -sh)"
    cd "$HERE" || exit 1 # return to the calling directory
else
    echo "$usage"
fi

exit 0
