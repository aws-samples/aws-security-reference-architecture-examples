#!/usr/bin/env bash
set -e

###########################################################################################
# Purpose: This script stages the solution Lambda function zip and CloudFormation templates by:
#          1. Creating a staging S3 bucket to hold the deployment resources.
#          2. Packaging and uploading each common solution to the S3 staging bucket for other solution reuse.
#          3. Packaging and uploading Lambda code to the S3 staging bucket lambda_code folder.
#          4. Uploading the CloudFormation templates to the S3 staging bucket templates folder.
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

check_caller() {
    {
        CALLER_ARN=$(aws sts get-caller-identity --output text --query "Arn" 2>&1) &&
            echo "---> ERROR: You might be logged into the wrong AWS account. Authenticated to $CALLER_ARN. Manually upload the files from the staging folder $STAGING_FOLDER"
    } || {
        echo "---> ERROR: Not Authenticated to an AWS account. The script is not able to upload the staging files to S3. Manually upload the files from the staging folder $STAGING_FOLDER"
    }
}

create_configuration_parameters() {
    # Function to create configuration parameters
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
}

create_solution_staging_folder() {
    cd "$SRA_STAGING_FOLDER_DIR" || exit 1
    STAGING_FOLDER="${PWD}"
    mkdir -p "$1" || exit 1 # create the staging templates folder
    mkdir -p "$2" || exit 1 # create the staging lambda folder
}

create_staging_folder() {
    # Function to create the staging folder
    echo "...Creating the $SRA_STAGING_FOLDER_NAME folder"
    cd "$SCRIPT_DIR" || exit 1
    cd ../../../ || exit 1                        # change directory into the base folder of the sra code
    mkdir -p "$SRA_STAGING_FOLDER_NAME" || exit 1 # create staging folder, if it doesn't exist
    SRA_STAGING_FOLDER_DIR="${PWD}/$SRA_STAGING_FOLDER_NAME"
}

stage_cloudformation_templates() {
    # Function to Stage CloudFormation templates
    echo "## Stage CloudFormation Templates"
    cd "$1" || exit 1 # change directory into solution directory

    cp -r ./templates/* "$2/" || exit 1 # copy CloudFormation templates to staging folder
}

package_and_stage_lambda_code() {
    # Function to package and stage Lambda code
    echo "## Package and Stage Lambda Code"
    lambda_folder_count=0
    for dir in "$1"/lambda/*/; do
        lambda_folder_count=$((lambda_folder_count + 1))
    done
    for dir in "$1"/lambda/*/; do
        lambda_dir="${dir%"${dir##*[!/]}"}" # remove the trailing /
        lambda_dir="${lambda_dir##*/}"      # remove everything before the last /
        lambda_dir="${lambda_dir//_/-}"     # replace all underscores with dashes

        cd "$dir" || exit 1
        has_python=$(find ./*.py 2>/dev/null | wc -l)
        has_requirements=$(find requirements.txt 2>/dev/null | wc -l)

        if [ "$has_python" -ne 0 ] && [ "$has_requirements" -ne 0 ]; then
            echo "...Creating the temporary packaging folder (tmp_sra_lambda_src_XXXX)"
            tmp_folder=$(mktemp -d "$TMP_FOLDER_NAME") || exit 1 # create the temp folder
            cp -r "$dir"* "$tmp_folder" || exit 1                # copy lambda source to temp source folder
            pip3 --disable-pip-version-check install -t "$tmp_folder" -r "$tmp_folder/requirements.txt" -q ||
                {
                    rm -rf "$tmp_folder"
                    echo "---> Error: Python3 is required"
                    exit 1
                }

            cd "$2" || exit 1 # change directory into staging folder
            if [ "$lambda_folder_count" -gt "1" ]; then
                lambda_zip_file="$2/$3-$lambda_dir.zip"
            else
                lambda_zip_file="$2/$3.zip"
            fi
            rm -f "$lambda_zip_file" # remove zip file, if exists

            # create zip file in the dist folder
            echo "...Creating zip file from the temp folder contents"
            cd "$tmp_folder" || exit 1 # changed directory to temp folder
            zip -r -q "$lambda_zip_file" . -x "*.DS_Store" -x "inline_*" ||
                7z a -tzip "$lambda_zip_file" ||
                {
                    echo "---> ERROR: Zip and 7zip are not available. Manually create the zip file with the $2 folder contents."
                    exit 1
                }                # zip source with packages
            cd "$HERE" || exit 1 # change directory to the original directory

            echo "...Removing Temporary Folder $tmp_folder"
            rm -rf "$tmp_folder"
        else
            echo "---> ERROR: Lambda folder '$lambda_dir' does not have any python files and a requirements.txt file"
        fi
    done
}

upload_cloudformation_templates() {
    # Function to upload CloudFormation templates to the S3 staging bucket
    {     # try
        { # shellcheck disable=SC2034
            templates_copy_result=$(aws s3 cp "$1/" s3://"$STAGING_BUCKET/$2/" --recursive --exclude "*" --include "*.yaml" 2>&1)
        } && {
            echo "...CloudFormation templates uploaded to $STAGING_BUCKET/$2/"
        }
    } || { # catch
        echo "---> ERROR: CloudFormation templates upload to S3 staging bucket failed. Manually upload the template files from the staging folder: $1"
    }
}

upload_lambda_code() {
    # Function to upload the lambda zip files to S3
    {     # try
        { # shellcheck disable=SC2034
            lambda_copy_result=$(aws s3 cp "$1/" s3://"$STAGING_BUCKET/$2/" --recursive --exclude "*" --include "*.zip" 2>&1)
        } && {
            echo "...Lambda zip files uploaded to $STAGING_BUCKET/$2/"
        }
    } || { # catch
        echo "---> ERROR: Lambda zip files upload to S3 staging bucket failed. Manually upload the Lambda zip files from the staging folder: $1"
    }
}

update_lambda_functions() {
    # Function to update existing Lambda functions with latest code
    for filename in *.zip; do
        lambda_name="${filename%.zip}"

        {     # try
            { # shellcheck disable=SC2034
                lambda_check_result=$(aws lambda get-function --function-name "$lambda_name" 2>&1)
            } && {
                # Update Lambda code
                { # try
                    # shellcheck disable=SC2034
                    lambda_update_result=$(aws lambda update-function-code --function-name "$lambda_name" --s3-key "$1/$filename" --s3-bucket "$STAGING_BUCKET" 2>&1) &&
                        echo "...Lambda function $lambda_name updated"
                } || { # catch
                    echo "---> ERROR: Lambda function $lambda_name update failed"
                }
            }
        } || { # catch
            echo "...Lambda function $lambda_name not found to update"
        }
    done
}

package_and_stage_common_solutions() {
    # Function to package and stage all the common solutions
    cd "$SCRIPT_DIR" || exit 1
    cd ../../solutions/ || exit 1
    for dir in "${PWD}"/common/*/; do
        cd "$dir" || exit 1                                # change directory into solution directory
        common_solution_name_snake_case=$(basename "$PWD") # get the solution name from the directory name
        common_solution_name="sra-"$(tr '_' '-' <<<"$common_solution_name_snake_case")

        common_lambda_s3_prefix="$common_solution_name/lambda_code"
        common_templates_s3_prefix="$common_solution_name/templates"

        create_solution_staging_folder "$common_templates_s3_prefix" "$common_lambda_s3_prefix"

        common_staging_templates_folder="$STAGING_FOLDER/$common_templates_s3_prefix" || exit 1
        common_staging_lambda_folder="$STAGING_FOLDER/$common_lambda_s3_prefix" || exit 1

        echo "# Solution: $common_solution_name"
        stage_cloudformation_templates "$dir" "$common_staging_templates_folder"
        package_and_stage_lambda_code "$dir" "$common_staging_lambda_folder" "$common_solution_name"

        { # try
            {
                # shellcheck disable=SC2034
                BUCKET_ACL=$(aws s3api get-bucket-acl --bucket "$STAGING_BUCKET" 2>&1)
            } && {
                upload_cloudformation_templates "$common_staging_templates_folder" "$common_templates_s3_prefix"
                upload_lambda_code "$common_staging_lambda_folder" "$common_lambda_s3_prefix"

                cd "$common_staging_lambda_folder" || exit 1
                update_lambda_functions "$common_lambda_s3_prefix"
            }
        } || { # catch
            check_caller
        }
    done
}

# Run the staging logic
if [ "$solution_directory" != "none" ]; then
    create_configuration_parameters
    create_staging_folder
    package_and_stage_common_solutions
    create_solution_staging_folder "$TEMPLATES_S3_PREFIX" "$LAMBDA_S3_PREFIX"

    STAGING_TEMPLATES_FOLDER="$STAGING_FOLDER/$TEMPLATES_S3_PREFIX" || exit 1
    STAGING_LAMBDA_FOLDER="$STAGING_FOLDER/$LAMBDA_S3_PREFIX" || exit 1

    echo "# Solution: $SOLUTION_NAME"
    stage_cloudformation_templates "$solution_directory" "$STAGING_TEMPLATES_FOLDER"
    package_and_stage_lambda_code "$solution_directory" "$STAGING_LAMBDA_FOLDER" "$SOLUTION_NAME"

    {
        {
            # shellcheck disable=SC2034
            BUCKET_ACL=$(aws s3api get-bucket-acl --bucket "$STAGING_BUCKET" 2>&1)
        } && {
            upload_cloudformation_templates "$STAGING_TEMPLATES_FOLDER" "$TEMPLATES_S3_PREFIX"
            upload_lambda_code "$STAGING_LAMBDA_FOLDER" "$LAMBDA_S3_PREFIX"

            cd "$STAGING_LAMBDA_FOLDER" || exit 1
            update_lambda_functions "$LAMBDA_S3_PREFIX"

            cd "$HERE" || exit 1 # return to the calling directory
        }
    } || {
        check_caller
    }

    if [[ "$STAGING_BUCKET" != "none" ]] && [[ "$STAGING_BUCKET" != *"--"* ]]; then
        echo "### SRA STAGING S3 BUCKET NAME: $STAGING_BUCKET"
    fi
    echo "### SRA STAGING UPLOADS FOLDER: $STAGING_FOLDER"
    echo "### CLOUDFORMATION TEMPLATES FOLDER: $TEMPLATES_S3_PREFIX"
    echo "### S3 LAMBDA CODE FOLDER: $LAMBDA_S3_PREFIX"
    cd "$HERE" || exit 1 # return to the calling directory
else
    echo "$usage"
fi

exit 0
