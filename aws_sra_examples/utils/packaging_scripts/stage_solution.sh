#!/usr/bin/env bash
set -e

###########################################################################################
# Purpose: This script stages all solution Lambda functions and CloudFormation templates by:
#          1. Create a local staging folder 'sra_staging_manual_upload' for all files that are uploaded to the S3 staging bucket
#          2. If no arguments provided, package all solutions and upload to the staging S3 bucket using the SSM parameter for the staging bucket name using the default or current AWS profile.
#          3. If --profile provided, this profile will get exported and used for uploading the staging files to S3.
#          4. If --solution_directory provided, package/upload all common solutions and package/upload the provided solution to the staging bucket.
#          5. If --staging_bucket_name provided, use this for the staging bucket name.
# Usage:   ~/aws-security-reference-architecture-examples/aws_sra_examples/utils/packaging_scripts/stage_solution.sh \
#           --profile <management account aws profile> \
#           --staging_bucket_name <sra staging s3 bucket name> \
#           --solution_directory <path to the solution directory>
# Example: ~/aws-security-reference-architecture-examples/aws_sra_examples/utils/packaging_scripts/stage_solution.sh \
#          --profile management-account-profile \
#          --staging_bucket_name sra-staging-123456789012-us-east-1 \
#          --solution_directory ~/aws-security-reference-architecture-examples/aws_sra_examples/solutions/cloudtrail/cloudtrail_org
###########################################################################################
# shellcheck disable=SC2086
usage="$(basename $0) [-h] [--profile s] [--staging_bucket_name s] [--solution_directory s] ---script stage solution Lambda code and CloudFormation templates

where:
    -h  show this help text
    --profile [optional] AWS CLI profile for the management account, example = management-account-profile
    --staging_bucket_name [optional] S3 Staging Bucket to upload files, example = sra-staging-123456789012-us-east-1
    --solution_directory [optional] SRA Solution Directory Path, example = ~/aws-security-reference-architecture-examples/aws_sra_examples/solutions/cloudtrail/cloudtrail_org"

if [[ $1 == "-h" ]]; then
    echo "$usage"
    exit 1
fi

profile=${profile:-none}
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

export_profile() {
    # Function to export the provided AWS profile
    if [ "$profile" != "none" ]; then
        export AWS_PROFILE=$profile || exit 1
        echo "...Using AWS Profile: $profile"
    fi
}

get_staging_bucket_name_from_ssm() {
    # Function to get the staging bucket name from SSM parameter store
    { # try
        STAGING_BUCKET_NAME=$(aws ssm get-parameter --name "/sra/staging-s3-bucket-name" --output text --query "Parameter.Value" 2>&1)
    } || {
        STAGING_BUCKET_NAME=""
        echo "---> ERROR: Unable to get SSM parameter for S3 Staging Bucket Name '/sra/staging-s3-bucket-name"
    }
}

create_solution_staging_folder() {
    # Function to create the solution staging folder
    cd "$SRA_STAGING_FOLDER_DIR" || exit 1
    STAGING_FOLDER="${PWD}"
    mkdir -p "$1" || exit 1 # create the staging templates folder
    mkdir -p "$2" || exit 1 # create the staging lambda folder
}

create_solution_staging_layer_folder() {
    # Function to create the solution staging folder
    cd "$SRA_STAGING_FOLDER_DIR" || exit 1
    STAGING_FOLDER="${PWD}"
    mkdir -p "$1" || exit 1 # create the staging layer folder
}

create_configuration_parameters() {
    # Function to create configuration parameters
    HERE="${PWD}"
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
    SRA_STAGING_FOLDER_NAME="sra_staging_manual_upload"
    TMP_FOLDER_NAME="$HOME/temp_sra_lambda_src_XXXX" # This folder will be cleaned up by the script after it is used. The XXXX will get replaced by a random value by the mktemp command.
    STAGING_BUCKET_NAME="$staging_bucket_name"

    if [ "$STAGING_BUCKET_NAME" == "none" ]; then
        get_staging_bucket_name_from_ssm
    fi
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
    echo "...Stage CloudFormation Templates"
    cd "$1" || exit 1 # change directory into solution directory

    cp -r ./templates/* "$2/" || exit 1 # copy CloudFormation templates to staging folder
}

package_and_stage_lambda_code() {
    # Function to package and stage Lambda code
    if [ -d "$1/lambda/src" ]; then
        echo "...Package and Stage Lambda Code"
        
        src_dir="$1/lambda/src"
        cd "$src_dir" || exit 1
        has_python=$(find ./*.py 2>/dev/null | wc -l)
        has_requirements=$(find requirements.txt 2>/dev/null | wc -l)

        if [ "$has_python" -ne 0 ] && [ "$has_requirements" -ne 0 ]; then
            echo "...Creating the temporary packaging folder (tmp_sra_lambda_src_XXXX)"
            tmp_folder=$(mktemp -d "$TMP_FOLDER_NAME") || exit 1 # create the temp folder
            cp -r "$src_dir"/* "$tmp_folder" || exit 1           # copy lambda source to temp source folder
            pip3 --disable-pip-version-check install -t "$tmp_folder" -r "$tmp_folder/requirements.txt" -q ||
                {
                    rm -rf "$tmp_folder"
                    echo "---> Error: Python3 is required"
                    exit 1
                }

            cd "$2" || exit 1 # change directory into staging folder
            lambda_zip_file="$2/$3.zip"
            rm -f "$lambda_zip_file" # remove zip file, if exists

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
            echo "---> ERROR: Lambda src folder does not have any python files and a requirements.txt file"
        fi
    else
        echo "---> ERROR: Lambda src folder not found at $1/lambda/src"
    fi
}

# added for layer code required for updated boto3 libraries for the inspector solution
package_and_stage_layer_code() {
    # Function to package and stage layer code (for lambda layers needed)
    if [ -d "$1/layer" ]; then
        echo "...Package and Stage Layer (lambda layers) Code"
        layer_folder_count=0
        for dir in "$1"/layer/*/; do
            layer_folder_count=$((layer_folder_count + 1))
        done
        for dir in "$1"/layer/*/; do
            layer_dir="${dir%"${dir##*[!/]}"}" # remove the trailing /
            layer_dir="${layer_dir##*/}"       # remove everything before the last /
            layer_dir="${layer_dir//_/-}"      # replace all underscores with dashes

            cd "$dir" || exit 1
            has_package=$(find package.txt 2>/dev/null | wc -l)
            if [ "$has_package" -ne 0 ]; then
                package_line=$(head -n 1 package.txt)
                IFS=';' read -ra package_info <<<"$package_line"

                tmp_folder=$(mktemp -d "$TMP_FOLDER_NAME") || exit 1 # create the temp folder

                cd "$2" || exit 1 # change directory into staging folder
                if [ "$layer_folder_count" -gt "1" ]; then
                    layer_zip_file="$3-${layer_dir}-layer.zip"
                else
                    layer_zip_file="${3}-layer.zip"
                fi
                layer_prep_python_script="$SCRIPT_DIR/sra-prepare-layer-code.py"
                echo "...Preparing lambda layer code"
                if [ ${#package_info[@]} -lt 2 ]; then
                    python3 "$layer_prep_python_script" -n "$layer_zip_file" -d "$2" -p "${package_info[0]}"
                else
                    python3 "$layer_prep_python_script" -n "$layer_zip_file" -d "$2" -p "${package_info[0]}" -v "${package_info[1]}"
                fi

            else

                echo "---> ERROR: Layer folder '$layer_dir' does not have a package.txt file"
            fi
        done
    fi

}

upload_cloudformation_templates() {
    # Function to upload CloudFormation templates to the S3 staging bucket
    if [ "$(ls -A "$1")" ]; then
        {     # try
            { # shellcheck disable=SC2034
                templates_copy_result=$(aws s3 cp "$1/" s3://"$STAGING_BUCKET_NAME/$2/" --recursive --exclude "*" --include "*.yaml" --include "*.template" 2>&1)
            } && {
                echo "...CloudFormation templates uploaded to $STAGING_BUCKET_NAME/$2/"
            }
        } || { # catch
            echo "---> ERROR: CloudFormation templates upload to S3 staging bucket failed. Manually upload the template files from the staging folder: $1"
        }
    fi
}

upload_lambda_code() {
    # Function to upload the lambda zip files to S3
    if [ "$(ls -A "$1")" ]; then
        {     # try
            { # shellcheck disable=SC2034
                lambda_copy_result=$(aws s3 cp "$1/" s3://"$STAGING_BUCKET_NAME/$2/" --recursive --exclude "*" --include "*.zip" 2>&1)
            } && {
                echo "...Lambda zip files uploaded to $STAGING_BUCKET_NAME/$2/"
            }
        } || { # catch
            echo "---> ERROR: Lambda zip files upload to S3 staging bucket failed. Manually upload the Lambda zip files from the staging folder: $1"
        }
    fi
}

upload_layer_code() {
    # Function to upload the layer zip files to S3
    if [ "$(ls -A "$1")" ]; then
        {     # try
            { # shellcheck disable=SC2034
                layer_copy_result=$(aws s3 cp "$1/" s3://"$STAGING_BUCKET_NAME/$2/" --recursive --exclude "*" --include "*.zip" 2>&1)
            } && {
                echo "...Layer zip files uploaded to $STAGING_BUCKET_NAME/$2/"
            }
        } || { # catch
            echo "---> ERROR: Layer zip files upload to S3 staging bucket failed. Manually upload the Lambda zip files from the staging folder: $1"
        }
    fi
}

update_lambda_functions() {
    # Function to update existing Lambda functions with latest code
    if [ "$(ls -A .)" ]; then
        for filename in *.zip; do
            lambda_name="${filename%.zip}"
            {     # try
                { # shellcheck disable=SC2034
                    lambda_check_result=$(aws lambda get-function --function-name "$lambda_name" 2>&1)
                } && {
                    # Update Lambda code
                    { # try
                        # shellcheck disable=SC2034
                        lambda_update_result=$(aws lambda update-function-code --function-name "$lambda_name" --s3-key "$1/$filename" --s3-bucket "$STAGING_BUCKET_NAME" 2>&1) &&
                            echo "...Lambda function $lambda_name updated"
                    } || { # catch
                        echo "---> ERROR: Lambda function $lambda_name update failed"
                    }
                }
            } || { # catch
                echo "...Lambda function $lambda_name not found to update"
            }
        done
    fi
}

check_caller() {
    {
        CALLER_ARN=$(aws sts get-caller-identity --output text --query "Arn" 2>&1) &&
            echo "---> ERROR: Unable to access the staging bucket: $STAGING_BUCKET_NAME. You might be logged into the wrong AWS account or provided the wrong S3 bucket. Authenticated to $CALLER_ARN. Manually upload the files from the staging folder $STAGING_FOLDER."
    } || {
        echo "---> ERROR: Not Authenticated to an AWS account. The script is not able to upload the staging files to S3. Manually upload the files from the staging folder."
    }
}

check_staging_bucket_access() {
    # Function to check the staging bucket access before uploads
    if [ -n "$STAGING_BUCKET_NAME" ]; then
        {     # try
            { # shellcheck disable=SC2034
                BUCKET_ACL=$(aws s3api get-bucket-acl --bucket "$STAGING_BUCKET_NAME" 2>&1) || {
                    if [[ "$BUCKET_ACL" == *"error"* ]] || [[ "$BUCKET_ACL" == *"Unable to locate credentials"* ]]; then
                        BUCKET_ACL=""
                        check_caller
                    fi
                }
            }
        } || { # catch
            BUCKET_ACL=""
            check_caller
        }
    fi
}

package_and_stage_common_solutions() {
    # Function to package and stage all the common solutions
    check_staging_bucket_access
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

        echo "------------------------------------------------------------"
        echo "-- Solution: $common_solution_name"
        echo "------------------------------------------------------------"
        stage_cloudformation_templates "$dir" "$common_staging_templates_folder"
        package_and_stage_lambda_code "$dir" "$common_staging_lambda_folder" "$common_solution_name"

        if [ -n "$BUCKET_ACL" ]; then
            upload_cloudformation_templates "$common_staging_templates_folder" "$common_templates_s3_prefix"
            upload_lambda_code "$common_staging_lambda_folder" "$common_lambda_s3_prefix"

            cd "$common_staging_lambda_folder" || exit 1
            update_lambda_functions "$common_lambda_s3_prefix"
        fi
    done
}

package_and_stage_solutions() {
    # Function to package and stage all the solutions
    check_staging_bucket_access
    cd "$SCRIPT_DIR" || exit 1
    cd ../../ || exit 1

    for solution_dir in "${PWD}"/solutions/*/; do
        cd "$solution_dir" || exit 1
        for dir in "${PWD}"/*/; do
            cd "$dir" || exit 1                                 # change directory into solution directory
            current_solution_name_snake_case=$(basename "$PWD") # get the solution name from the directory name
            current_solution_name="sra-"$(tr '_' '-' <<<"$current_solution_name_snake_case")

            current_lambda_s3_prefix="$current_solution_name/lambda_code"
            current_templates_s3_prefix="$current_solution_name/templates"
            # added for layer code
            current_layer_s3_prefix="$current_solution_name/layer_code"

            create_solution_staging_folder "$current_templates_s3_prefix" "$current_lambda_s3_prefix"
            # added for layer code
            create_solution_staging_layer_folder "$current_layer_s3_prefix"

            current_staging_templates_folder="$STAGING_FOLDER/$current_templates_s3_prefix" || exit 1
            current_staging_lambda_folder="$STAGING_FOLDER/$current_lambda_s3_prefix" || exit 1
            # added for layer code
            current_staging_layer_folder="$STAGING_FOLDER/$current_layer_s3_prefix" || exit 1

            echo "------------------------------------------------------------"
            echo "-- Solution: $current_solution_name"
            echo "------------------------------------------------------------"
            stage_cloudformation_templates "$dir" "$current_staging_templates_folder"
            base_dir="$dir"
            package_and_stage_lambda_code "$dir" "$current_staging_lambda_folder" "$current_solution_name"
            # added for layer code
            package_and_stage_layer_code "$base_dir" "$current_staging_layer_folder" "$current_solution_name"

            if [ -n "$BUCKET_ACL" ]; then
                upload_cloudformation_templates "$current_staging_templates_folder" "$current_templates_s3_prefix"
                upload_lambda_code "$current_staging_lambda_folder" "$current_lambda_s3_prefix"
                # added for layer code
                upload_layer_code "$current_staging_layer_folder" "$current_layer_s3_prefix"

                cd "$current_staging_lambda_folder" || exit 1
                update_lambda_functions "$current_lambda_s3_prefix"
            fi
        done
    done
}

# Run the staging logic
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
# echo $SCRIPT_DIR
export_profile
create_configuration_parameters
create_staging_folder

if [ "$solution_directory" != "none" ]; then
    cd "$solution_directory" || exit 1          # change directory into solution directory
    solution_name_snake_case=$(basename "$PWD") # get the solution name from the directory name
    solution_name="sra-"$(tr '_' '-' <<<"$solution_name_snake_case")
    solution_lambda_s3_prefix="$solution_name/lambda_code"
    solution_templates_s3_prefix="$solution_name/templates"

    package_and_stage_common_solutions
    create_solution_staging_folder "$solution_templates_s3_prefix" "$solution_lambda_s3_prefix"

    staging_templates_folder="$STAGING_FOLDER/$solution_templates_s3_prefix" || exit 1
    staging_lambda_folder="$STAGING_FOLDER/$solution_lambda_s3_prefix" || exit 1
    echo "------------------------------------------------------------"
    echo "-- Solution: $solution_name"
    echo "------------------------------------------------------------"
    stage_cloudformation_templates "$solution_directory" "$staging_templates_folder"
    package_and_stage_lambda_code "$solution_directory" "$staging_lambda_folder" "$solution_name"

    if [ -n "$BUCKET_ACL" ]; then
        upload_cloudformation_templates "$staging_templates_folder" "$solution_templates_s3_prefix"
        upload_lambda_code "$staging_lambda_folder" "$solution_lambda_s3_prefix"

        cd "$staging_lambda_folder" || exit 1
        update_lambda_functions "$solution_lambda_s3_prefix"

        cd "$HERE" || exit 1 # return to the calling directory
    fi
else
    package_and_stage_solutions
fi

# Outputs
echo ""
echo "------------------------------------------------------------"
echo "-- Staging Folder and S3 Bucket"
echo "------------------------------------------------------------"
echo "SRA STAGING UPLOADS FOLDER: $STAGING_FOLDER"
if [[ "$STAGING_BUCKET_" != "none" ]] && [[ "$STAGING_BUCKET_NAME" != *"--"* ]]; then
    echo "SRA STAGING S3 BUCKET NAME: $STAGING_BUCKET_NAME"
fi

if [ -z "$BUCKET_ACL" ]; then
    echo "---> Error: Upload to S3 Staging Bucket Failed. Manually upload the files from the staging folder: $STAGING_FOLDER to the staging S3 bucket: $STAGING_BUCKET_NAME"
fi
cd "$HERE" || exit 1 # return to the calling directory

exit 0
