#!/bin/bash
###########################################################################################
# Purpose: This script packages the Lambda source code by:
#          1. Installing the python packages to a /lib directory
#          2. Compressing the files into a zip file
#          3. Optional - Uploading the zip file to an S3 bucket
# Prerequisites:
#          - Python v3.x
#          - Zip or 7zip installed
# Usage:   ./package-lambda.sh \
#           --file_name [zip_file_name] \
#           --bucket [s3_bucket] \
#           --src_dir [src_dir]
# Example: ./package-lambda.sh \
#           --file_name cloudtrail-org.zip \
#           --bucket my-s3-bucket \
#           --src_dir ~/aws_sra_examples/solutions/cloudtrail/cloudtrail_org/lambda/src
###########################################################################################

usage="$(basename "$0") [-h] <--file_name s> [--bucket s] <--src_folder s> ---script to package lambda zip and upload to s3

where:
    -h  show this help text
    --file_name  <required> Lambda zip file
    --bucket  [optional] S3 bucket name for lambda source
    --src_dir <required> Lambda source directory"

if [[ $1 == "-h" ]]; then
  echo "$usage"
  exit 1
fi

file_name=${file_name:-none}
bucket=${bucket:-none}
src_dir=${src_dir:-none}

# read input parameters
while [ $# -gt 0 ]; do

  if [[ $1 == *"--"* ]]; then
    param="${1/--/}"
    declare "$param"="$2"
    # echo $1 $2 // Optional to see the parameter:value result
  fi

  shift
done

if [ "$file_name" != "none" ] && [ "$src_dir" != "none" ]; then

  HERE="${PWD}"                                   # absolute path to this file's folder
  DIST_FOLDER_NAME="$HERE/dist-XXXX"              # dist folder for the zip file if bucket is not provided
  TMP_FOLDER_NAME="$HOME/tmp-sra-lambda-src-XXXX" # will be cleaned
  SRC_FOLDER=$src_dir

  # create the temp packaging folder and install python packages
  echo "...Creating the temporary packaging folder (tmp-sra-lambda-src-XXXX)"
  TMP_FOLDER=$(mktemp -d "$TMP_FOLDER_NAME") || exit 1 # create the temp folder
  cp -r "$SRC_FOLDER"/* "$TMP_FOLDER" || exit 1        # copy lambda source to temp source folder
  pip3 install -t "$TMP_FOLDER" -r "$TMP_FOLDER/requirements.txt" -q ||
    {
      rm -rf "$TMP_FOLDER"
      echo "Error: Python is required"
      exit 1
    }

  # prepare the dist folder
  echo "...Creating the temporary dist-XXXX folder"
  DIST_FOLDER=$(mktemp -d "$DIST_FOLDER_NAME") || exit 1 # create dist folder, if it doesn't exist
  cd "$DIST_FOLDER" || exit 1                            # change directory into dist folder
  rm -f "$file_name"                                     # remove zip file, if exists

  # create zip file in the dist folder
  echo "...Creating zip file from the temp folder contents"
  cd "$TMP_FOLDER" || exit 1 # changed directory to temp folder
  zip -r -q "$DIST_FOLDER/$file_name" . -x .DS_Store ||
    7z a -tzip "$DIST_FOLDER/$file_name" ||
    {
      rm -rf "$DIST_FOLDER"
      echo "---> Zip and 7zip are not available. Manually create the zip file with the temporary folder contents. $TMP_FOLDER"
      exit 1
    } # zip source with packages

  cd "$DIST_FOLDER" || exit 1 # change directory to dist folder

  echo "...Removing $TMP_FOLDER"
  rm -rf "$TMP_FOLDER"

  if [[ "$bucket" != "none" ]]; then

    # upload the lambda zip file to S3
    aws s3api put-object --bucket "$bucket" --key "$file_name" --body "$file_name" &>/dev/null # upload zip file to S3
    if [ $? = 0 ]; then
      echo "...Uploaded Lambda zip file: $file_name to $bucket"
      echo "...Removing $DIST_FOLDER"
      rm -rf "$DIST_FOLDER"
    else
      echo "Error: S3 upload failed. Manually upload the Lambda zip file from the dist folder: $DIST_FOLDER"
    fi

    cd "$HERE" || exit 1 # return to the packaging directory

  fi

else

  echo "$usage"

fi

exit 0
