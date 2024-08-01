# import json
import logging
import urllib3
from io import BytesIO
from zipfile import ZipFile
from zipfile import ZIP_DEFLATED
import os
import shutil
import subprocess  # noqa S404 (best practice for calling pip from script)
import sys
# import boto3
# from botocore.exceptions import NoCredentialsError

# import zipfile
import shutil

import pip

# todo(liamschn): need to exclude "inline_" files from the staging process


class sra_repo:
    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    # class attributes # todo(liamschn): make these parameters
    # REPO_RAW_FILE_URL_PREFIX = "https://raw.githubusercontent.com/liamschn/aws-security-reference-architecture-examples/sra-genai/aws_sra_examples/solutions/genai/bedrock_org/lambda/rules/"
    # RULE_LAMBDA_FILES = {}
    # RULE_LAMBDA_FILES["sra_check_iam_users"] = "sra_check_iam_users.py"
    # REPO_BRANCH = REPO_RAW_FILE_URL_PREFIX.split("/")[5]

    REPO_ZIP_URL = "https://github.com/aws-samples/aws-security-reference-architecture-examples/archive/refs/heads/main.zip"
    REPO_BRANCH = REPO_ZIP_URL.split(".")[1].split("/")[len(REPO_ZIP_URL.split(".")[1].split("/")) - 1]
    SOLUTIONS_DIR = f"/tmp/aws-security-reference-architecture-examples-{REPO_BRANCH}/aws_sra_examples/solutions"
    STAGING_UPLOAD_FOLDER = "/tmp/sra_staging_upload"
    STAGING_TEMP_FOLDER = "/tmp/sra_temp"

    CONFIG_RULES: dict = {}

    STAGING_BUCKET: str = "sra-staging-"  # todo(liamschn): get from SSM parameter
    PIP_VERSION = pip.__version__
    URLLIB3_VERSION = urllib3.__version__

    # class methods
    def pip_install(self, requirements: str, package_temp_directory: str, individual: bool = False) -> None:
        """Use pip to install package.

        Args:
            requirements: requirements file or name of the package to install (see individual arg)
            package_temp_directory: target directory where packages will be installed
            individual: set to True if specifying a specific package
        """
        self.LOGGER.info(f"...Downloading requirements ({requirements}) to {package_temp_directory} target folder")
        if individual is False:
            subprocess.check_call(  # noqa S603 (trusted input from parameters passed)
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "-r",
                    requirements,
                    "--upgrade",
                    "--target",
                    f"{package_temp_directory}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            subprocess.check_call(  # noqa S603 (trusted input from parameters passed)
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    requirements,
                    "--upgrade",
                    "--target",
                    f"{package_temp_directory}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


    def zip_folder(self, path: str, zip_file: ZipFile, layer: bool = False) -> None:
        """Create a zipped file from a folder.

        Args:
            path: path to the file
            zip_file: zipped file handle
            layer: true if lambda layer, false otherwise
        """
        self.LOGGER.info(f"Creating code zip file")
        for root, dirs, files in os.walk(path):  # noqa B007 (dirs variable required & unused)
            for discovered_file in files:
                if layer is False:
                    # LOGGER.info("Adding lambda code to zip file")
                    zip_file.write(
                        os.path.join(root, discovered_file),
                        os.path.relpath(os.path.join(root, discovered_file), path),
                    )
                else:
                    # LOGGER.info("Adding layer code to zip file")
                    zip_file.write(
                        os.path.join(root, discovered_file),
                        os.path.relpath(os.path.join(root, discovered_file), os.path.join(path, "..")),
                    )

    # def download_file(self, repo_url_prefix, repo_file, local_folder):
    #     self.LOGGER.info(f"Downloading {repo_file} file from {repo_url_prefix}")
    #     http = urllib3.PoolManager()
    #     # repo_code_file = http.request("GET", 
    #     with open(f"/tmp/{local_folder}{repo_file}", 'wb') as out:
    #         repo_code_file = http.request("GET", repo_url_prefix + repo_file)
    #         self.LOGGER.info(f"HTTP status code: {repo_code_file.status}")
    #         shutil.copyfileobj(repo_code_file, out)
    #     self.LOGGER.info(f"/tmp/{local_folder} directory listing: {os.listdir('/tmp/' + local_folder)}")

    def download_code_library(self, repo_zip_url):
        self.LOGGER.info(f"Downloading code library from {repo_zip_url}")
        http = urllib3.PoolManager()
        repo_zip_file = http.request("GET", repo_zip_url)
        self.LOGGER.info(f"HTTP status code: {repo_zip_file.status}")
        zipfile = ZipFile(BytesIO(repo_zip_file.data))
        zipfile.extractall("/tmp")
        self.LOGGER.info("Files extracted to /tmp")
        self.LOGGER.info(f"tmp directory listing: {os.listdir('/tmp')}")

    def prepare_config_rules_for_staging(self, solution, staging_upload_folder, staging_temp_folder, solutions_dir):
        # self.LOGGER.info(f"listing config rules for {solution}")
        if os.path.exists(staging_upload_folder):
            shutil.rmtree(staging_upload_folder)
        if os.path.exists(staging_temp_folder):
            shutil.rmtree(staging_temp_folder)
        os.mkdir(staging_upload_folder)
        os.mkdir(staging_temp_folder)

        service_folders = os.listdir(solutions_dir)
        for service in service_folders:
            service_dir = solutions_dir + "/" + service
            if os.path.isdir(service_dir):
                service_solutions_folders = sorted(os.listdir(service_dir))
                for solution in sorted(service_solutions_folders):
                    if os.path.isdir(os.path.join(service_dir, solution)):
                        self.LOGGER.info(f"Solution: {solution}")
                        if os.path.isdir(os.path.join(service_dir, solution, "lambda/rules")): # config rules folder
                            solution_config_rules = os.path.join(service_dir, solution, "lambda/rules")
                            config_rule_folders = sorted(os.listdir(solution_config_rules))
                            self.CONFIG_RULES[solution] = []
                            for config_rule in sorted(config_rule_folders):
                                self.LOGGER.info(f"config rule: {config_rule} (in the {solution} solution)")
                                self.CONFIG_RULES[solution].append(config_rule)
                                config_rule_source_files = os.path.join(solution_config_rules, config_rule)
                                upload_folder_name = "/sra-" + solution.replace("_", "-")
                                config_rule_upload_folder_name = "/" + config_rule.replace("_", "-")
                                os.mkdir(staging_temp_folder + upload_folder_name)
                                os.mkdir(staging_temp_folder + upload_folder_name + "/rules")
                                config_rule_staging_folder_path = staging_temp_folder + upload_folder_name + "/rules/" + config_rule_upload_folder_name
                                os.mkdir(config_rule_staging_folder_path)
                                os.mkdir(staging_upload_folder + upload_folder_name)
                                os.mkdir(staging_upload_folder + upload_folder_name + "/rules")
                                config_rule_upload_folder_path = staging_upload_folder + upload_folder_name + "/rules" + config_rule_upload_folder_name
                                os.mkdir(config_rule_upload_folder_path)

                                # lambda code
                                if os.path.exists(config_rule_source_files) and os.path.exists(os.path.join(config_rule_source_files, "requirements.txt")):
                                    self.LOGGER.info(f"Downloading required packages for {solution} lambda...")
                                    self.pip_install(
                                        os.path.join(config_rule_source_files, "requirements.txt"),
                                        config_rule_staging_folder_path,
                                    )
                                for source_file in os.listdir(config_rule_source_files):
                                    if os.path.isdir(os.path.join(config_rule_source_files, source_file)):
                                        self.LOGGER.info(f"{source_file} is a directory, skipping...")
                                    else:
                                        shutil.copy(os.path.join(config_rule_source_files, source_file), staging_temp_folder + upload_folder_name + config_rule_upload_folder_name)
                                lambda_target_folder = config_rule_upload_folder_path
                                self.LOGGER.info(f"Zipping config rule code for {solution} / {config_rule} lambda to {lambda_target_folder}{config_rule_upload_folder_name}.zip...")
                                # os.mkdir(lambda_target_folder)
                                zip_file = ZipFile(f"{lambda_target_folder}/{config_rule_upload_folder_name}.zip", "w", ZIP_DEFLATED)
                                self.zip_folder(f"{config_rule_staging_folder_path}", zip_file)
                                zip_file.close()
                        # debug stuff:
                        else:
                            self.LOGGER.info(f"{os.path.join(service_dir, solution, "rules")} does not exist!")
                            # if solution == "bedrock_org":
                            #     self.LOGGER.info(f"bedrock_org solution does not have config rules!")
                            #     self.LOGGER.info(f"bedrock_org directory listing: {os.listdir('/tmp/aws-security-reference-architecture-examples-sra-genai/aws_sra_examples/solutions/genai/bedrock_org/lambda')}")

    def prepare_code_for_staging(self, staging_upload_folder, staging_temp_folder, solutions_dir):
        if os.path.exists(staging_upload_folder):
            shutil.rmtree(staging_upload_folder)
        if os.path.exists(staging_temp_folder):
            shutil.rmtree(staging_temp_folder)
        os.mkdir(staging_upload_folder)
        os.mkdir(staging_temp_folder)

        service_folders = os.listdir(solutions_dir)
        for service in service_folders:
            service_dir = solutions_dir + "/" + service
            if os.path.isdir(service_dir):
                service_solutions_folders = sorted(os.listdir(service_dir))
                for solution in sorted(service_solutions_folders):
                    if os.path.isdir(os.path.join(service_dir, solution)):
                        self.LOGGER.info(f"Solution: {solution}")
                        # if solution != "inspector_org":  # for debugging
                        #     continue
                        source_files = os.path.join(service_dir, solution, "lambda/src")

                        upload_folder_name = "/sra-" + solution.replace("_", "-")
                        os.mkdir(staging_temp_folder + upload_folder_name)
                        os.mkdir(staging_upload_folder + upload_folder_name)

                        # lambda code
                        if os.path.exists(source_files) and os.path.exists(os.path.join(source_files, "requirements.txt")):
                            self.LOGGER.info(f"Downloading required packages for {solution} lambda...")
                            self.pip_install(
                                os.path.join(service_dir, solution, "lambda/src/requirements.txt"),
                                staging_temp_folder + upload_folder_name + "/lambda",
                            )
                            for source_file in os.listdir(source_files):
                                if os.path.isdir(os.path.join(source_files, source_file)):
                                    self.LOGGER.info(f"{source_file} is a directory, skipping...")
                                else:
                                    shutil.copy(os.path.join(source_files, source_file), staging_temp_folder + upload_folder_name + "/lambda")
                            lambda_target_folder = staging_upload_folder + upload_folder_name + "/lambda_code"
                            self.LOGGER.info(f"Zipping lambda code for {solution} lambda to {lambda_target_folder}{upload_folder_name}.zip...")
                            os.mkdir(lambda_target_folder)
                            zip_file = ZipFile(f"{lambda_target_folder}/{upload_folder_name}.zip", "w", ZIP_DEFLATED)
                            self.zip_folder(f"{staging_temp_folder + upload_folder_name}/lambda", zip_file)
                            zip_file.close()

                        # layer code
                        layer_files = os.path.join(service_dir, solution, "layer")
                        if os.path.exists(layer_files):
                            for package in os.listdir(layer_files):
                                self.LOGGER.info(f"Downloading required package ({package}) for {solution} lambda...")
                                self.pip_install(package, staging_temp_folder + upload_folder_name + "/layer/python", True)
                                layer_target_folder = staging_upload_folder + upload_folder_name + "/layer_code"
                                self.LOGGER.info(f"Zipping layer code for {solution} to {layer_target_folder}{upload_folder_name}.zip...")
                                os.mkdir(layer_target_folder)
                                zip_file = ZipFile(f"{layer_target_folder}/{upload_folder_name}-layer.zip", "w", ZIP_DEFLATED)
                                self.zip_folder(f"{staging_temp_folder + upload_folder_name}/layer/python", zip_file, True)
                                zip_file.close()

                        # CloudFormation template code
                        cfn_template_files = os.path.join(service_dir, solution, "templates")
                        if os.path.exists(cfn_template_files):
                            cfn_templates_target_folder = staging_upload_folder + upload_folder_name + "/templates"
                            self.LOGGER.info(f"Copying CloudFormation templates for {solution} to {cfn_templates_target_folder}...")
                            os.mkdir(cfn_templates_target_folder)

                            for cfn_template_file in os.listdir(cfn_template_files):
                                if os.path.isdir(os.path.join(cfn_template_files, cfn_template_file)):
                                    self.LOGGER.info(f"{cfn_template_file} is a directory, skipping...")
                                else:
                                    shutil.copy(os.path.join(cfn_template_files, cfn_template_file), cfn_templates_target_folder)


    # def stage_code_to_s3(self, directory_path, bucket_name, s3_path):
    #     """
    #     Uploads the prepared code directory to the staging S3 bucket.

    #     :param directory_path: Local path to directory
    #     :param bucket_name: Name of the S3 bucket
    #     :param s3_path: S3 path where the directory will be uploaded
    #     """
    #     s3_client = boto3.client("s3")

    #     for root, dirs, files in os.walk(directory_path):
    #         for file in files:
    #             local_path = os.path.join(root, file)

    #             relative_path = os.path.relpath(local_path, directory_path)
    #             s3_file_path = relative_path
    #             try:
    #                 s3_client.upload_file(local_path, bucket_name, s3_file_path)
    #             except NoCredentialsError:
    #                 self.LOGGER.info("Credentials not available")
    #                 return
