"""Lambda python module to interact with the SRA code repository.

Version: 1.0

REPO module for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging
import urllib3
from io import BytesIO
from zipfile import ZipFile
from zipfile import ZIP_DEFLATED
import os
import shutil
import subprocess  # noqa S404 (best practice for calling pip from script)
import sys

# TODO(liamschn): need to exclude "inline_" files from the staging process


class SRARepo:
    """SRA Repo Class."""

    # Setup Default Logger
    LOGGER = logging.getLogger(__name__)
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    LOGGER.setLevel(log_level)

    REPO_ZIP_URL = "https://github.com/aws-samples/aws-security-reference-architecture-examples/archive/refs/heads/main.zip"
    REPO_BRANCH = REPO_ZIP_URL.split(".")[1].split("/")[len(REPO_ZIP_URL.split(".")[1].split("/")) - 1]  # noqa: ECE001
    SOLUTIONS_DIR: str = f"/tmp/aws-security-reference-architecture-examples-{REPO_BRANCH}/aws_sra_examples/solutions"  # noqa: S108
    STAGING_UPLOAD_FOLDER = "/tmp/sra_staging_upload"  # noqa: S108
    STAGING_TEMP_FOLDER = "/tmp/sra_temp"  # noqa: S108

    CONFIG_RULES: dict = {}

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
        self.LOGGER.info("Creating code zip file...")
        for root, dirs, files in os.walk(path):  # noqa B007
            for discovered_file in files:
                if layer is False:
                    zip_file.write(
                        os.path.join(root, discovered_file),
                        os.path.relpath(os.path.join(root, discovered_file), path),
                    )
                else:
                    zip_file.write(
                        os.path.join(root, discovered_file),
                        os.path.relpath(os.path.join(root, discovered_file), os.path.join(path, "..")),
                    )

    def download_code_library(self, repo_zip_url: str) -> None:
        """Download the code library from the repository.

        Args:
            repo_zip_url: URL to the repository zip file
        """
        self.LOGGER.info(f"Downloading code library from {repo_zip_url}")
        http = urllib3.PoolManager()
        repo_zip_file = http.request("GET", repo_zip_url)
        self.LOGGER.info(f"HTTP status code: {repo_zip_file.status}")
        zipfile = ZipFile(BytesIO(repo_zip_file.data))
        zipfile.extractall("/tmp")  # noqa: S108, DUO112
        self.LOGGER.info("Files extracted to /tmp")
        self.LOGGER.info(f"tmp directory listing: {os.listdir('/tmp')}")  # noqa: S108

    def prepare_config_rules_for_staging(self, staging_upload_folder: str, staging_temp_folder: str,  # noqa: CCR001, C901
                                         solutions_dir: str) -> None:
        """Prepare config rules for staging.

        Args:
            staging_upload_folder: staging upload folder
            staging_temp_folder: staging temp folder
            solutions_dir: solutions directory
        """
        self.LOGGER.info("Preparing config rules for staging...")
        if os.path.exists(staging_upload_folder):  # noqa: PL110
            shutil.rmtree(staging_upload_folder)
        if os.path.exists(staging_temp_folder):  # noqa: PL110
            shutil.rmtree(staging_temp_folder)
        os.mkdir(staging_upload_folder)  # noqa: PL102
        os.mkdir(staging_temp_folder)  # noqa: PL102

        service_folders = os.listdir(solutions_dir)
        for service in service_folders:
            service_dir = solutions_dir + "/" + service
            if os.path.isdir(service_dir):  # noqa: PL112
                service_solutions_folders = sorted(os.listdir(service_dir))
                for solution in sorted(service_solutions_folders):
                    if os.path.isdir(os.path.join(service_dir, solution)):  # noqa: PL112
                        self.LOGGER.info(f"Solution: {solution}")
                        if os.path.isdir(os.path.join(service_dir, solution, "lambda/rules")):  # noqa: PL112  # config rules folder
                            solution_config_rules = os.path.join(service_dir, solution, "lambda/rules")  # noqa: PL118
                            config_rule_folders = sorted(os.listdir(solution_config_rules))
                            for config_rule in sorted(config_rule_folders):
                                self.LOGGER.info(f"config rule: {config_rule} (in the {solution} solution)")
                                config_rule_source_files = os.path.join(solution_config_rules, config_rule)  # noqa: PL118
                                solution_name = "sra-" + solution.replace("_", "-")
                                upload_folder_name = "/" + solution_name
                                rule_name = config_rule.replace("_", "-")
                                config_rule_upload_folder_name = "/" + rule_name
                                if solution_name in self.CONFIG_RULES:
                                    self.CONFIG_RULES[solution_name].append(config_rule)
                                else:
                                    self.CONFIG_RULES[solution_name] = [config_rule]
                                if not os.path.exists(staging_temp_folder + upload_folder_name):  # noqa: PL110
                                    os.mkdir(staging_temp_folder + upload_folder_name)  # noqa: PL102
                                if not os.path.exists(staging_temp_folder + upload_folder_name + "/rules"):  # noqa: PL110
                                    os.mkdir(staging_temp_folder + upload_folder_name + "/rules")  # noqa: PL102
                                config_rule_staging_folder_path = (
                                    staging_temp_folder + upload_folder_name + "/rules" + config_rule_upload_folder_name
                                )
                                if not os.path.exists(config_rule_staging_folder_path):  # noqa: PL110
                                    self.LOGGER.info(f"Creating {config_rule_staging_folder_path} folder")
                                    os.mkdir(config_rule_staging_folder_path)  # noqa: PL102
                                if not os.path.exists(staging_upload_folder + upload_folder_name):  # noqa: PL110
                                    self.LOGGER.info(f"Creating {staging_upload_folder + upload_folder_name} folder")
                                    os.mkdir(staging_upload_folder + upload_folder_name)  # noqa: PL102
                                if not os.path.exists(staging_upload_folder + upload_folder_name + "/rules"):  # noqa: PL110
                                    self.LOGGER.info(f"Creating {staging_upload_folder + upload_folder_name + '/rules'} folder")
                                    os.mkdir(staging_upload_folder + upload_folder_name + "/rules")  # noqa: PL102
                                config_rule_upload_folder_path = (
                                    staging_upload_folder + upload_folder_name + "/rules" + config_rule_upload_folder_name
                                )
                                if not os.path.exists(config_rule_upload_folder_path):  # noqa: PL110
                                    self.LOGGER.info(f"Creating {config_rule_upload_folder_path} folder")
                                    os.mkdir(config_rule_upload_folder_path)  # noqa: PL102
                                self.LOGGER.info(f"DEBUG: config_rule_staging_folder_path: {config_rule_staging_folder_path}")
                                self.LOGGER.info(f"DEBUG: config_rule_upload_folder_path: {config_rule_upload_folder_path}")
                                # lambda code
                                if os.path.exists(config_rule_source_files) and os.path.exists(  # noqa: PL110
                                    os.path.join(config_rule_source_files, "requirements.txt")
                                ):
                                    self.LOGGER.info(f"Downloading required packages for {solution} lambda...")
                                    self.pip_install(
                                        os.path.join(config_rule_source_files, "requirements.txt"),
                                        config_rule_staging_folder_path,
                                    )
                                for source_file in os.listdir(config_rule_source_files):
                                    self.LOGGER.info(f"source_file: {source_file}")
                                    if os.path.isdir(os.path.join(config_rule_source_files, source_file)):  # noqa: PL112
                                        self.LOGGER.info(f"{source_file} is a directory, skipping...")
                                    else:
                                        shutil.copy(
                                            os.path.join(config_rule_source_files, source_file),
                                            config_rule_staging_folder_path,
                                        )
                                        self.LOGGER.info(f"DEBUG: Copied {source_file} to {config_rule_staging_folder_path}")
                                        self.LOGGER.info(f"DEBUG: listdir = {os.listdir(config_rule_staging_folder_path)}")
                                        self.LOGGER.info(f"DEBUG: isdir = {os.path.isdir(config_rule_staging_folder_path)}")
                                        for dest_file in os.listdir(config_rule_staging_folder_path):
                                            self.LOGGER.info(f"DEBUG: listing {dest_file} in {config_rule_staging_folder_path}")
                                lambda_target_folder = config_rule_upload_folder_path
                                self.LOGGER.info(
                                    f"Zipping config rule code for {solution} / {config_rule} lambda to"
                                    + f"{lambda_target_folder}{config_rule_upload_folder_name}.zip..."
                                )

                                zip_file = ZipFile(f"{lambda_target_folder}/{config_rule_upload_folder_name}.zip", "w", ZIP_DEFLATED)
                                self.LOGGER.info(
                                    f"DEBUG: Zipping {config_rule_staging_folder_path} folder in to"
                                    + f"{lambda_target_folder}/{config_rule_upload_folder_name}.zip"
                                )
                                self.zip_folder(f"{config_rule_staging_folder_path}", zip_file)
                                zip_file.close()
                                self.LOGGER.info(f"{lambda_target_folder}{config_rule_upload_folder_name}.zip file size is"
                                                 + f"{os.path.getsize(f'{lambda_target_folder}{config_rule_upload_folder_name}.zip')}")
                        # debug stuff:
                        else:
                            self.LOGGER.info(f"{os.path.join(service_dir, solution, 'rules')} does not exist!")
        self.LOGGER.info(f"All config rules: {self.CONFIG_RULES}")

    def prepare_code_for_staging(self, staging_upload_folder: str, staging_temp_folder: str, solutions_dir: str) -> None:  # noqa: CCR001
        """Prepare code for staging.

        Args:
            staging_upload_folder: staging upload folder
            staging_temp_folder: staging temp folder
            solutions_dir: solutions directory
        """
        self.LOGGER.info("Preparing code for staging...")
        if os.path.exists(staging_upload_folder):  # noqa: PL110
            shutil.rmtree(staging_upload_folder)
        if os.path.exists(staging_temp_folder):  # noqa: PL110
            shutil.rmtree(staging_temp_folder)
        os.mkdir(staging_upload_folder)  # noqa: PL102
        os.mkdir(staging_temp_folder)  # noqa: PL102

        service_folders = os.listdir(solutions_dir)
        for service in service_folders:
            service_dir = solutions_dir + "/" + service
            if os.path.isdir(service_dir):  # noqa: PL112
                service_solutions_folders = sorted(os.listdir(service_dir))
                for solution in sorted(service_solutions_folders):
                    if os.path.isdir(os.path.join(service_dir, solution)):  # noqa: PL112
                        self.LOGGER.info(f"Solution: {solution}")
                        source_files = os.path.join(service_dir, solution, "lambda/src")  # noqa: PL118

                        upload_folder_name = "/sra-" + solution.replace("_", "-")
                        os.mkdir(staging_temp_folder + upload_folder_name)  # noqa: PL102
                        os.mkdir(staging_upload_folder + upload_folder_name)  # noqa: PL102

                        # lambda code
                        if os.path.exists(source_files) and os.path.exists(os.path.join(source_files, "requirements.txt")):  # noqa: PL110
                            self.LOGGER.info(f"Downloading required packages for {solution} lambda...")
                            self.pip_install(
                                os.path.join(service_dir, solution, "lambda/src/requirements.txt"),
                                staging_temp_folder + upload_folder_name + "/lambda",
                            )
                            for source_file in os.listdir(source_files):
                                if os.path.isdir(os.path.join(source_files, source_file)):  # noqa: PL112
                                    self.LOGGER.info(f"{source_file} is a directory, skipping...")
                                else:
                                    shutil.copy(os.path.join(source_files, source_file), staging_temp_folder + upload_folder_name + "/lambda")
                            lambda_target_folder = staging_upload_folder + upload_folder_name + "/lambda_code"
                            self.LOGGER.info(f"Zipping lambda code for {solution} lambda to {lambda_target_folder}{upload_folder_name}.zip...")
                            os.mkdir(lambda_target_folder)  # noqa: PL102
                            zip_file = ZipFile(f"{lambda_target_folder}/{upload_folder_name}.zip", "w", ZIP_DEFLATED)
                            self.zip_folder(f"{staging_temp_folder + upload_folder_name}/lambda", zip_file)
                            zip_file.close()

                        # layer code
                        layer_files = os.path.join(service_dir, solution, "layer")  # noqa: PL118
                        if os.path.exists(layer_files):  # noqa: PL110
                            for package in os.listdir(layer_files):
                                self.LOGGER.info(f"Downloading required package ({package}) for {solution} lambda...")
                                self.pip_install(package, staging_temp_folder + upload_folder_name + "/layer/python", True)
                                layer_target_folder = staging_upload_folder + upload_folder_name + "/layer_code"
                                self.LOGGER.info(f"Zipping layer code for {solution} to {layer_target_folder}{upload_folder_name}.zip...")
                                os.mkdir(layer_target_folder)  # noqa: PL102
                                zip_file = ZipFile(f"{layer_target_folder}/{upload_folder_name}-layer.zip", "w", ZIP_DEFLATED)
                                self.zip_folder(f"{staging_temp_folder + upload_folder_name}/layer/python", zip_file, True)
                                zip_file.close()

                        # CloudFormation template code
                        cfn_template_files = os.path.join(service_dir, solution, "templates")  # noqa: PL118
                        if os.path.exists(cfn_template_files):  # noqa: PL110
                            cfn_templates_target_folder = staging_upload_folder + upload_folder_name + "/templates"
                            self.LOGGER.info(f"Copying CloudFormation templates for {solution} to {cfn_templates_target_folder}...")
                            os.mkdir(cfn_templates_target_folder)  # noqa: PL102

                            for cfn_template_file in os.listdir(cfn_template_files):
                                if os.path.isdir(os.path.join(cfn_template_files, cfn_template_file)):  # noqa: PL112
                                    self.LOGGER.info(f"{cfn_template_file} is a directory, skipping...")
                                else:
                                    shutil.copy(os.path.join(cfn_template_files, cfn_template_file), cfn_templates_target_folder)
