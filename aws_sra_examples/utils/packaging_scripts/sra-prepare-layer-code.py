"""This script performs operations to download a package using python's pip module.

Version: 1.0

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import argparse
import os
import shutil
import subprocess  # noqa S404 (best practice for calling pip from script)
import sys
import zipfile

import pip

command_arguments = argparse.ArgumentParser(
    description="Download a python module, zips the module to prep for use as a lambda layer part of the security reference architecture (SRA)"
)
command_arguments.add_argument(
    "-n",
    "--name",
    help="The name of the zip file. e.g. sra-inspector-org-layer.zip",
    nargs="?",
    default="sra-inspector-org-layer.zip",
    required=True,
)
command_arguments.add_argument(
    "-d",
    "--directory",
    help="The directory (with full path) to store the zip file. e.g. ~/director_name/sra_staging_manual_upload/sra-inspector-org/layer_code",
    nargs="?",
    default="~/Docs/Code/fork/aws-security-reference-architecture-examples/sra_staging_manual_upload/sra-inspector-org/layer_code",
    required=True,
)
command_arguments.add_argument(
    "-p",
    "--package",
    help="The name of the package library to download. e.g. boto3",
    nargs="?",
    default="boto3",
    required=True,
)
command_arguments.add_argument(
    "-v",
    "--version",
    help="The version of the package library to download. e.g. 1.26.24",
    nargs="?",
    default="",
    required=False,
)


input_arguments = command_arguments.parse_args()
package_version = ""
zip_file_directory = ""
zip_file_name = ""
package_name = ""
if str(input_arguments.name).strip():
    zip_file_name = str(input_arguments.name).strip()
if str(input_arguments.directory).strip():
    zip_file_directory = str(input_arguments.directory).strip()
if str(input_arguments.package).strip():
    package_name = str(input_arguments.package).strip()
if str(input_arguments.version).strip():
    package_version = str(input_arguments.version).strip()
if package_version == "":
    package_temp_directory = f"{zip_file_directory}/tmp_{package_name}"  # noqa S108 (set using command-line arguments)
else:
    package_temp_directory = f"{zip_file_directory}/tmp_{package_name}-{package_version}"  # noqa S108 (set using command-line arguments)


def pip_install(package: str) -> None:
    """Use pip to install package.

    Args:
        package: name of the package to install
    """
    print(f"...Downloading {package} to {package_temp_directory}/python target folder")  # noqa T201 (uses print)
    subprocess.check_call(  # noqa S603 (trusted input from parameters passed)
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            package,
            "--upgrade",
            "--target",
            f"{package_temp_directory}/python",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def zip_folder(path: str, zip_file: zipfile.ZipFile) -> None:
    """Create a zipped file from a folder.

    Args:
        path: path to the file
        zip_file: zipped file handle
    """
    print(f"...Creating layer code zip file")  # noqa T201 (uses print)
    for root, dirs, files in os.walk(path):  # noqa B007 (dirs variable required & unused)
        for discovered_file in files:
            zip_file.write(
                os.path.join(root, discovered_file),
                os.path.relpath(os.path.join(root, discovered_file), os.path.join(path, "..")),
            )


print(f"...Using pip version {pip.__version__}")  # noqa T201 (uses print)
if package_version == "":
    print(f"...Package to download: {package_name} (latest version in pip)")  # noqa T201 (uses print)
    pip_install(package_name)
else:
    print(f"...Package to download: {package_name} version {package_version}")  # noqa T201 (uses print)
    pip_install(f"{package_name}=={package_version}")
print(f"...Zip file to create from downloaded package: {zip_file_directory}/{zip_file_name}")  # noqa T201 (uses print)
zip_file = zipfile.ZipFile(f"{zip_file_directory}/{zip_file_name}", "w", zipfile.ZIP_DEFLATED)
zip_folder(f"{package_temp_directory}/python", zip_file)
zip_file.close()

shutil.rmtree(package_temp_directory)
