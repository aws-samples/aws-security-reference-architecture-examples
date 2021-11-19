# Solutions <!-- omit in toc -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Table of Contents <!-- omit in toc -->

- [Introduction](#introduction)
- [Solutions Folder layout](#solutions-folder-layout)
- [Resources](#resources)

## Introduction

The structure of the Security Reference Architecture solution folders are in the below format and include the files needed to deploy the solutions using different deployment platforms including the Customizations for AWS Control Tower and
CloudFormation StackSets.

## Solutions Folder layout

- aws_service_name
  - aws_service_solution
    - customizations_for_aws_control_tower
      - parameters [required for manifest version 2020-01-01]
        - solution-template-name.json [Update the values to align with your deployment]
      - manifest.yaml [Update the OU, account names, and parameters to align with your deployment]
    - documentation
      - solution-architecture.png
      - solution-architecture.pptx
    - lambda
      - lambda_function_1_source
        - lambda_function_name.py
        - requirements.txt
      - lambda_function_n_source
        - lambda_function_name.py
        - requirements.txt
    - policies
      - service-control-policy.json
      - iam-policy.json
    - templates [CloudFormation template files for deploying resources]
      - sra-solution-name-template.yaml
    - scripts
      - verification_script.py
      - helper_script.py

## Resources

- [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)
- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
