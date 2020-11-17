Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## Security Reference Architecture Examples

This repository accompanies the AWS Security Reference Architecture (AWS SRA) that can be 
downloaded *[Document will be released soon]*.  AWS SRA is a set of holistic recommendations for thinking about and 
deploying the full set of AWS security and security-related services in a multi-account environment. Customers can 
leverage the AWS SRA to get practical guidance on the scope of all available security services and where they should 
be deployed.

The examples within this repository have been deployed and tested using the corresponding deployment 
platform (e.g. AWS Landing Zone, AWS Control Tower, AWS CloudFormation StackSets).  The AWS services, infrastructure, 
roles, and policies that are deployed in these templates are deliberately very restrictive. They are intended to 
illustrate an implementation path rather than provide a complete solution.

## Example Solutions
* CloudTrail
    * [Organization CloudTrail](solutions/cloudtrail/cloudtrail-org/README.md)
* Config
    * [Account Aggregator](solutions/config/aggregator-acct/README.md)
    * [Organization Conformance Pack](solutions/config/conformance-pack-org/README.md)
* Firewall Manager
    * [Organization Firewall Manager](solutions/firewall-manager/firewall-manager-org)
* GuardDuty
    * [Organization GuardDuty](solutions/guardduty/guardduty-org/README.md)
* SecurityHub
    * [Account SecurityHub Enabler](solutions/securityhub/securityhub-enabler-acct/README.md)
* Extras
   * [Prerequisites for AWS Control Tower solutions](extras/aws-control-tower/prerequisites/README.md)
   * [AWS Landing Zone Configuration](extras/aws-landing-zone-configuration/README.md)
   * packaging-scripts 
      * package-lambda.sh (Creates the Lambda zip file and uploads to an S3 bucket)

## Repository and Solution Naming Convention

The repository is organized by AWS service solutions, which include deployment platforms (e.g., AWS Control Tower, 
AWS Landing Zone, and AWS CloudFormation StackSet).

**Example:**
```
.
|-- solutions
    |-- guardduty
        |-- guardduty-org
            |-- aws-control-tower/
                |-- parameters/
                |-- manifest.yaml
            |-- aws-landing-zone/
                |-- parameters/
                    |-- guardduty-org-configuration.json
                    |-- ...
                |-- add_on_manifest.yaml
                |-- user-input.yaml
           |-- code/src/
               |-- app.py
               |-- requirements.txt
           |-- templates/
               |-- guardduty-org-configuration.yaml
               |-- ...
    |-- ...
```

The example solutions within this repository can be managed/deployed to accounts using AWS Organizations or directly within individual accounts. The suffix on the solution name identifies how the solution is managed/deployed.

| Solution Suffix | Description |
| --------------- | ----------- |
| acct            | The solution is managed/deployed within each account | 
| org             | The solution is managed/deployed to accounts via AWS Organizations |
| ou              | The solution is managed/deployed to accounts via Organization Units |


## Frequently Asked Questions

Q. How were these particular solutions chosen?  
A. All the examples in this repo are derived from patterns shown in the AWS Security Reference Architecture document <<insert link to main doc>>.  We will be adding to the examples over time.

Q. How were these solutions created?  
A. We’ve collected, cataloged, and curated our multi-account security solution knowledge based on working with a variety of AWS customers.

Q. Who is the audience for these AWS Security Reference Architecture examples?  
A. Security professionals that are looking for illustrative examples of deploying security patterns in AWS. These code samples provide a starting point from which you can build and tailor infrastructure for your needs.

Q. Why didn't the solutions use inline Lambda functions within the CloudFormation templates?  
A. Reasons: 
1. You should control the dependencies in your function's deployment package as stated in the [best practices for working with AWS Lambda functions](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html). 
2. The [AWS Lambda runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) might not be the latest version, which contains a feature that is needed for the solution.

Q. I have ideas to improve this repository. What should I do?  
A. Please create an issue or submit a pull request.

## Contributors
[Contributors](CONTRIBUTORS)

## License Summary
The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License. See the LICENSE file.

The sample code within this documentation is made available under the MIT-0 license. See the LICENSE-SAMPLECODE file.
