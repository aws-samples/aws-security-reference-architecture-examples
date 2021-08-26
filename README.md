Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

## AWS Security Reference Architecture Examples

This repository contains AWS CloudFormation templates to help developers and engineers deploy AWS security-related 
services in a multi-account environment following patterns that align with the 
[AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/). 
The Amazon Web Services (AWS) Security Reference Architecture (AWS SRA) is a holistic set of guidelines for deploying 
the full complement of AWS security services in a multi-account environment.

The AWS service configurations and resources (e.g. IAM roles and policies) deployed by these templates are deliberately very 
restrictive. They are intended to illustrate an implementation path rather than provide a complete solution. 
You will need to modify and tailor these templates to suit your individual environment and security needs.

The examples within this repository have been deployed and tested using the corresponding deployment 
platform (e.g. AWS Landing Zone, AWS Control Tower, AWS CloudFormation StackSets).

## Example Solutions
* CloudTrail
    * [Organization CloudTrail](solutions/cloudtrail/cloudtrail-org)
* Config
    * [Account Aggregator](solutions/config/aggregator-acct)
    * [Organization Aggregator](solutions/config/aggregator-org)
    * [Organization Conformance Pack](solutions/config/conformance-pack-org)
* Firewall Manager
    * [Organization Firewall Manager](solutions/firewall-manager/firewall-manager-org)
* GuardDuty
    * [Organization GuardDuty](solutions/guardduty/guardduty-org)
* Macie
    * [Organization Macie](solutions/macie/macie-org)
* SecurityHub
    * [Account SecurityHub Enabler](solutions/securityhub/securityhub-enabler-acct)

## Extras
   * [Prerequisites for AWS Control Tower solutions](extras/aws-control-tower/prerequisites)
   * [AWS Landing Zone Configuration](extras/aws-landing-zone-configuration)
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
A. All the examples in this repository are derived from common patterns that many customers ask us to help them deploy
   within their environments. We will be adding to the examples over time.

Q. How were these solutions created?  
A. We’ve collected, cataloged, and curated our multi-account security solution knowledge based on working with a 
   variety of AWS customers.

Q. Who is the audience for these AWS Security Reference Architecture examples?  
A. Security professionals that are looking for illustrative examples of deploying security patterns in AWS. These 
   code samples provide a starting point from which you can build and tailor infrastructure for your needs.

Q. Why didn't the solutions use inline Lambda functions within the CloudFormation templates?  
A. Reasons: 
   * You should control the dependencies in your function's deployment package as stated in the [best practices for working with AWS Lambda functions](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html). 
   * The [AWS Lambda runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) might not be the latest version, which contains a feature that is needed for the solution.

Q. I have ideas to improve this repository. What should I do?  
A. Please create an issue or submit a pull request.

## Contributors
[Contributors](CONTRIBUTORS)

## License Summary
The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License. See the LICENSE file.

The sample code within this documentation is made available under the MIT-0 license. See the LICENSE-SAMPLECODE file.
