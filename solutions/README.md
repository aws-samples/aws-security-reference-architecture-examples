Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

# Solutions

The Security Reference Architecture solution folders are structured in the below format and include the files needed to deploy the solutions using different deployment platforms including the AWS Landing Zone, AWS Control Tower, and CloudFormation StackSets.

#### Solutions Folder layout

- AWS Service Name
   - AWS Service Solution
      - documentation
         - diagram (architecture diagram files)
         - setup (setup files to help with solution deployment)
      - code 
         - src (Lambda source code)
      - templates (CloudFormation template files for deploying resources)
      - aws-landing-zone
         - parameters (Uses jinja2 to accept values passed from the user-input.yaml file)                    
         - add_on_manifest.yaml (defines which core accounts or baseline AVMs a resource will get created in)
           > **Review OU and account names align with your deployment**
         - user-input.yaml (parameters and values used within each template)
           > **Modify parameter values to reflect your environment**
      - aws-control-tower
         - parameters
         - manifest.yaml                                                                      

#### Resources

- [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)
- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
- [AWS Landing Zone](https://aws.amazon.com/solutions/implementations/aws-landing-zone/)
   - [Implementation Guide](https://s3.amazonaws.com/www.awslandingzone.com/guides/aws-landing-zone-implementation-guide.pdf)
   - [Developer Guide](https://s3.amazonaws.com/www.awslandingzone.com/guides/aws-landing-zone-developer-guide.pdf)