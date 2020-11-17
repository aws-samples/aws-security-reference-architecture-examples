Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

# Solutions

The structure of the Security Reference Architecture solution folders are in the below format and include the files 
needed to deploy the solutions using different deployment platforms including the AWS Landing Zone, AWS Control Tower, 
and CloudFormation StackSets.

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
         - parameters (provides customizable parameter values that are passed to the template)
           > **Update the values to align with your deployment**                  
         - add_on_manifest.yaml (defines which core accounts or baseline AVMs a resource will get created in)
           > **Update the OU and account names to align with your deployment**
         - user-input.yaml (parameters and values used within each template)
           > **Empty - Parameter values are in the parameter files**
      - aws-control-tower
         - parameters (provides customizable parameter values that are passed to the template)
           > **Update the values to align with your deployment**   
         - manifest.yaml
           > **Update the OU and account names to align with your deployment**                                                                    

#### Resources

- [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)
- [Customizations for AWS Control Tower](https://aws.amazon.com/solutions/implementations/customizations-for-aws-control-tower/)
- [AWS Landing Zone](https://aws.amazon.com/solutions/implementations/aws-landing-zone/)
   - [Implementation Guide](https://s3.amazonaws.com/www.awslandingzone.com/guides/aws-landing-zone-implementation-guide.pdf)
   - [Developer Guide](https://s3.amazonaws.com/www.awslandingzone.com/guides/aws-landing-zone-developer-guide.pdf)