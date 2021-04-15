## General Guidance for Contributing

### CloudFormation

- [ ] GG-CLOUDFORMATION1 = Parameterize all resource values
- [ ] GG-CLOUDFORMATION2 = Include parameter groups and labels
- [ ] GG-CLOUDFORMATION3 = Validate all parameters
- [ ] GG-CLOUDFORMATION4 = Sort everything in alphabetical order (e.g. Labels, Parameters, Policy Actions, etc.)
- [ ] GG-CLOUDFORMATION5 = No inline Lambda code
- [ ] GG-CLOUDFORMATION6 = Use custom resource properties over Lambda resource environment variables
- [ ] GG-CLOUDFORMATION7 = Scan templates using CFN NAG and provide metadata with specific reason for any findings that 
  cannot be remediated

### Encryption

- [ ] GG-ENCRYPTION1 = Enable encryption by default. Customer Managed Key (CMK) preferred.
- [ ] GG-ENCRYPTION2 = Least privilege used in key policies
  
### IAM

- [ ] GG-IAM1 = All IAM roles and users must be least privileged with full action names (no wildcards) listed in 
  policies
- [ ] GG-IAM2 = IAM policy files and/or statements are grouped by service with read and write actions in separate 
  statements
- [ ] GG-IAM3 = Avoid using AWS managed policies
- [ ] GG-IAM4 = Restrict actions to a resource or resource prefix when possible
  
### Lambda 

- [ ] GG-LAMBDA1 = Add disclaimer stating input validation covered in CloudFormation
- [ ] GG-LAMBDA2 = Handle all exceptions
- [ ] GG-LAMBDA3 = Code broken up in to smaller specific methods or classes for readability
- [ ] GG-LAMBDA4 = No hardcoded values
- [ ] GG-LAMBDA5 = Unique IAM role used for each function
- [ ] GG-LAMBDA6 = Only include libraries that are not included by the Lambda runtime (e.g. boto3 containing new API)
- [ ] GG-LAMBDA7 = Include a packaging script or instructions instead of including packaged Lambda code (e.g. zip file)
- [ ] GG-LAMBDA8 = Run a SAST scan on the code and fix all findings, if possible but at a minimum fix critical and high 
  findings (e.g. bandit for python)
  
### Testing

- [ ] GG-SOLUTION_TESTING1 = Test deploying the solution in a multi-account environment using AWS Landing Zone and 
  Customizations for AWS Control
- [ ] GG-SOLUTION_TESTING2 = Test removing the solution in a multi-account environment following the provided 
  instructions
- [ ] GG-SOLUTION_TESTING3 = Have at least 1 peer review of the solution before submitting a merge/pull request

