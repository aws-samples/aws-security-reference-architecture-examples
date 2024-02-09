<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | n/a |
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_null"></a> [null](#provider\_null) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.management_account_parameters](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_iam_role.management_account_parameters_lambda_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.cloudwatch_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.management_account_parameters_lambda_ssm_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_lambda_function.management_account_parameters](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_invocation.lambda_invoke](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_invocation) | resource |
| [null_resource.package_lambda](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) | resource |
| [archive_file.hash_check](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.zipped_lambda](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudwatch_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.management_account_parameters_lambda_ssm_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_control_tower"></a> [control\_tower](#input\_control\_tower) | AWS Control Tower landing zone deployed/in-use | `string` | `"true"` | no |
| <a name="input_create_lambda_log_group"></a> [create\_lambda\_log\_group](#input\_create\_lambda\_log\_group) | Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function, to allow for setting a Log Retention and/or KMS Key for encryption. | `string` | `"false"` | no |
| <a name="input_governed_regions"></a> [governed\_regions](#input\_governed\_regions) | AWS regions (comma separated) if not using AWS Control Tower (leave set to ct-regions for AWS Control Tower environments) | `string` | `"ct-regions"` | no |
| <a name="input_lambda_log_group_kms_key"></a> [lambda\_log\_group\_kms\_key](#input\_lambda\_log\_group\_kms\_key) | (Optional) KMS Key ARN to use for encrypting the Lambda logs data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys. | `string` | `""` | no |
| <a name="input_lambda_log_group_retention"></a> [lambda\_log\_group\_retention](#input\_lambda\_log\_group\_retention) | Specifies the number of days you want to retain log events. | `string` | `"14"` | no |
| <a name="input_lambda_log_level"></a> [lambda\_log\_level](#input\_lambda\_log\_level) | Lambda Function Logging Level. | `string` | `"INFO"` | no |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | Log Archive Account ID | `number` | `222222222222` | no |
| <a name="input_management_account_parameters_lambda_function_name"></a> [management\_account\_parameters\_lambda\_function\_name](#input\_management\_account\_parameters\_lambda\_function\_name) | Lambda function name for creating Control Tower account SSM parameters. | `string` | `"sra-management-account-parameters"` | no |
| <a name="input_management_account_parameters_lambda_role_name"></a> [management\_account\_parameters\_lambda\_role\_name](#input\_management\_account\_parameters\_lambda\_role\_name) | Lambda execution role for creating Control Tower account SSM parameters. | `string` | `"sra-management-account-parameters-lambda"` | no |
| <a name="input_security_account_id"></a> [security\_account\_id](#input\_security\_account\_id) | Security Tooling Account ID | `number` | `111111111111` | no |
| <a name="input_sra_solution_name"></a> [sra\_solution\_name](#input\_sra\_solution\_name) | The SRA solution name. The default value is the folder name of the solution. | `string` | `"sra-common-prerequisites"` | no |
| <a name="input_sra_solution_tag_key"></a> [sra\_solution\_tag\_key](#input\_sra\_solution\_tag\_key) | The SRA solution tag key applied to all resources created by the solution that support tagging. The value is the pSRASolutionName. | `string` | `"sra-solution"` | no |
| <a name="input_sra_staging_s3_bucket_name"></a> [sra\_staging\_s3\_bucket\_name](#input\_sra\_staging\_s3\_bucket\_name) | (Optional) SRA Staging S3 bucket name for the artifacts relevant to the solution. (e.g., lambda zips, CloudFormation templates). If empty, the SRA Staging S3 bucket name will be resolved from the SSM Parameter '/sra/staging-s3-bucket-name'. | `string` | `""` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->