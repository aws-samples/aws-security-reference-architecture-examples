<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.1.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws.main"></a> [aws.main](#provider\_aws.main) | >= 5.1.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_inspector_configuration"></a> [inspector\_configuration](#module\_inspector\_configuration) | ./configuration | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_allow_users_to_change_password"></a> [allow\_users\_to\_change\_password](#input\_allow\_users\_to\_change\_password) | You can permit all IAM users in your account to use the IAM console to change their own passwords. | `string` | `"true"` | no |
| <a name="input_create_lambda_log_group"></a> [create\_lambda\_log\_group](#input\_create\_lambda\_log\_group) | Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function, to allow for setting a Log Retention and/or KMS Key for encryption. | `string` | `"false"` | no |
| <a name="input_hard_expiry"></a> [hard\_expiry](#input\_hard\_expiry) | You can prevent IAM users from choosing a new password after their current password has expired. | `string` | `"false"` | no |
| <a name="input_home_region"></a> [home\_region](#input\_home\_region) | Name of the Control Tower home region | `string` | n/a | yes |
| <a name="input_lambda_function_name"></a> [lambda\_function\_name](#input\_lambda\_function\_name) | Lambda function name | `string` | `"sra-iam-password-policy"` | no |
| <a name="input_lambda_log_group_kms_key"></a> [lambda\_log\_group\_kms\_key](#input\_lambda\_log\_group\_kms\_key) | (Optional) KMS Key ARN to use for encrypting the Lambda logs data. If empty, encryption is enabled with CloudWatch Logs managing the server-side encryption keys. | `string` | `""` | no |
| <a name="input_lambda_log_group_retention"></a> [lambda\_log\_group\_retention](#input\_lambda\_log\_group\_retention) | Specifies the number of days you want to retain log events | `string` | `"14"` | no |
| <a name="input_lambda_log_level"></a> [lambda\_log\_level](#input\_lambda\_log\_level) | Lambda Function Logging Level | `string` | `"INFO"` | no |
| <a name="input_lambda_role_name"></a> [lambda\_role\_name](#input\_lambda\_role\_name) | Lambda role name | `string` | `"sra-iam-password-policy-lambda"` | no |
| <a name="input_max_password_age"></a> [max\_password\_age](#input\_max\_password\_age) | You can set IAM user passwords to be valid for only the specified number of days. | `string` | `90` | no |
| <a name="input_minimum_password_length"></a> [minimum\_password\_length](#input\_minimum\_password\_length) | You can specify the minimum number of characters allowed in an IAM user password. | `string` | `14` | no |
| <a name="input_password_reuse_prevention"></a> [password\_reuse\_prevention](#input\_password\_reuse\_prevention) | You can prevent IAM users from reusing a specified number of previous passwords. | `string` | `24` | no |
| <a name="input_require_lowercase_characters"></a> [require\_lowercase\_characters](#input\_require\_lowercase\_characters) | You can require that IAM user passwords contain at least one lowercase character from the ISO basic Latin alphabet (a to z). | `string` | `"true"` | no |
| <a name="input_require_numbers"></a> [require\_numbers](#input\_require\_numbers) | You can require that IAM user passwords contain at least one numeric character (0 to 9). | `string` | `"true"` | no |
| <a name="input_require_symbols"></a> [require\_symbols](#input\_require\_symbols) | You can require that IAM user passwords contain at least one of the following nonalphanumeric characters: ! @ # $ % ^ & * ( ) \_ + - = [ ] {} \| ' | `string` | `"true"` | no |
| <a name="input_require_uppercase_characters"></a> [require\_uppercase\_characters](#input\_require\_uppercase\_characters) | You can require that IAM user passwords contain at least one uppercase character from the ISO basic Latin alphabet (A to Z). | `string` | `"true"` | no |
| <a name="input_sra_solution_name"></a> [sra\_solution\_name](#input\_sra\_solution\_name) | The SRA solution name. The default value is the folder name of the solution | `string` | `"sra-iam-password-policy"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->