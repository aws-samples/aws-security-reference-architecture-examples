<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.1.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.1.0 |
| <a name="provider_local"></a> [local](#provider\_local) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_dynamo_tf_lock"></a> [dynamo\_tf\_lock](#module\_dynamo\_tf\_lock) | ./dynamodb | n/a |
| <a name="module_mangement_account_parameters"></a> [mangement\_account\_parameters](#module\_mangement\_account\_parameters) | ./ssm_parameters | n/a |
| <a name="module_s3_state_bucket"></a> [s3\_state\_bucket](#module\_s3\_state\_bucket) | ./s3 | n/a |
| <a name="module_sra_execution_role"></a> [sra\_execution\_role](#module\_sra\_execution\_role) | ./sra_execution_role | n/a |
| <a name="module_sra_secrets_kms"></a> [sra\_secrets\_kms](#module\_sra\_secrets\_kms) | ./secrets_kms | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_cloudformation_stack_set.sra_execution_role_stackset](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack_set) | resource |
| [aws_cloudformation_stack_set_instance.sra_execution_role_stackset_instance](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack_set_instance) | resource |
| [local_file.backend_file_creation](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.config_file_creation](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_ssm_parameter.audit_account_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.customer_control_tower_regions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.customer_control_tower_regions_without_home_region](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.enabled_regions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.enabled_regions_without_home_region](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.home_region](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.log_archive_account_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.management_account_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.organization_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_ssm_parameter.root_organizational_unit_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_partition"></a> [aws\_partition](#input\_aws\_partition) | AWS Partition (e.g., aws or aws-cn) | `string` | `"aws"` | no |
| <a name="input_control_tower"></a> [control\_tower](#input\_control\_tower) | AWS Control Tower landing zone deployed/in-use | `string` | `"true"` | no |
| <a name="input_execution_role_name"></a> [execution\_role\_name](#input\_execution\_role\_name) | Name of the SRA execution role | `string` | `"sra-execution"` | no |
| <a name="input_governed_regions"></a> [governed\_regions](#input\_governed\_regions) | AWS regions (comma separated) if not using AWS Control Tower (leave set to ct-regions for AWS Control Tower environments) | `string` | `"ct-regions"` | no |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | Log Archive Account ID | `string` | `"222222222222"` | no |
| <a name="input_security_account_id"></a> [security\_account\_id](#input\_security\_account\_id) | Security Tooling Account ID | `string` | `"111111111111"` | no |
| <a name="input_solution_name"></a> [solution\_name](#input\_solution\_name) | Name of the SRA solution | `string` | `"sra-create-deployment-roles"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->