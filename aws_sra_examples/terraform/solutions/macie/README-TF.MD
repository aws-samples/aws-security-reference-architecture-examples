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
| <a name="module_configuration_role"></a> [configuration\_role](#module\_configuration\_role) | ./configuration_role | n/a |
| <a name="module_delivery_kms_key"></a> [delivery\_kms\_key](#module\_delivery\_kms\_key) | ./delivery_kms_key | n/a |
| <a name="module_delivery_s3_bucket"></a> [delivery\_s3\_bucket](#module\_delivery\_s3\_bucket) | ./delivery_s3_bucket | n/a |
| <a name="module_disable_role"></a> [disable\_role](#module\_disable\_role) | ./disable_role | n/a |
| <a name="module_macie_configuration"></a> [macie\_configuration](#module\_macie\_configuration) | ./configuration | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_audit_account_id"></a> [audit\_account\_id](#input\_audit\_account\_id) | AWS Account ID of the Control Tower Audit account. | `string` | n/a | yes |
| <a name="input_disable_macie"></a> [disable\_macie](#input\_disable\_macie) | Disabled Macie SRA solution | `string` | n/a | yes |
| <a name="input_home_region"></a> [home\_region](#input\_home\_region) | Name of the Control Tower home region | `string` | n/a | yes |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | AWS Account ID of the Control Tower Log Archive account. | `string` | n/a | yes |
| <a name="input_macie_finding_publishing_frequency"></a> [macie\_finding\_publishing\_frequency](#input\_macie\_finding\_publishing\_frequency) | Macie finding publishing frequency | `string` | n/a | yes |
| <a name="input_macie_org_configuration_role_name"></a> [macie\_org\_configuration\_role\_name](#input\_macie\_org\_configuration\_role\_name) | Configuration IAM Role Name | `string` | `"sra-macie-org-configuration"` | no |
| <a name="input_macie_org_lambda_role_name"></a> [macie\_org\_lambda\_role\_name](#input\_macie\_org\_lambda\_role\_name) | Lambda Role Name | `string` | `"sra-macie-org-lambda"` | no |
| <a name="input_management_account_id"></a> [management\_account\_id](#input\_management\_account\_id) | Organization Management Account ID | `string` | n/a | yes |
| <a name="input_organization_id"></a> [organization\_id](#input\_organization\_id) | AWS Organization ID | `string` | n/a | yes |
| <a name="input_secrets_key_alias_arn"></a> [secrets\_key\_alias\_arn](#input\_secrets\_key\_alias\_arn) | (Optional) SRA Secrets Manager KMS Key Alias ARN | `string` | `""` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->