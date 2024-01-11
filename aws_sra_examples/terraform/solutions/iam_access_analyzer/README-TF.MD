<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.1.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.1.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_account_analyzer"></a> [account\_analyzer](#module\_account\_analyzer) | ./account | n/a |
| <a name="module_org_analyzer"></a> [org\_analyzer](#module\_org\_analyzer) | ./org | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_analyzer_name_prefix"></a> [access\_analyzer\_name\_prefix](#input\_access\_analyzer\_name\_prefix) | Access Analyzer Name Prefix. The Account ID will be appended to the name. | `string` | `"sra-account-access-analyzer"` | no |
| <a name="input_account_id"></a> [account\_id](#input\_account\_id) | Current Account ID | `string` | n/a | yes |
| <a name="input_audit_account_id"></a> [audit\_account\_id](#input\_audit\_account\_id) | AWS Account ID of the Control Tower Audit account. | `string` | n/a | yes |
| <a name="input_home_region"></a> [home\_region](#input\_home\_region) | Name of the Control Tower home region | `string` | n/a | yes |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | AWS Account ID of the Control Tower Log Archive account. | `string` | n/a | yes |
| <a name="input_org_access_analyzer_name"></a> [org\_access\_analyzer\_name](#input\_org\_access\_analyzer\_name) | Organization Access Analyzer Name | `string` | `"sra-organization-access-analyzer"` | no |
| <a name="input_sra_solution_name"></a> [sra\_solution\_name](#input\_sra\_solution\_name) | The SRA solution name. The default value is the folder name of the solution | `string` | `"sra-iam-access-analyzer"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->