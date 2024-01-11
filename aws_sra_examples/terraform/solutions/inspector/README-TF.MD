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
| <a name="module_inspector_configuration_role"></a> [inspector\_configuration\_role](#module\_inspector\_configuration\_role) | ./configuration_role | n/a |

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
| <a name="input_ecr_rescan_duration"></a> [ecr\_rescan\_duration](#input\_ecr\_rescan\_duration) | ECR Rescan Duration | `string` | n/a | yes |
| <a name="input_enabled_regions"></a> [enabled\_regions](#input\_enabled\_regions) | (Optional) Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions. | `string` | `""` | no |
| <a name="input_home_region"></a> [home\_region](#input\_home\_region) | Name of the Control Tower home region | `string` | n/a | yes |
| <a name="input_inspector_configuration_role_name"></a> [inspector\_configuration\_role\_name](#input\_inspector\_configuration\_role\_name) | Inspector Configuration role to assume in the delegated administrator account | `string` | `"sra-inspector-configuration"` | no |
| <a name="input_inspector_control_tower_regions_only"></a> [inspector\_control\_tower\_regions\_only](#input\_inspector\_control\_tower\_regions\_only) | Only enable in the Control Tower governed regions | `bool` | `true` | no |
| <a name="input_inspector_org_lambda_function_name"></a> [inspector\_org\_lambda\_function\_name](#input\_inspector\_org\_lambda\_function\_name) | Lambda function name | `string` | `"sra-inspector-org"` | no |
| <a name="input_inspector_org_lambda_role_name"></a> [inspector\_org\_lambda\_role\_name](#input\_inspector\_org\_lambda\_role\_name) | Inspector configuration Lambda role name | `string` | `"sra-inspector-org-lambda"` | no |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | AWS Account ID of the Control Tower Log Archive account. | `string` | n/a | yes |
| <a name="input_management_account_id"></a> [management\_account\_id](#input\_management\_account\_id) | Organization Management Account ID | `string` | n/a | yes |
| <a name="input_organization_id"></a> [organization\_id](#input\_organization\_id) | AWS Organizations ID | `string` | n/a | yes |
| <a name="input_scan_components"></a> [scan\_components](#input\_scan\_components) | Components to scan (e.g., 'ec2,ecs') | `string` | n/a | yes |
| <a name="input_sra_solution_name"></a> [sra\_solution\_name](#input\_sra\_solution\_name) | The SRA solution name. The default value is the folder name of the solution. | `string` | `"sra-inspector-org"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->