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
| <a name="module_recorder_start_event"></a> [recorder\_start\_event](#module\_recorder\_start\_event) | ./recorder_start_event | n/a |
| <a name="module_security_hub"></a> [security\_hub](#module\_security\_hub) | ./configuration | n/a |
| <a name="module_securityhub_configuration_role"></a> [securityhub\_configuration\_role](#module\_securityhub\_configuration\_role) | ./configuration_role | n/a |

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
| <a name="input_cis_standard_version"></a> [cis\_standard\_version](#input\_cis\_standard\_version) | CIS Standard Version | `string` | `"1.4.0"` | no |
| <a name="input_compliance_frequency"></a> [compliance\_frequency](#input\_compliance\_frequency) | Frequency to Check for Organizational Compliance (in days between 1 and 30, default is 7) | `number` | `7` | no |
| <a name="input_control_tower_lifecycle_rule_name"></a> [control\_tower\_lifecycle\_rule\_name](#input\_control\_tower\_lifecycle\_rule\_name) | The name of the AWS Control Tower Life Cycle Rule | `string` | `"sra-securityhub-org-trigger"` | no |
| <a name="input_create_lambda_log_group"></a> [create\_lambda\_log\_group](#input\_create\_lambda\_log\_group) | Indicates whether a CloudWatch Log Group should be explicitly created for the Lambda function | `bool` | `false` | no |
| <a name="input_delegated_admin_account_id"></a> [delegated\_admin\_account\_id](#input\_delegated\_admin\_account\_id) | Delegated administrator account ID | `string` | n/a | yes |
| <a name="input_disable_security_hub"></a> [disable\_security\_hub](#input\_disable\_security\_hub) | Update to 'true' to disable Security Hub in all accounts and regions before deleting the stack | `bool` | `false` | no |
| <a name="input_enable_cis_standard"></a> [enable\_cis\_standard](#input\_enable\_cis\_standard) | Indicates whether to enable the CIS AWS Foundations Benchmark Standard | `bool` | `false` | no |
| <a name="input_enable_nist_standard"></a> [enable\_nist\_standard](#input\_enable\_nist\_standard) | Indicates whether to enable the National Institute of Standards and Technology (NIST) SP 800-53 Rev. 5 | `bool` | `false` | no |
| <a name="input_enable_pci_standard"></a> [enable\_pci\_standard](#input\_enable\_pci\_standard) | Indicates whether to enable the Payment Card Industry Data Security Standard (PCI DSS) | `bool` | `false` | no |
| <a name="input_enable_security_best_practices_standard"></a> [enable\_security\_best\_practices\_standard](#input\_enable\_security\_best\_practices\_standard) | Indicates whether to enable the AWS Foundational Security Best Practices Standard | `bool` | `true` | no |
| <a name="input_enabled_regions"></a> [enabled\_regions](#input\_enabled\_regions) | (Optional) Enabled regions (AWS regions, separated by commas). Leave blank to enable all regions. | `string` | n/a | yes |
| <a name="input_event_rule_role_name"></a> [event\_rule\_role\_name](#input\_event\_rule\_role\_name) | Event rule role name for putting events on the home region event bus | `string` | `"sra-security-hub-global-events"` | no |
| <a name="input_home_region"></a> [home\_region](#input\_home\_region) | Name of the Control Tower home region | `string` | n/a | yes |
| <a name="input_lambda_log_group_kms_key"></a> [lambda\_log\_group\_kms\_key](#input\_lambda\_log\_group\_kms\_key) | (Optional) KMS Key ARN to use for encrypting the Lambda logs data | `string` | `""` | no |
| <a name="input_lambda_log_group_retention"></a> [lambda\_log\_group\_retention](#input\_lambda\_log\_group\_retention) | Specifies the number of days you want to retain log events | `number` | `14` | no |
| <a name="input_lambda_log_level"></a> [lambda\_log\_level](#input\_lambda\_log\_level) | Lambda Function Logging Level | `string` | `"INFO"` | no |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | AWS Account ID of the Control Tower Log Archive account. | `string` | n/a | yes |
| <a name="input_management_account_id"></a> [management\_account\_id](#input\_management\_account\_id) | Organization Management Account ID | `string` | n/a | yes |
| <a name="input_nist_standard_version"></a> [nist\_standard\_version](#input\_nist\_standard\_version) | NIST Standard Version | `string` | `"5.0.0"` | no |
| <a name="input_organization_id"></a> [organization\_id](#input\_organization\_id) | AWS Organizations ID | `string` | n/a | yes |
| <a name="input_pci_standard_version"></a> [pci\_standard\_version](#input\_pci\_standard\_version) | PCI Standard Version | `string` | `"3.2.1"` | no |
| <a name="input_region_linking_mode"></a> [region\_linking\_mode](#input\_region\_linking\_mode) | Indicates whether to aggregate findings from all of the available Regions in the current partition | `string` | `"SPECIFIED_REGIONS"` | no |
| <a name="input_sechub_rule_name"></a> [sechub\_rule\_name](#input\_sechub\_rule\_name) | Eventbridge rule name | `string` | `"sra-config-recorder"` | no |
| <a name="input_security_best_practices_standard_version"></a> [security\_best\_practices\_standard\_version](#input\_security\_best\_practices\_standard\_version) | SBP Standard Version | `string` | `"1.0.0"` | no |
| <a name="input_security_hub_configuration_role_name"></a> [security\_hub\_configuration\_role\_name](#input\_security\_hub\_configuration\_role\_name) | SecurityHub Configuration role to assume in the delegated administrator account | `string` | `"sra-securityhub-configuration"` | no |
| <a name="input_security_hub_org_lambda_function_name"></a> [security\_hub\_org\_lambda\_function\_name](#input\_security\_hub\_org\_lambda\_function\_name) | Lambda function name | `string` | `"sra-securityhub-org"` | no |
| <a name="input_security_hub_org_lambda_role_name"></a> [security\_hub\_org\_lambda\_role\_name](#input\_security\_hub\_org\_lambda\_role\_name) | SecurityHub configuration Lambda role name | `string` | `"sra-securityhub-org-lambda"` | no |
| <a name="input_securityhub_control_tower_regions_only"></a> [securityhub\_control\_tower\_regions\_only](#input\_securityhub\_control\_tower\_regions\_only) | Only enable in the Control Tower governed regions | `bool` | `true` | no |
| <a name="input_sra_alarm_email"></a> [sra\_alarm\_email](#input\_sra\_alarm\_email) | (Optional) Email address for receiving DLQ alarms | `string` | `""` | no |
| <a name="input_sra_solution_name"></a> [sra\_solution\_name](#input\_sra\_solution\_name) | The SRA solution name. The default value is the folder name of the solution. | `string` | `"sra-securityhub-org"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->