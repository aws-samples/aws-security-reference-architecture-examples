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
| <a name="module_guardduty_configuration"></a> [guardduty\_configuration](#module\_guardduty\_configuration) | ./gd_configuration | n/a |
| <a name="module_guardduty_configuration_role"></a> [guardduty\_configuration\_role](#module\_guardduty\_configuration\_role) | ./configuration_role | n/a |
| <a name="module_guardduty_delete_role"></a> [guardduty\_delete\_role](#module\_guardduty\_delete\_role) | ./delete_detector | n/a |
| <a name="module_guardduty_delivery_key"></a> [guardduty\_delivery\_key](#module\_guardduty\_delivery\_key) | ./kms_key | n/a |
| <a name="module_guardduty_s3_bucket"></a> [guardduty\_s3\_bucket](#module\_guardduty\_s3\_bucket) | ./s3 | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_account_id"></a> [account\_id](#input\_account\_id) | Current Account ID | `string` | n/a | yes |
| <a name="input_audit_account_id"></a> [audit\_account\_id](#input\_audit\_account\_id) | AWS Account ID of the Control Tower Audit account. | `string` | n/a | yes |
| <a name="input_disable_guard_duty"></a> [disable\_guard\_duty](#input\_disable\_guard\_duty) | Update to 'true' to disable GuardDuty in all accounts and regions before deleting the TF. | `string` | n/a | yes |
| <a name="input_enable_eks_addon_management"></a> [enable\_eks\_addon\_management](#input\_enable\_eks\_addon\_management) | Auto enable EKS Add-on Management | `string` | n/a | yes |
| <a name="input_enable_eks_runtime_monitoring"></a> [enable\_eks\_runtime\_monitoring](#input\_enable\_eks\_runtime\_monitoring) | Auto enable EKS Runtime Monitoring | `string` | n/a | yes |
| <a name="input_enable_kubernetes_audit_logs"></a> [enable\_kubernetes\_audit\_logs](#input\_enable\_kubernetes\_audit\_logs) | Auto enable Kubernetes Audit Logs | `string` | n/a | yes |
| <a name="input_enable_lambda_network_logs"></a> [enable\_lambda\_network\_logs](#input\_enable\_lambda\_network\_logs) | Auto enable Lambda Network Logs | `string` | n/a | yes |
| <a name="input_enable_malware_protection"></a> [enable\_malware\_protection](#input\_enable\_malware\_protection) | Auto enable Malware Protection | `string` | n/a | yes |
| <a name="input_enable_rds_login_events"></a> [enable\_rds\_login\_events](#input\_enable\_rds\_login\_events) | Auto enable RDS Login Events | `string` | n/a | yes |
| <a name="input_enable_s3_logs"></a> [enable\_s3\_logs](#input\_enable\_s3\_logs) | Auto enable S3 logs | `string` | n/a | yes |
| <a name="input_finding_publishing_frequency"></a> [finding\_publishing\_frequency](#input\_finding\_publishing\_frequency) | Finding publishing frequency | `string` | n/a | yes |
| <a name="input_guardduty_control_tower_regions_only"></a> [guardduty\_control\_tower\_regions\_only](#input\_guardduty\_control\_tower\_regions\_only) | Only enable in the Control Tower governed regions | `string` | n/a | yes |
| <a name="input_home_region"></a> [home\_region](#input\_home\_region) | Name of the Control Tower home region | `string` | n/a | yes |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | AWS Account ID of the Control Tower Log Archive account. | `string` | n/a | yes |
| <a name="input_management_account_id"></a> [management\_account\_id](#input\_management\_account\_id) | Organization Management Account ID | `string` | n/a | yes |
| <a name="input_organization_id"></a> [organization\_id](#input\_organization\_id) | AWS Organization ID | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_guard_duty_results"></a> [guard\_duty\_results](#output\_guard\_duty\_results) | n/a |
<!-- END_TF_DOCS -->