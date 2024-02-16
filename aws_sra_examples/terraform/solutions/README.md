# AWS SRA Solutions<!-- omit in toc -->
<!-- markdownlint-disable MD033 -->

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: CC-BY-SA-4.0

---

⚠️**Influence the future of the AWS Security Reference Architecture (AWS SRA) code library by taking a [short survey](https://amazonmr.au1.qualtrics.com/jfe/form/SV_9oFz0p67iCw3obk).**

## <!-- omit in toc -->


## Introduction

This will install the other AWS SRA solutions including their lambdas and other resources into the AWS environment to help protect it.

The common pre-requisites solution must be installed, in the management account, prior to installing and of these AWS SRA solutions.

Information on the Terraform requirements, providers, modules, resources, and inputs of this module are documented below.

Please navigate to the [installing the AWS SRA solutions](aws_sra_examples/terraform/README.md#installing-the-aws-sra-solutions) section of the documentation for more information and installation instructions.

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
| <a name="module_access_analyzer"></a> [access\_analyzer](#module\_access\_analyzer) | ./iam_access_analyzer | n/a |
| <a name="module_cloudtrail"></a> [cloudtrail](#module\_cloudtrail) | ./cloudtrail_org | n/a |
| <a name="module_guard_duty"></a> [guard\_duty](#module\_guard\_duty) | ./guard_duty | n/a |
| <a name="module_iam_password_policy"></a> [iam\_password\_policy](#module\_iam\_password\_policy) | ./iam_password_policy | n/a |
| <a name="module_inspector"></a> [inspector](#module\_inspector) | ./inspector | n/a |
| <a name="module_macie"></a> [macie](#module\_macie) | ./macie | n/a |
| <a name="module_register_delegated_admin"></a> [register\_delegated\_admin](#module\_register\_delegated\_admin) | ./register_delegated_administrator | n/a |
| <a name="module_security_hub"></a> [security\_hub](#module\_security\_hub) | ./security_hub | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_account_id"></a> [account\_id](#input\_account\_id) | Account ID used for assuming role | `string` | n/a | yes |
| <a name="input_account_region"></a> [account\_region](#input\_account\_region) | Account Region used for assuming role | `string` | n/a | yes |
| <a name="input_audit_account_id"></a> [audit\_account\_id](#input\_audit\_account\_id) | The name for the audit account ID. | `string` | n/a | yes |
| <a name="input_cis_standard_version"></a> [cis\_standard\_version](#input\_cis\_standard\_version) | CIS Standard Version | `string` | n/a | yes |
| <a name="input_compliance_frequency"></a> [compliance\_frequency](#input\_compliance\_frequency) | Frequency to Check for Organizational Compliance (in days between 1 and 30, default is 7) | `number` | n/a | yes |
| <a name="input_customer_control_tower_regions"></a> [customer\_control\_tower\_regions](#input\_customer\_control\_tower\_regions) | The name for customer control tower regions. | `string` | n/a | yes |
| <a name="input_customer_control_tower_regions_without_home_region"></a> [customer\_control\_tower\_regions\_without\_home\_region](#input\_customer\_control\_tower\_regions\_without\_home\_region) | The name for customer control tower regions without home region. | `string` | n/a | yes |
| <a name="input_disable_guard_duty"></a> [disable\_guard\_duty](#input\_disable\_guard\_duty) | Update to 'true' to disable GuardDuty in all accounts and regions before deleting the TF. | `string` | `"false"` | no |
| <a name="input_disable_macie"></a> [disable\_macie](#input\_disable\_macie) | Update to 'true' to disable Macie in all accounts and regions before deleting the TF. | `string` | n/a | yes |
| <a name="input_disable_security_hub"></a> [disable\_security\_hub](#input\_disable\_security\_hub) | Update to 'true' to disable Security Hub in all accounts and regions before deleting the stack | `bool` | n/a | yes |
| <a name="input_ecr_rescan_duration"></a> [ecr\_rescan\_duration](#input\_ecr\_rescan\_duration) | ECR Rescan Duration | `string` | `"LIFETIME"` | no |
| <a name="input_enable_access_analyzer"></a> [enable\_access\_analyzer](#input\_enable\_access\_analyzer) | Enable or disable IAM Access Analyzer module | `bool` | `true` | no |
| <a name="input_enable_cis_standard"></a> [enable\_cis\_standard](#input\_enable\_cis\_standard) | Indicates whether to enable the CIS AWS Foundations Benchmark Standard | `bool` | n/a | yes |
| <a name="input_enable_cloudtrail_org"></a> [enable\_cloudtrail\_org](#input\_enable\_cloudtrail\_org) | Enable or disable CloudTrail Organization module | `bool` | `true` | no |
| <a name="input_enable_data_events_only"></a> [enable\_data\_events\_only](#input\_enable\_data\_events\_only) | Only Enable Cloud Trail Data Events | `string` | n/a | yes |
| <a name="input_enable_eks_addon_management"></a> [enable\_eks\_addon\_management](#input\_enable\_eks\_addon\_management) | Auto enable EKS Add-on Management | `string` | n/a | yes |
| <a name="input_enable_eks_runtime_monitoring"></a> [enable\_eks\_runtime\_monitoring](#input\_enable\_eks\_runtime\_monitoring) | Auto enable EKS Runtime Monitoring | `string` | n/a | yes |
| <a name="input_enable_gd"></a> [enable\_gd](#input\_enable\_gd) | Enable or disable Guard Duty module | `bool` | `true` | no |
| <a name="input_enable_iam_password_policy"></a> [enable\_iam\_password\_policy](#input\_enable\_iam\_password\_policy) | Enable or disable IAM Password Policy Module | `bool` | `true` | no |
| <a name="input_enable_inspector"></a> [enable\_inspector](#input\_enable\_inspector) | Enable or disable Inspector module | `bool` | `true` | no |
| <a name="input_enable_kubernetes_audit_logs"></a> [enable\_kubernetes\_audit\_logs](#input\_enable\_kubernetes\_audit\_logs) | Auto enable Kubernetes Audit Logs | `string` | n/a | yes |
| <a name="input_enable_lambda_data_events"></a> [enable\_lambda\_data\_events](#input\_enable\_lambda\_data\_events) | Enable Cloud Trail Data Events for all Lambda functions | `string` | n/a | yes |
| <a name="input_enable_lambda_network_logs"></a> [enable\_lambda\_network\_logs](#input\_enable\_lambda\_network\_logs) | Auto enable Lambda Network Logs | `string` | n/a | yes |
| <a name="input_enable_macie"></a> [enable\_macie](#input\_enable\_macie) | Enable or disable Macie module | `bool` | `true` | no |
| <a name="input_enable_malware_protection"></a> [enable\_malware\_protection](#input\_enable\_malware\_protection) | Auto enable Malware Protection | `string` | n/a | yes |
| <a name="input_enable_member_account_parameters"></a> [enable\_member\_account\_parameters](#input\_enable\_member\_account\_parameters) | Enable or disable Members Account Paramters module | `bool` | `true` | no |
| <a name="input_enable_nist_standard"></a> [enable\_nist\_standard](#input\_enable\_nist\_standard) | Indicates whether to enable the National Institute of Standards and Technology (NIST) SP 800-53 Rev. 5 | `bool` | n/a | yes |
| <a name="input_enable_pci_standard"></a> [enable\_pci\_standard](#input\_enable\_pci\_standard) | Indicates whether to enable the Payment Card Industry Data Security Standard (PCI DSS) | `bool` | n/a | yes |
| <a name="input_enable_rds_login_events"></a> [enable\_rds\_login\_events](#input\_enable\_rds\_login\_events) | Auto enable RDS Login Events | `string` | n/a | yes |
| <a name="input_enable_s3_data_events"></a> [enable\_s3\_data\_events](#input\_enable\_s3\_data\_events) | Enable Cloud Trail S3 Data Events for all buckets | `string` | n/a | yes |
| <a name="input_enable_s3_logs"></a> [enable\_s3\_logs](#input\_enable\_s3\_logs) | Auto enable S3 logs | `string` | n/a | yes |
| <a name="input_enable_security_best_practices_standard"></a> [enable\_security\_best\_practices\_standard](#input\_enable\_security\_best\_practices\_standard) | Indicates whether to enable the AWS Foundational Security Best Practices Standard | `bool` | n/a | yes |
| <a name="input_enable_sh"></a> [enable\_sh](#input\_enable\_sh) | Enable or disable Security Hub module | `bool` | `true` | no |
| <a name="input_enabled_regions"></a> [enabled\_regions](#input\_enabled\_regions) | The name for enabled regions. | `string` | n/a | yes |
| <a name="input_enabled_regions_without_home_region"></a> [enabled\_regions\_without\_home\_region](#input\_enabled\_regions\_without\_home\_region) | The name for enabled regions without home region. | `string` | n/a | yes |
| <a name="input_finding_publishing_frequency"></a> [finding\_publishing\_frequency](#input\_finding\_publishing\_frequency) | Finding publishing frequency | `string` | `"FIFTEEN_MINUTES"` | no |
| <a name="input_guardduty_control_tower_regions_only"></a> [guardduty\_control\_tower\_regions\_only](#input\_guardduty\_control\_tower\_regions\_only) | Only enable in the Control Tower governed regions | `string` | `"true"` | no |
| <a name="input_home_region"></a> [home\_region](#input\_home\_region) | The name for the home region. | `string` | n/a | yes |
| <a name="input_iam_password_policy_allow_users_to_change_password"></a> [iam\_password\_policy\_allow\_users\_to\_change\_password](#input\_iam\_password\_policy\_allow\_users\_to\_change\_password) | You can permit all IAM users in your account to use the IAM console to change their own passwords. | `string` | n/a | yes |
| <a name="input_iam_password_policy_hard_expiry"></a> [iam\_password\_policy\_hard\_expiry](#input\_iam\_password\_policy\_hard\_expiry) | You can prevent IAM users from choosing a new password after their current password has expired. | `string` | n/a | yes |
| <a name="input_iam_password_policy_max_password_age"></a> [iam\_password\_policy\_max\_password\_age](#input\_iam\_password\_policy\_max\_password\_age) | You can set IAM user passwords to be valid for only the specified number of days. | `string` | n/a | yes |
| <a name="input_iam_password_policy_minimum_password_length"></a> [iam\_password\_policy\_minimum\_password\_length](#input\_iam\_password\_policy\_minimum\_password\_length) | You can specify the minimum number of characters allowed in an IAM user password. | `string` | n/a | yes |
| <a name="input_iam_password_policy_password_reuse_prevention"></a> [iam\_password\_policy\_password\_reuse\_prevention](#input\_iam\_password\_policy\_password\_reuse\_prevention) | You can prevent IAM users from reusing a specified number of previous passwords. | `string` | n/a | yes |
| <a name="input_iam_password_policy_require_lowercase_characters"></a> [iam\_password\_policy\_require\_lowercase\_characters](#input\_iam\_password\_policy\_require\_lowercase\_characters) | You can require that IAM user passwords contain at least one lowercase character from the ISO basic Latin alphabet (a to z). | `string` | n/a | yes |
| <a name="input_iam_password_policy_require_numbers"></a> [iam\_password\_policy\_require\_numbers](#input\_iam\_password\_policy\_require\_numbers) | You can require that IAM user passwords contain at least one numeric character (0 to 9). | `string` | n/a | yes |
| <a name="input_iam_password_policy_require_symbols"></a> [iam\_password\_policy\_require\_symbols](#input\_iam\_password\_policy\_require\_symbols) | You can require that IAM user passwords contain at least one of the following nonalphanumeric characters: ! @ # $ % ^ & * ( ) \_ + - = [ ] {} \| ' | `string` | n/a | yes |
| <a name="input_iam_password_policy_require_uppercase_characters"></a> [iam\_password\_policy\_require\_uppercase\_characters](#input\_iam\_password\_policy\_require\_uppercase\_characters) | You can require that IAM user passwords contain at least one uppercase character from the ISO basic Latin alphabet (A to Z). | `string` | n/a | yes |
| <a name="input_inspector_control_tower_regions_only"></a> [inspector\_control\_tower\_regions\_only](#input\_inspector\_control\_tower\_regions\_only) | Only enable in the Control Tower governed regions | `string` | `"true"` | no |
| <a name="input_log_archive_account_id"></a> [log\_archive\_account\_id](#input\_log\_archive\_account\_id) | The name for the log archive account ID. | `string` | n/a | yes |
| <a name="input_macie_finding_publishing_frequency"></a> [macie\_finding\_publishing\_frequency](#input\_macie\_finding\_publishing\_frequency) | Macie finding publishing frequency | `string` | n/a | yes |
| <a name="input_management_account_id"></a> [management\_account\_id](#input\_management\_account\_id) | The name for the management account ID. | `string` | n/a | yes |
| <a name="input_nist_standard_version"></a> [nist\_standard\_version](#input\_nist\_standard\_version) | NIST Standard Version | `string` | n/a | yes |
| <a name="input_organization_id"></a> [organization\_id](#input\_organization\_id) | The SSM parameter name for the organization ID. | `string` | n/a | yes |
| <a name="input_pci_standard_version"></a> [pci\_standard\_version](#input\_pci\_standard\_version) | PCI Standard Version | `string` | n/a | yes |
| <a name="input_root_organizational_unit_id"></a> [root\_organizational\_unit\_id](#input\_root\_organizational\_unit\_id) | The name for the root organizational unit ID. | `string` | n/a | yes |
| <a name="input_scan_components"></a> [scan\_components](#input\_scan\_components) | Components to scan (e.g., 'ec2,ecs') | `string` | `"ec2"` | no |
| <a name="input_security_best_practices_standard_version"></a> [security\_best\_practices\_standard\_version](#input\_security\_best\_practices\_standard\_version) | SBP Standard Version | `string` | n/a | yes |
| <a name="input_securityhub_control_tower_regions_only"></a> [securityhub\_control\_tower\_regions\_only](#input\_securityhub\_control\_tower\_regions\_only) | Only enable in the Control Tower governed regions | `bool` | n/a | yes |
| <a name="input_sra_alarm_email"></a> [sra\_alarm\_email](#input\_sra\_alarm\_email) | (Optional) Email address for receiving DLQ alarms | `string` | `""` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->