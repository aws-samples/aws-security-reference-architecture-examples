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
| <a name="module_register_delegated_admin"></a> [register\_delegated\_admin](#module\_register\_delegated\_admin) | ./register_admin | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_delegated_admin_account_id"></a> [delegated\_admin\_account\_id](#input\_delegated\_admin\_account\_id) | Delegated Admin Account ID | `string` | n/a | yes |
| <a name="input_register_delegated_admin_lambda_function_name"></a> [register\_delegated\_admin\_lambda\_function\_name](#input\_register\_delegated\_admin\_lambda\_function\_name) | Register Delegated Admin - Lambda Function Name | `string` | `"sra-common-register-delegated-admin"` | no |
| <a name="input_register_delegated_admin_lambda_role_name"></a> [register\_delegated\_admin\_lambda\_role\_name](#input\_register\_delegated\_admin\_lambda\_role\_name) | Register Delegated Admin - Lambda Role Name | `string` | `"sra-common-register-delegated-admin-lambda"` | no |
| <a name="input_service_principal_list"></a> [service\_principal\_list](#input\_service\_principal\_list) | Comma delimited list of AWS service principals to delegate an administrator account | `list(string)` | <pre>[<br>  "access-analyzer.amazonaws.com",<br>  "config-multiaccountsetup.amazonaws.com",<br>  "config.amazonaws.com"<br>]</pre> | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->