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

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_iam_role.sra_execution_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_partition"></a> [aws\_partition](#input\_aws\_partition) | AWS Partition (e.g., aws or aws-cn) | `string` | `"aws"` | no |
| <a name="input_execution_role_name"></a> [execution\_role\_name](#input\_execution\_role\_name) | Name of the SRA execution role | `string` | `"sra-execution"` | no |
| <a name="input_management_account_id"></a> [management\_account\_id](#input\_management\_account\_id) | AWS Account ID of the Management account (12 digits) | `string` | `"333333333333"` | no |
| <a name="input_solution_name"></a> [solution\_name](#input\_solution\_name) | Name of the SRA solution | `string` | `"sra-create-deployment-roles"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->