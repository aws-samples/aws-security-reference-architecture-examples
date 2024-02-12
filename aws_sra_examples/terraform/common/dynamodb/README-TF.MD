<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_dynamodb_table.terraform_locks](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_dynamodb_name"></a> [dynamodb\_name](#input\_dynamodb\_name) | DynamoDB Table Name for state locking | `string` | `"sra-tfstate-lock"` | no |
| <a name="input_sra_solution_name"></a> [sra\_solution\_name](#input\_sra\_solution\_name) | SRA Solution Name | `string` | `"sra-tfstate-s3"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_dynamo_db_table_name"></a> [dynamo\_db\_table\_name](#output\_dynamo\_db\_table\_name) | n/a |
<!-- END_TF_DOCS -->