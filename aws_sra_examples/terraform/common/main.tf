########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################


########################################################################
# Deploy Pre-requisites for Management Account
########################################################################

module "mangement_account_parameters" {
  source = "./ssm_parameters"

  control_tower          = var.control_tower
  governed_regions       = var.governed_regions
  security_account_id    = var.security_account_id
  log_archive_account_id = var.log_archive_account_id
}

module "sra_execution_role" {
  depends_on = [module.mangement_account_parameters]
  source     = "./sra_execution_role"

  management_account_id = data.aws_ssm_parameter.management_account_id.value
}

module "sra_secrets_kms" {
  depends_on = [module.mangement_account_parameters]

  source = "./secrets_kms"

  management_account_id = data.aws_ssm_parameter.management_account_id.value
  organization_id       = data.aws_ssm_parameter.organization_id.value
}

resource "aws_cloudformation_stack_set" "sra_execution_role_stackset" {
  name        = "sra-stackset-execution-role"
  description = "SRA execution role stackset"

  template_body = file("${path.root}/../../solutions/common/common_prerequisites/templates/sra-common-prerequisites-stackset-execution-role.yaml")
  parameters = {
    pSRAExecutionRoleName = var.execution_role_name,
    pSRASolutionName      = var.solution_name,
    pManagementAccountId  = data.aws_ssm_parameter.management_account_id.value
  }

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }
  call_as      = "SELF"
  capabilities = ["CAPABILITY_NAMED_IAM"]
  managed_execution {
    active = true
  }
  operation_preferences {
    failure_tolerance_percentage = 100
    max_concurrent_percentage    = 100
    region_concurrency_type      = "PARALLEL"
  }
  permission_model = "SERVICE_MANAGED"
}

module "s3_state_bucket" {
  source = "./s3"

  kms_key_id = module.sra_secrets_kms.kms_key_arn
}

module "dynamo_tf_lock" {
  source = "./dynamodb"
}

resource "aws_cloudformation_stack_set_instance" "sra_execution_role_stackset_instance" {
  deployment_targets {
    organizational_unit_ids = [data.aws_ssm_parameter.root_organizational_unit_id.value]
  }
  region         = data.aws_ssm_parameter.home_region.value
  stack_set_name = aws_cloudformation_stack_set.sra_execution_role_stackset.name
}

########################################################################
# Create tfvar config file
########################################################################
resource "local_file" "backend_file_creation" {
  depends_on = [module.mangement_account_parameters]
  content    = <<-EOT
    ########################################################################
    # Main Configuration
    ########################################################################
    bucket         = "${module.s3_state_bucket.bucket_name}"
    key            = "state/sra_state.tfstate"
    region         = "${data.aws_ssm_parameter.home_region.value}"
    encrypt        = true
    dynamodb_table = "${module.dynamo_tf_lock.dynamo_db_table_name}"
    EOT
  filename   = "${path.root}/../solutions/backend.tfvars"
}

resource "local_file" "config_file_creation" {
  depends_on = [module.mangement_account_parameters]
  content    = <<-EOT
    ########################################################################
    # Main Configuration
    ########################################################################
    audit_account_id                                   = "${data.aws_ssm_parameter.audit_account_id.value}"
    home_region                                        = "${data.aws_ssm_parameter.home_region.value}"
    log_archive_account_id                             = "${data.aws_ssm_parameter.log_archive_account_id.value}"
    management_account_id                              = "${data.aws_ssm_parameter.management_account_id.value}"
    organization_id                                    = "${data.aws_ssm_parameter.organization_id.value}"
    root_organizational_unit_id                        = "${data.aws_ssm_parameter.root_organizational_unit_id.value}"
    customer_control_tower_regions                     = "${data.aws_ssm_parameter.customer_control_tower_regions.value}"
    customer_control_tower_regions_without_home_region = "${data.aws_ssm_parameter.customer_control_tower_regions_without_home_region.value}"
    enabled_regions                                    = "${data.aws_ssm_parameter.enabled_regions.value}"
    enabled_regions_without_home_region                = "${data.aws_ssm_parameter.enabled_regions_without_home_region.value}"

    ########################################################################
    # Services to enable/disable
    ########################################################################
    enable_gd                  = false
    enable_sh                  = false
    enable_access_analyzer     = false
    enable_macie               = false
    enable_cloudtrail_org      = false
    enable_iam_password_policy = false
    enable_inspector           = false
    
    ########################################################################
    # Guard Duty Settings
    ########################################################################
    disable_guard_duty                   = true
    enable_s3_logs                       = true
    enable_kubernetes_audit_logs         = true
    enable_malware_protection            = true
    enable_rds_login_events              = true
    enable_eks_runtime_monitoring        = true
    enable_eks_addon_management          = true
    enable_lambda_network_logs           = true
    guardduty_control_tower_regions_only = true
    finding_publishing_frequency         = "FIFTEEN_MINUTES"

    ########################################################################
    # Security Hub Settings
    ########################################################################
    disable_security_hub                     = false
    cis_standard_version                     = "1.4.0"
    compliance_frequency                     = "7"
    securityhub_control_tower_regions_only   = true
    enable_cis_standard                      = false
    enable_pci_standard                      = false
    enable_nist_standard                     = false
    enable_security_best_practices_standard  = true
    pci_standard_version                     = "3.2.1"
    nist_standard_version                    = "5.0.0"
    security_best_practices_standard_version = "1.0.0"

    ########################################################################
    # Inspector Settings
    ########################################################################
    ecr_rescan_duration                  = "LIFETIME"
    scan_components                      = "EC2,ECR,LAMBDA,LAMBDA_CODE"
    inspector_control_tower_regions_only = true

    ########################################################################
    # IAM Password Policy
    ########################################################################
    iam_password_policy_allow_users_to_change_password = true
    iam_password_policy_hard_expiry                    = false
    iam_password_policy_max_password_age               = 90
    iam_password_policy_minimum_password_length        = 14
    iam_password_policy_password_reuse_prevention      = 24
    iam_password_policy_require_lowercase_characters   = true
    iam_password_policy_require_numbers                = true
    iam_password_policy_require_symbols                = true
    iam_password_policy_require_uppercase_characters   = true
    
    ########################################################################
    # Macie Settings
    ########################################################################
    disable_macie                      = false
    macie_finding_publishing_frequency = "FIFTEEN_MINUTES"

    ########################################################################
    # CloudTrail Settings
    ########################################################################
    enable_data_events_only   = true
    enable_lambda_data_events = true
    enable_s3_data_events     = true
    EOT
  filename   = "${path.root}/../solutions/config.tfvars"
}
