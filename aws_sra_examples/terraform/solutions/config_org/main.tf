locals {
  aws_partition  = data.aws_partition.current.partition
  aws_account_id = data.aws_caller_identity.current.account_id
  aws_region     = data.aws_region.current.name

  c_not_global_region_us_east_1 = local.aws_region != "us-east-1"
  c_register_delegated_admin    = var.p_register_delegated_admin_account == true
  c_control_tower_regions       = var.p_control_tower_regions_only == true

  is_audit_account = data.aws_caller_identity.current.account_id == var.p_audit_account_id
  is_log_account   = data.aws_caller_identity.current.account_id == var.p_audit_account_id
  is_home_region   = data.aws_region.current.name == var.p_home_region
}

module "m_config_sns_topic" {
  depends_on = [module.m_configuration_role]
  count      = local.is_audit_account ? 1 : 0
  source     = "./sns"

  p_configuration_email              = var.p_configuration_email
  p_config_org_sns_key_alias         = var.p_config_org_sns_key_alias
  p_config_topic_name                = var.p_config_topic_name
  p_subscribe_to_configuration_topic = var.p_subscribe_to_configuration_topic
}

module "m_configuration_role" {
  count = local.is_home_region ? 1 : 0

  source = "./configuration_role"

  providers = {
    aws = aws.main
  }

  p_audit_account_id      = var.p_audit_account_id
  p_management_account_id = var.p_management_account_id
  p_home_region           = var.p_home_region
}

// delivery kms
module "m_delivery_kms" {
  count  = local.is_audit_account ? 1 : 0
  source = "./delivery_kms_key"

  providers = {
    aws = aws.main
  }

  p_log_archive_account_id = var.p_log_archive_account_id
  p_management_account_id  = var.p_management_account_id
}

// delivery bucket
module "m_delivery_bucket" {
  depends_on = [module.m_configuration_role, module.m_delivery_kms]
  count      = local.is_audit_account && local.is_home_region ? 1 : 0
  source     = "./delivery_s3_bucket"

  providers = {
    aws = aws.log_archive
  }

  p_organization_id                   = var.p_organization_id
  p_config_org_delivery_bucket_prefix = var.p_config_org_delivery_bucket_prefix
  p_config_org_delivery_kms_key_arn   = module.m_delivery_kms[0].config_delivery_kms_key_arn
}

// configuration
module "m_configuration" {
  depends_on = [module.m_configuration_role, module.m_delivery_bucket]
  count      = local.is_audit_account && local.is_home_region ? 1 : 0
  source     = "./configuration"

  providers = {
    aws = aws.management
  }

  p_publishing_destination_bucket_name = module.m_delivery_bucket[0].config_delivery_bucket_name
  p_home_region                        = var.p_home_region
  p_delivery_s3_key_prefix             = var.p_organization_id
  p_kms_key_arn                        = module.m_delivery_kms[0].config_delivery_kms_key_arn
  p_audit_account_id                   = var.p_audit_account_id
  p_organization_id                    = var.p_organization_id
  p_log_archive_account_id             = var.p_log_archive_account_id
  p_current_region                     = data.aws_region.current.name
}

// global events
module "m_global_events" {
  count  = local.is_audit_account && local.is_home_region && local.c_not_global_region_us_east_1 ? 1 : 0
  source = "./global_events"

  providers = {
    aws = aws.management
  }

  p_home_region       = var.p_home_region
  p_sra_solution_name = var.p_sra_solution_name
}

// org-sns
module "m_org_sns_kms_key" {
  count = local.is_audit_account ? 1 : 0

  source = "./sns"

  providers = {
    aws = aws.main
  }
}

// config aggregator
module "m_config_aggregator" {
  count = local.is_audit_account && local.is_home_region ? 1 : 0

  source = "./aggregator_org_configuration"

  providers = {
    aws = aws.main
  }
}