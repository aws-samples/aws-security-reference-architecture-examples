locals {
  aws_partition          = data.aws_partition.current.partition
  aws_account_id         = data.aws_caller_identity.current.account_id
  aws_region             = data.aws_region.current.name

  c_not_global_region_us_east_1 = local.aws_region != "us-east-1"
  c_register_delegated_admin = var.p_register_delegated_admin_account == true
  c_control_tower_regions = var.p_control_tower_regions_only == true
}

module "m_config_sns_topic" {
  source = "./sns"

  providers = {
    aws = aws.audit
  }

  p_configuration_email = var.p_configuration_email
  p_config_org_sns_key_alias = var.p_config_org_sns_key_alias
  p_config_topic_name = var.p_config_topic_name
  p_subscribe_to_configuration_topic = var.p_subscribe_to_configuration_topic
}

module "m_management_configuration_role"{
    source = "./configuration_role"

    providers = {
      aws = aws.management
    }

    p_audit_account_id = var.p_audit_account_id
    p_management_account_id = var.p_management_account_id
    p_home_region = var.p_home_region
}

module "m_configuration_role"{
    count = local.aws_account_id != var.p_management_account_id ? 1 : 0

    source = "./configuration_role"

    providers = {
      aws = aws.main
    }

    p_audit_account_id = var.p_audit_account_id
    p_management_account_id = var.p_management_account_id
    p_home_region = var.p_home_region
}

// delivery bucket

// configuration

// global events

// delivery kms

// org-sns

// register delegated admin..?

// config aggregator
