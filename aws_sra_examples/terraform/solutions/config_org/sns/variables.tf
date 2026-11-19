########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "p_configuration_email" {
  type        = string
  description = "Email for receiving all AWS configuration events"
  default     = ""
}

variable "p_config_org_sns_key_alias" {
  type        = string
  default     = "sra-config-org-sns-key"
  description = "Config SNS KMS Key Alias"
}

variable "p_config_topic_name" {
  type        = string
  default     = "sra-ConfigNotifications"
  description = "Configuration Notification SNS Topic in Audit Account that AWS Config delivers notifications to."
}

variable "p_sra_solution_name" {
  type        = string
  default     = "sra-config-org"
  description = "The SRA solution name. The default value is the folder name of the solution"
}

variable "p_subscribe_to_configuration_topic" {
  type        = bool
  default     = false
  description = "Indicates whether ConfigurationEmail will be subscribed to the ConfigurationTopicName topic."
}