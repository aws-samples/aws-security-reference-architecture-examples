########################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
########################################################################
variable "account_id" {
  description = "Current Account ID"
  type        = string
}

variable "management_account_id" {
  description = "Organization Management Account ID"
  type        = string
}

variable "home_region" {
  description = "Name of the Control Tower home region"
  type        = string
}

variable "audit_account_id" {
  description = "AWS Account ID of the Control Tower Audit account."
  type        = string
}

variable "log_archive_account_id" {
  description = "AWS Account ID of the Control Tower Log Archive account."
  type        = string
}

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "disable_guard_duty" {
  description = "Update to 'true' to disable GuardDuty in all accounts and regions before deleting the TF."
  type        = string
}

variable "enable_s3_logs" {
  description = "Auto enable S3 logs"
  type        = string
}

variable "enable_kubernetes_audit_logs" {
  description = "Auto enable Kubernetes Audit Logs"
  type        = string
}

variable "enable_malware_protection" {
  description = "Auto enable Malware Protection"
  type        = string
}

variable "enable_rds_login_events" {
  description = "Auto enable RDS Login Events"
  type        = string
}

variable "enable_eks_runtime_monitoring" {
  description = "Auto enable EKS Runtime Monitoring"
  type        = string
}

variable "enable_eks_addon_management" {
  description = "Auto enable EKS Add-on Management"
  type        = string
}

variable "enable_lambda_network_logs" {
  description = "Auto enable Lambda Network Logs"
  type        = string
}