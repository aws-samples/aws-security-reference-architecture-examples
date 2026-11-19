output "config_delivery_kms_key_arn" {
  description = "ARN of the KMS Key used for Config delivery encryption"
  value       = aws_kms_key.r_config_delivery_key.arn
}