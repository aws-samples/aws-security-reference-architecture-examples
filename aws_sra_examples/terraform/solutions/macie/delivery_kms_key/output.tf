output "macie_delivery_kms_key_arn" {
  description = "ARN of the KMS Key used for Macie delivery encryption"
  value       = aws_kms_key.macie_delivery_key.arn
}