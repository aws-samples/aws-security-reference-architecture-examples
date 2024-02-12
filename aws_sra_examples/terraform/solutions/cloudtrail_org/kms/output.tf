output "cloudtrail_kms_key_arn" {
  description = "ARN of the KMS Key used for Cloudtrail delivery encryption"
  value       = aws_kms_key.organization_cloudtrail_key.arn
}