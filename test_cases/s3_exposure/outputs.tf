output "bucket_arns" {
  value = {
    "VULN-S3-001" = module.s3_public_policy.bucket_arn
    "VULN-S3-002" = module.s3_external_account_trust.bucket_arn
    "VULN-S3-003" = module.s3_public_acl.bucket_arn
    "VULN-S3-004" = module.s3_public_object_acl.bucket_arn
    "VULN-S3-005" = module.s3_public_access_point.bucket_arn
    "VULN-S3-006" = module.s3_external_access_point.bucket_arn
    "VULN-S3-007" = module.s3_replication_source.bucket_arn
    "VULN-S3-008" = module.s3_public_write.bucket_arn
    "VULN-S3-009" = module.s3_weak_condition.bucket_arn
    "VULN-S3-010" = module.s3_org_wide.bucket_arn
    "VULN-S3-011" = module.s3_authenticated_users_acl.bucket_arn
    "VULN-S3-012" = module.s3_cloudfront_bypass.bucket_arn
  }
}

output "cloudfront_domain_name" {
  description = "VULN-S3-012: the intended access path, in front of the bucket that's also directly public."
  value       = aws_cloudfront_distribution.s3_cloudfront_bypass.domain_name
}

output "access_point_arns" {
  value = {
    "VULN-S3-005" = aws_s3_access_point.s3_public_access_point.arn
    "VULN-S3-006" = aws_s3_access_point.s3_external_access_point.arn
  }
}

output "replication_destination_bucket_name" {
  description = "Exact bucket name the destination_account/ config must create, in the destination account."
  value       = local.replication_destination_bucket_name
}

output "replication_role_arn" {
  description = "Role the destination_account/ bucket policy must trust."
  value       = aws_iam_role.s3_replication.arn
}
