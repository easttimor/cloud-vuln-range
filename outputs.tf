output "iam_trust_policy_vuln_role_arns" {
  value = module.iam_trust_policy_vulns.role_arns
}

output "s3_exposure_vuln_bucket_arns" {
  value = module.s3_exposure_vulns.bucket_arns
}

output "s3_exposure_vuln_access_point_arns" {
  value = module.s3_exposure_vulns.access_point_arns
}

output "replication_destination_bucket_name" {
  value = module.s3_exposure_vulns.replication_destination_bucket_name
}

output "replication_role_arn" {
  value = module.s3_exposure_vulns.replication_role_arn
}

output "sqs_exposure_vuln_queue_arns" {
  value = module.sqs_exposure_vulns.queue_arns
}

output "cloudfront_domain_name" {
  value = module.s3_exposure_vulns.cloudfront_domain_name
}

output "kms_key_policy_vuln_key_arns" {
  value = module.kms_key_policy_vulns.key_arns
}

output "kms_key_policy_vuln_bucket_arns" {
  value = module.kms_key_policy_vulns.bucket_arns
}
