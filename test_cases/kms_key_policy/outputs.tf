output "key_arns" {
  value = {
    "VULN-KMS-001" = module.kms_public_decrypt.key_arn
  }
}

output "bucket_arns" {
  value = {
    "VULN-KMS-001" = module.s3_kms_exposure_bucket.bucket_arn
  }
}
