# Catalog: KMS-mediated exposure. The S3 bucket and bucket policy/ACL here
# are entirely clean and private - any scanner that only inspects S3
# resource policies/ACLs will correctly see nothing wrong with the bucket.
# The actual exposure is one layer down: the KMS key used for the bucket's
# default encryption has a key policy that hands out kms:Decrypt far more
# broadly than the bucket itself ever does. This category is intentionally
# scoped to the key policy itself, not just S3 - SQS, SNS, and Lambda can
# all be mediated by a permissive CMK the exact same way; VULN-KMS-001
# demonstrates the pattern via S3 since that's the clearest to verify.

# ---------------------------------------------------------------------------
# VULN-KMS-001: Key policy grants kms:Decrypt/DescribeKey to Principal "*"
# with no condition. The bucket using this key for default encryption has
# no bucket policy and no public ACL - fully private at the S3 layer.
#
# This is a latent risk, not a directly-exploitable one on its own: nobody
# outside this account can call s3:GetObject on this bucket at all (that's
# gated by the bucket's own policy/ACL, which grant nothing to anyone), so
# an external principal can't retrieve the ciphertext through S3 in the
# first place. The exposure matters the moment the ciphertext becomes
# reachable through ANY other path - a misconfigured share added later, a
# stolen snapshot, an intercepted replication stream, a backup - at which
# point this key policy means that ciphertext decrypts for literally
# anyone, instead of being useless noise the way a properly-scoped key
# policy would make it. A defense-in-depth layer that silently isn't one.
# ---------------------------------------------------------------------------
module "kms_public_decrypt" {
  source = "../../modules/kms_key_vuln"

  test_case_id = "VULN-KMS-001"
  account_id   = var.account_id
  description  = "KMS key policy grants Decrypt to Principal wildcard while the bucket using it for default encryption is otherwise fully private"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"

  key_policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-default-1"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid       = "PublicDecrypt"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })
}

module "s3_kms_exposure_bucket" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-KMS-001"
  account_id   = var.account_id
  description  = "Bucket is fully private at the S3 layer. Default encryption uses a KMS key whose policy grants Decrypt to Principal wildcard"

  expected_access_analyzer_finding = "no"
  expected_cspm_finding            = "no"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_kms_exposure_bucket" {
  bucket = module.s3_kms_exposure_bucket.bucket_id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.kms_public_decrypt.key_arn
    }
  }
}

resource "aws_s3_object" "s3_kms_exposure_bucket" {
  bucket       = module.s3_kms_exposure_bucket.bucket_id
  key          = "vuln-kms-001-encrypted-object.txt"
  content      = "VULN-KMS-001: this object is encrypted with a KMS key whose policy grants Decrypt to anyone, even though the bucket itself is private."
  content_type = "text/plain"

  tags = {
    Project        = "cloud-vuln-range"
    VulnTestCaseId = "VULN-KMS-001"
  }

  depends_on = [aws_s3_bucket_server_side_encryption_configuration.s3_kms_exposure_bucket]
}
