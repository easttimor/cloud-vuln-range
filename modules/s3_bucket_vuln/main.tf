# Intentionally vulnerable S3 bucket: the bucket itself, its Block Public
# Access settings, and (optionally) a bucket ACL. Bucket policies, objects,
# and access points vary too much per test case to generalize here — callers
# attach those directly in the test_cases file, wired to this module's
# bucket_id/bucket_arn outputs.

locals {
  bucket_name = lower("cloud-vuln-range-${var.test_case_id}-${var.account_id}")
}

resource "aws_s3_bucket" "this" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  tags = merge(
    {
      Project                       = "cloud-vuln-range"
      VulnTestCaseId                = var.test_case_id
      VulnDescription               = var.description
      ExpectedAccessAnalyzerFinding = var.expected_access_analyzer_finding
      ExpectedCspmFinding           = var.expected_cspm_finding
      DetectionControl              = var.detection_control
      ManagedBy                     = "terraform"
    },
    var.extra_tags
  )
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
}

resource "aws_s3_bucket_ownership_controls" "this" {
  count  = var.enable_acls ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "this" {
  count  = var.bucket_acl != null ? 1 : 0
  bucket = aws_s3_bucket.this.id
  acl    = var.bucket_acl

  depends_on = [
    aws_s3_bucket_ownership_controls.this,
    aws_s3_bucket_public_access_block.this,
  ]
}

resource "aws_s3_bucket_versioning" "this" {
  count  = var.enable_versioning ? 1 : 0
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}
