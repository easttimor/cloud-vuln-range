# Destination side of VULN-S3-007 (cross-account S3 replication). Apply
# this with credentials for the destination account itself - NOT via the
# sandbox account's profile/role, which has no access here.
#
#   cd test_cases/s3_exposure/destination_account
#   terraform init
#   terraform apply -var="aws_profile=<your profile for the destination account>" \
#     -var="destination_account_id=<destination account id>" \
#     -var="source_account_id=<sandbox account id>"
#
# Then confirm the source side's replication role ARN
# (`terraform output replication_role_arn` from the project root) matches
# what source_replication_role_name/source_account_id build here - it's
# duplicated by hand across two Terraform states, each scoped to a
# different account with no remote backend the other side could read.

locals {
  bucket_name     = "cloud-vuln-range-vuln-s3-007-dest-${var.destination_account_id}"
  source_role_arn = "arn:aws:iam::${var.source_account_id}:role/${var.source_replication_role_name}"
}

resource "aws_s3_bucket" "destination" {
  bucket        = local.bucket_name
  force_destroy = true

  tags = {
    Project        = "cloud-vuln-range"
    VulnTestCaseId = "VULN-S3-007"
    Role           = "replication-destination"
  }
}

# Pinned explicitly rather than relying on the current AWS default for new
# buckets (BucketOwnerEnforced) - this sidesteps ACL/ownership handling for
# replicated objects entirely, so no access_control_translation block is
# needed on the source side's replication rule.
resource "aws_s3_bucket_ownership_controls" "destination" {
  bucket = aws_s3_bucket.destination.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "destination" {
  bucket = aws_s3_bucket.destination.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "destination" {
  bucket = aws_s3_bucket.destination.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowReplicationFromSourceAccount"
      Effect = "Allow"
      Principal = {
        AWS = local.source_role_arn
      }
      Action = [
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags",
      ]
      Resource = "${aws_s3_bucket.destination.arn}/*"
    }]
  })
}

output "destination_bucket_arn" {
  value = aws_s3_bucket.destination.arn
}
