# Intentionally vulnerable KMS key: one customer-managed key with a
# caller-supplied key policy. Same shape as modules/iam_trust_vuln - the
# policy is passed straight in at creation time since KMS key policies
# (like IAM trust policies) don't need the resource's own ARN in a
# Resource field.

locals {
  alias_name = lower("alias/cloud-vuln-range-${var.test_case_id}-${var.account_id}")
}

resource "aws_kms_key" "this" {
  description             = var.description
  policy                  = var.key_policy
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = true

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

resource "aws_kms_alias" "this" {
  name          = local.alias_name
  target_key_id = aws_kms_key.this.key_id
}
