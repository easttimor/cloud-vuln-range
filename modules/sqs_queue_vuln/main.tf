# Intentionally vulnerable SQS queue: just the queue and its tags. Queue
# policies vary per test case and need the queue's own ARN in their
# Resource field, so (same reasoning as modules/s3_bucket_vuln) callers
# attach aws_sqs_queue_policy themselves, wired to this module's outputs,
# rather than this module owning policy content.

locals {
  queue_name = lower("cloud-vuln-range-${var.test_case_id}-${var.account_id}")
}

resource "aws_sqs_queue" "this" {
  name = local.queue_name

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
