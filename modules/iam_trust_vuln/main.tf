# Intentionally vulnerable IAM role: trust policy only, zero permissions attached.
# No aws_iam_role_policy / aws_iam_role_policy_attachment resources should ever be
# added here — the vulnerability under test is the trust relationship itself, not
# what the role can do once assumed.

resource "aws_iam_role" "this" {
  name                 = var.name
  assume_role_policy   = var.assume_role_policy
  max_session_duration = 3600

  tags = merge(
    {
      Project          = "cloud-vuln-range"
      VulnTestCaseId   = var.test_case_id
      VulnDescription  = var.description
      DetectionControl = var.detection_control
      ManagedBy        = "terraform"
    },
    var.extra_tags
  )
}
