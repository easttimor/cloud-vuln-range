# Bootstrap role, not a vulnerability test case.
#
# An org-wide SCP denies s3:CreateBucket everywhere in this AWS
# Organization unless the calling principal carries the tag
# aws:PrincipalTag/etotag-scp-s3=true. No principal in the org carries that
# tag by default. Rather than weakening that org-wide guardrail, this role
# is the explicit, scoped opt-in it's designed for: one role, in this
# sandbox account only, tagged to satisfy the gate. versions.tf's provider
# assumes into this role for all applies. If your org doesn't have a
# similar guardrail, this role (and the assume_role block in versions.tf)
# isn't needed - a plain admin session can create buckets directly.
resource "aws_iam_role" "deploy" {
  name = "cloud-vuln-range-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.sandbox_account_id}:root"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    "etotag-scp-s3" = "true"
    Project         = "cloud-vuln-range"
    ManagedBy       = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "deploy_admin" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
