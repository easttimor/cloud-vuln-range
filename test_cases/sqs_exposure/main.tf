# Catalog: SQS queue policy misconfigurations. Direct SQS analogue of
# test_cases/iam_trust_policy - same four shapes (named external account,
# any account, org-wide, weak principal-tag condition), applied to a
# resource-based queue policy instead of an IAM trust policy. See
# ../../README.md for the full catalog with detection-control mappings.

# ---------------------------------------------------------------------------
# VULN-SQS-001: Queue policy grants one named external AWS account
# (example_external_account_id, the same real third-party account used in
# VULN-IAM-001 and VULN-S3-002) permission to send, receive, delete, and
# read attributes - the "vendor queue integration done wrong" pattern, no
# further condition scoping it to a specific expected use.
# ---------------------------------------------------------------------------
module "sqs_external_account_trust" {
  source = "../../modules/sqs_queue_vuln"

  test_case_id = "VULN-SQS-001"
  account_id   = var.account_id
  description  = "Queue policy grants send receive delete and read access to a named external AWS account with no condition"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "yes"
}

resource "aws_sqs_queue_policy" "sqs_external_account_trust" {
  queue_url = module.sqs_external_account_trust.queue_url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ExternalAccountQueueAccess"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.example_external_account_id}:root"
      }
      Action = [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
      ]
      Resource = module.sqs_external_account_trust.queue_arn
    }]
  })
}

# ---------------------------------------------------------------------------
# VULN-SQS-002: Queue policy grants Principal "*" Action "sqs:*" - any AWS
# principal in any account can send, receive, purge, delete, or reconfigure
# this queue. Most severe variant, most universally detected.
#
# Verified empirically, and worth noting for the catalog as a whole: unlike
# S3, SQS has no concept of an unauthenticated/anonymous request at all -
# every SQS API call requires a valid SigV4 signature regardless of what
# the queue policy says. An anonymous (--no-sign-request) SendMessage
# against this queue fails ("Access to the resource ... is denied"), while
# the identical call signed with any real AWS credentials succeeds. So
# "Principal *" on an SQS queue policy means "any authenticated AWS
# principal in any account," never literal internet-anonymous - true for
# every test case in this file, not just this one.
# ---------------------------------------------------------------------------
module "sqs_any_account" {
  source = "../../modules/sqs_queue_vuln"

  test_case_id = "VULN-SQS-002"
  account_id   = var.account_id
  description  = "Queue policy grants Principal wildcard Action wildcard full public access to the queue"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "yes"
}

resource "aws_sqs_queue_policy" "sqs_any_account" {
  queue_url = module.sqs_any_account.queue_url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicFullAccess"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = module.sqs_any_account.queue_arn
    }]
  })
}

# ---------------------------------------------------------------------------
# VULN-SQS-003: Queue policy open to any account inside this AWS
# Organization (aws:PrincipalOrgID), the SQS analogue of VULN-IAM-003.
# Narrower than VULN-SQS-002, but still trusts every current and future
# member account in the org.
# ---------------------------------------------------------------------------
module "sqs_org_wide" {
  source = "../../modules/sqs_queue_vuln"

  test_case_id = "VULN-SQS-003"
  account_id   = var.account_id
  description  = "Queue policy allows any AWS principal in any account belonging to the AWS Organization full access to this queue"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"
}

resource "aws_sqs_queue_policy" "sqs_org_wide" {
  queue_url = module.sqs_org_wide.queue_url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgWideFullAccess"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = module.sqs_org_wide.queue_arn
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = var.org_id
        }
      }
    }]
  })
}

# ---------------------------------------------------------------------------
# VULN-SQS-004: Queue policy open to any account, constrained only by a
# self-assignable aws:PrincipalTag condition - the SQS analogue of
# VULN-IAM-004. Looks scoped, isn't a real boundary: any external account's
# admin can tag their own calling principal to match and satisfy the
# condition.
# ---------------------------------------------------------------------------
module "sqs_principal_tag" {
  source = "../../modules/sqs_queue_vuln"

  test_case_id = "VULN-SQS-004"
  account_id   = var.account_id
  description  = "Queue policy allows any AWS account constrained only by a self-assignable aws PrincipalTag condition rather than an account or org boundary"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"
}

resource "aws_sqs_queue_policy" "sqs_principal_tag" {
  queue_url = module.sqs_principal_tag.queue_url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PrincipalTagGatedAccess"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = module.sqs_principal_tag.queue_arn
      Condition = {
        StringEquals = {
          "aws:PrincipalTag/PartnerAccess" = "trusted"
        }
      }
    }]
  })
}
