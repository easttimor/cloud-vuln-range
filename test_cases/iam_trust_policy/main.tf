# Catalog: IAM role external trust policy misconfigurations.
# Every role in this file has zero attached permissions — the entire point is
# the trust (AssumeRole) policy, not what the role can do once assumed.
# See ../../README.md for the full catalog with detection-control mappings.

# VULN-IAM-001: Trust policy scoped to a single named external AWS account,
# with no ExternalId and no other condition. example_external_account_id is
# meant to be set to a real SaaS vendor's published integration account ID
# (e.g. the account a vendor's AWS integration asks customers to trust) -
# IAM validates that principal account IDs correspond to real accounts, so
# a made-up placeholder is rejected at CreateRole time (see the README).
# Represents the classic "vendor/SaaS cross-account role done wrong"
# pattern: anyone holding credentials in that account's root/any
# IAM-principal (i.e. the vendor itself, or anyone who compromises it) can
# assume this role with no ExternalId to scope it to this specific
# customer.
module "iam_trust_external_account" {
  source = "../../modules/iam_trust_vuln"

  name         = "vuln-iam-trust-external-account"
  test_case_id = "VULN-IAM-001"
  description  = "Trust policy allows any principal in a named external AWS account to assume this role with no ExternalId condition."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.example_external_account_id}:root"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# VULN-IAM-002: Trust policy open to literally any AWS account on earth.
# Principal: "AWS": "*" with no condition. This is the most severe variant —
# any IAM principal in any account, including attacker-controlled accounts,
# can assume this role.
module "iam_trust_any_account" {
  source = "../../modules/iam_trust_vuln"

  name         = "vuln-iam-trust-any-account"
  test_case_id = "VULN-IAM-002"
  description  = "Trust policy allows any AWS principal in any AWS account to assume this role with no restricting condition."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "*"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# VULN-IAM-003: Trust policy open to any account inside this AWS Organization.
# Principal: "AWS": "*" constrained by aws:PrincipalOrgID. Narrower than
# VULN-IAM-002, but still trusts every account in the org, including ones
# added later and any compromised member account.
module "iam_trust_org_wide" {
  source = "../../modules/iam_trust_vuln"

  name         = "vuln-iam-trust-org-wide"
  test_case_id = "VULN-IAM-003"
  description  = "Trust policy allows any AWS principal in any account belonging to AWS Organization ${var.org_id} to assume this role."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "*"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = var.org_id
        }
      }
    }]
  })
}

# VULN-IAM-004: Trust policy open to any account, constrained only by a
# principal tag condition. Looks scoped at a glance, but aws:PrincipalTag
# is a tag on the CALLING principal in the CALLING account — an admin in any
# external account can self-apply the matching tag to their own IAM
# user/role and satisfy the condition. This is a "looks constrained, isn't"
# control that's a good test of whether a review process (human or
# automated) catches the difference between "scoped" and "tagged".
module "iam_trust_principal_tag" {
  source = "../../modules/iam_trust_vuln"

  name         = "vuln-iam-trust-principal-tag"
  test_case_id = "VULN-IAM-004"
  description  = "Trust policy allows any AWS account constrained only by a self-assignable aws:PrincipalTag condition PartnerAccess=trusted rather than an account/org boundary."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "*"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:PrincipalTag/PartnerAccess" = "trusted"
        }
      }
    }]
  })
}
