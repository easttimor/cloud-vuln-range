output "role_arns" {
  value = {
    "VULN-IAM-001" = module.iam_trust_external_account.role_arn
    "VULN-IAM-002" = module.iam_trust_any_account.role_arn
    "VULN-IAM-003" = module.iam_trust_org_wide.role_arn
    "VULN-IAM-004" = module.iam_trust_principal_tag.role_arn
  }
}
