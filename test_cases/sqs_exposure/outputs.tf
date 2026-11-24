output "queue_arns" {
  value = {
    "VULN-SQS-001" = module.sqs_external_account_trust.queue_arn
    "VULN-SQS-002" = module.sqs_any_account.queue_arn
    "VULN-SQS-003" = module.sqs_org_wide.queue_arn
    "VULN-SQS-004" = module.sqs_principal_tag.queue_arn
  }
}
