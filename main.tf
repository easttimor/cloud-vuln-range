module "iam_trust_policy_vulns" {
  source = "./test_cases/iam_trust_policy"

  example_external_account_id = var.example_external_account_id
  org_id                      = var.org_id
}

module "s3_exposure_vulns" {
  source = "./test_cases/s3_exposure"

  account_id                         = var.sandbox_account_id
  example_external_account_id        = var.example_external_account_id
  replication_destination_account_id = var.replication_destination_account_id
  org_id                             = var.org_id
}

module "sqs_exposure_vulns" {
  source = "./test_cases/sqs_exposure"

  account_id                  = var.sandbox_account_id
  example_external_account_id = var.example_external_account_id
  org_id                      = var.org_id
}

module "kms_key_policy_vulns" {
  source = "./test_cases/kms_key_policy"

  account_id = var.sandbox_account_id
}
