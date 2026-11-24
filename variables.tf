variable "aws_profile" {
  description = "AWS CLI/SSO profile used to deploy into the sandbox account."
  type        = string
}

variable "aws_region" {
  description = "Default AWS region for the sandbox account."
  type        = string
  default     = "us-east-1"
}

variable "sandbox_account_id" {
  description = "The sandbox account ID. All applies are hard-locked to this account."
  type        = string
}

variable "org_id" {
  description = "AWS Organizations ID that this sandbox account belongs to."
  type        = string
}

variable "example_external_account_id" {
  description = <<-EOT
    AWS account ID representing a real external third party used as the
    "named external account" test case. IAM validates that principal
    account IDs in trust policies correspond to real accounts, so this must
    be a real account ID rather than a placeholder.
  EOT
  type        = string
}

variable "replication_destination_account_id" {
  description = <<-EOT
    A real AWS account you own OUTSIDE this organization, used as the
    destination for the cross-account replication test case (VULN-S3-007).
    This project has no credentials for that account - see
    test_cases/s3_exposure/destination_account/ for the matching config to
    apply there.
  EOT
  type        = string
}
