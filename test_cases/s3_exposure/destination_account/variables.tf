variable "aws_profile" {
  description = "AWS CLI profile with credentials for the destination account. No default - this account is outside the org, so there's no shared SSO session to assume."
  type        = string
}

variable "aws_region" {
  description = "Region for the destination bucket. Cross-region replication is fine, but keeping it in us-east-1 for simplicity to match the source."
  type        = string
  default     = "us-east-1"
}

variable "destination_account_id" {
  description = "This account's own ID. Used only for the allowed_account_ids guardrail and to build the bucket name. No default - fill in via -var or a local tfvars file, never commit the real value."
  type        = string
}

variable "source_account_id" {
  description = "The cloud-vuln-range sandbox account ID that owns the replication source bucket and role. No default - fill in via -var or a local tfvars file, never commit the real value."
  type        = string
}

variable "source_replication_role_name" {
  description = "Name of the IAM role in the source account that performs the replication (see test_cases/s3_exposure/main.tf, aws_iam_role.s3_replication)."
  type        = string
  default     = "vuln-s3-007-replication-role"
}
