variable "test_case_id" {
  description = "Catalog ID for this test case, e.g. VULN-KMS-001. Baked into the key alias."
  type        = string
}

variable "account_id" {
  description = "Sandbox account ID, baked into the key alias for consistency with the rest of the catalog."
  type        = string
}

variable "description" {
  description = "Human-readable description of the vulnerability this key demonstrates."
  type        = string
}

variable "key_policy" {
  description = <<-EOT
    Full key policy JSON, caller-supplied - like IAM trust policies (and
    unlike S3/SQS resource policies), KMS key policies conventionally omit
    any Resource element (it's implicitly this key), so there's no
    self-reference problem passing this straight into aws_kms_key at
    creation time. Must include a statement granting the account itself
    (root) sufficient permissions to administer the key via IAM policies -
    AWS requires this; omitting it can lock even the account's own admins
    out of managing the key.
  EOT
  type        = string
}

variable "expected_access_analyzer_finding" {
  description = "Hypothesis for whether IAM Access Analyzer (external access analyzer) flags this key: yes, no, partial, or unverified. Not a guarantee - verify empirically once an analyzer is running."
  type        = string
  default     = "unverified"
}

variable "expected_cspm_finding" {
  description = "Hypothesis for whether a generic third-party CSPM flags this key: yes, no, partial, or unverified."
  type        = string
  default     = "unverified"
}

variable "detection_control" {
  description = "Short name of the detection control this test case is meant to validate, once one is wired up."
  type        = string
  default     = "unassigned"
}

variable "deletion_window_in_days" {
  description = "Minimum allowed by AWS is 7; kept short since this is a disposable test range."
  type        = number
  default     = 7
}

variable "extra_tags" {
  description = "Additional tags to merge onto the key."
  type        = map(string)
  default     = {}
}
