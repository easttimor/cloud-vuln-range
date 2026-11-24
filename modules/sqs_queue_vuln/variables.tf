variable "test_case_id" {
  description = "Catalog ID for this test case, e.g. VULN-SQS-001. Baked into the queue name."
  type        = string
}

variable "account_id" {
  description = "Sandbox account ID, baked into the queue name for consistency with the rest of the catalog."
  type        = string
}

variable "description" {
  description = "Human-readable description of the vulnerability this queue demonstrates."
  type        = string
}

variable "expected_access_analyzer_finding" {
  description = "Hypothesis for whether IAM Access Analyzer (external access analyzer) flags this queue: yes, no, partial, or unverified. Not a guarantee - verify empirically once an analyzer is running."
  type        = string
  default     = "unverified"
}

variable "expected_cspm_finding" {
  description = "Hypothesis for whether a generic third-party CSPM flags this queue: yes, no, partial, or unverified."
  type        = string
  default     = "unverified"
}

variable "detection_control" {
  description = "Short name of the detection control this test case is meant to validate, once one is wired up."
  type        = string
  default     = "unassigned"
}

variable "extra_tags" {
  description = "Additional tags to merge onto the queue."
  type        = map(string)
  default     = {}
}
