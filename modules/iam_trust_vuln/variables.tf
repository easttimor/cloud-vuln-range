variable "name" {
  description = "Name of the IAM role (also used as the test case identifier)."
  type        = string
}

variable "assume_role_policy" {
  description = "JSON trust (assume role) policy document for the role."
  type        = string
}

variable "description" {
  description = "Human-readable description of the vulnerability this role demonstrates."
  type        = string
}

variable "test_case_id" {
  description = "Catalog ID for this test case, e.g. VULN-IAM-001."
  type        = string
}

variable "detection_control" {
  description = "Short name of the detection control this test case is meant to validate (e.g. the GuardDuty finding type or custom Config rule name)."
  type        = string
  default     = "unassigned"
}

variable "extra_tags" {
  description = "Additional tags to merge onto the role."
  type        = map(string)
  default     = {}
}
