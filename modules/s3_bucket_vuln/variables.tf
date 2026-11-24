variable "test_case_id" {
  description = "Catalog ID for this test case, e.g. VULN-S3-001. Baked into the bucket name."
  type        = string
}

variable "account_id" {
  description = "Sandbox account ID, baked into the bucket name for global-uniqueness."
  type        = string
}

variable "description" {
  description = "Human-readable description of the vulnerability this bucket demonstrates."
  type        = string
}

variable "expected_access_analyzer_finding" {
  description = "Hypothesis for whether IAM Access Analyzer (external access analyzer) flags this bucket: yes, no, partial, or unverified. Not a guarantee — verify empirically once an analyzer is running."
  type        = string
  default     = "unverified"
}

variable "expected_cspm_finding" {
  description = "Hypothesis for whether a generic third-party CSPM flags this bucket: yes, no, partial, or unverified."
  type        = string
  default     = "unverified"
}

variable "detection_control" {
  description = "Short name of the detection control this test case is meant to validate, once one is wired up."
  type        = string
  default     = "unassigned"
}

variable "enable_acls" {
  description = "Switch bucket ownership controls to BucketOwnerPreferred so ACLs (bucket- or object-level) are usable at all. Required if bucket_acl is set, or if a caller intends to set object-level ACLs on objects in this bucket."
  type        = bool
  default     = false
}

variable "bucket_acl" {
  description = "Canned ACL to apply to the bucket itself, e.g. public-read. Leave null to leave the bucket's own ACL at the default (private). Requires enable_acls = true."
  type        = string
  default     = null
}

variable "block_public_acls" {
  type    = bool
  default = true
}

variable "block_public_policy" {
  type    = bool
  default = true
}

variable "ignore_public_acls" {
  type    = bool
  default = true
}

variable "restrict_public_buckets" {
  type    = bool
  default = true
}

variable "enable_versioning" {
  description = "Enable bucket versioning. Required for S3 replication; off by default since most test cases don't need it."
  type        = bool
  default     = false
}

variable "force_destroy" {
  description = "Allow terraform destroy to delete this bucket even if it has objects in it. Default true since this is a disposable test range."
  type        = bool
  default     = true
}

variable "extra_tags" {
  description = "Additional tags to merge onto the bucket."
  type        = map(string)
  default     = {}
}
