variable "account_id" {
  description = "Sandbox account ID, used for bucket naming and access point ownership."
  type        = string
}

variable "example_external_account_id" {
  description = "Real external AWS account ID used as the 3rd-party principal in cross-account trust test cases."
  type        = string
}

variable "replication_destination_account_id" {
  description = "Real AWS account outside this org, used as the replication destination for VULN-S3-007."
  type        = string
}

variable "org_id" {
  description = "AWS Organizations ID that the sandbox account belongs to."
  type        = string
}
