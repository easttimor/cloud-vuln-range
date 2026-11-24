variable "account_id" {
  description = "Sandbox account ID, used for queue naming."
  type        = string
}

variable "example_external_account_id" {
  description = "Real external AWS account ID used as the 3rd-party principal in cross-account trust test cases."
  type        = string
}

variable "org_id" {
  description = "AWS Organizations ID that the sandbox account belongs to."
  type        = string
}
