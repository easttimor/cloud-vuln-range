terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Separate, local state - this targets a different AWS account entirely,
  # outside the org the rest of this project lives in. Intentionally not
  # wired into the root module: the root provider is hard-locked to the
  # sandbox account via allowed_account_ids and has no credentials for this
  # account at all.
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  # Hard guardrail, mirroring the root project: refuse to apply against
  # anything but the intended destination account.
  allowed_account_ids = [var.destination_account_id]
}
