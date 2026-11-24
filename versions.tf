terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Local state for now. This is a disposable detection-testing sandbox account;
  # move to a remote backend (S3 + DynamoDB lock) if that changes.
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  # Assume the project's deploy role, which carries the
  # aws:PrincipalTag/etotag-scp-s3=true tag the org-wide base-deny SCP
  # requires for s3:CreateBucket. See deploy_role.tf.
  assume_role {
    role_arn = "arn:aws:iam::${var.sandbox_account_id}:role/cloud-vuln-range-deploy"
  }

  # Hard guardrail: refuse to apply against anything but the sandbox account.
  allowed_account_ids = [var.sandbox_account_id]

  default_tags {
    tags = {
      Project = "cloud-vuln-range"
    }
  }
}
