# Catalog: S3 exposure misconfigurations. See ../../README.md for the full
# catalog with detection-control mappings and the expected-finding tag
# legend. Every bucket tags itself with VulnTestCaseId / VulnDescription /
# ExpectedAccessAnalyzerFinding / ExpectedCspmFinding / DetectionControl —
# see modules/s3_bucket_vuln. Those "Expected*" tags are hypotheses about
# what a detection control *should* flag, not verified fact — treat this
# whole file as something to validate empirically once analyzers/CSPM tools
# are pointed at this account, and correct the tags based on what you
# actually observe.

# ---------------------------------------------------------------------------
# VULN-S3-001: Bucket policy grants Principal "*" / Action "*" — full public
# read+write+delete on the bucket and every object in it. The most severe
# and most universally-detected variant; every CSPM and IAM Access Analyzer
# should flag this.
# ---------------------------------------------------------------------------
module "s3_public_policy" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-001"
  account_id   = var.account_id
  description  = "Bucket policy grants Principal wildcard Action wildcard full public read write and delete access to the bucket and all objects"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "yes"

  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "s3_public_policy" {
  bucket = module.s3_public_policy.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicFullAccess"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        module.s3_public_policy.bucket_arn,
        "${module.s3_public_policy.bucket_arn}/*",
      ]
    }]
  })

  depends_on = [module.s3_public_policy]
}

# ---------------------------------------------------------------------------
# VULN-S3-002: Bucket policy trusts one named external AWS account for read
# access, no further condition. Reuses the same example_external_account_id
# as VULN-IAM-001/VULN-SQS-001. Not "public" by AWS's own definition (a
# named-account grant doesn't trip Block Public Access), so default BPA
# settings are left in place deliberately — this test case is specifically
# about whether tools catch over-broad *cross-account* trust even when BPA
# looks fully locked down.
# ---------------------------------------------------------------------------
module "s3_external_account_trust" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-002"
  account_id   = var.account_id
  description  = "Bucket policy grants read access to a named external AWS account with no ExternalId condition"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "yes"
}

resource "aws_s3_bucket_policy" "s3_external_account_trust" {
  bucket = module.s3_external_account_trust.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ExternalAccountReadAccess"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.example_external_account_id}:root"
      }
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
      ]
      Resource = [
        module.s3_external_account_trust.bucket_arn,
        "${module.s3_external_account_trust.bucket_arn}/*",
      ]
    }]
  })

  depends_on = [module.s3_external_account_trust]
}

# ---------------------------------------------------------------------------
# VULN-S3-003: Bucket-level canned ACL set to public-read. No bucket policy
# involved at all — a pure legacy-ACL exposure path. IAM Access Analyzer for
# S3 does evaluate bucket ACLs, so this should still be caught by it even
# though it predates bucket policies entirely.
# ---------------------------------------------------------------------------
module "s3_public_acl" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-003"
  account_id   = var.account_id
  description  = "Bucket-level canned ACL set to public-read with no bucket policy involved"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "yes"

  enable_acls = true
  bucket_acl  = "public-read"

  block_public_acls  = false
  ignore_public_acls = false
}

# ---------------------------------------------------------------------------
# VULN-S3-004: The bucket itself is private (no policy, no bucket ACL), but
# one object inside it carries a public-read object ACL. This is a known
# blind spot: IAM Access Analyzer for S3 evaluates bucket policies, bucket
# ACLs, and access point policies — it does not enumerate individual object
# ACLs. Most CSPMs don't enumerate per-object ACLs either (cost-prohibitive
# at scale), so this is a good test of whether a given tool goes deeper than
# bucket-level posture.
# ---------------------------------------------------------------------------
module "s3_public_object_acl" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-004"
  account_id   = var.account_id
  description  = "Bucket is private. One object inside carries a public-read object ACL that IAM Access Analyzer for S3 does not evaluate"

  expected_access_analyzer_finding = "no"
  expected_cspm_finding            = "partial"

  enable_acls = true

  block_public_acls  = false
  ignore_public_acls = false
}

resource "aws_s3_object" "s3_public_object_acl" {
  bucket  = module.s3_public_object_acl.bucket_id
  key     = "vuln-s3-004-public-object.txt"
  content = "VULN-S3-004: this object has a public-read object ACL even though the bucket itself is private."
  acl     = "public-read"

  tags = {
    Project        = "cloud-vuln-range"
    VulnTestCaseId = "VULN-S3-004"
  }

  # Needs ownership_controls (inside the module) switched off
  # BucketOwnerEnforced before an object-level ACL is even acceptable;
  # depending only on bucket_id doesn't capture that sibling resource.
  depends_on = [module.s3_public_object_acl]
}

# ---------------------------------------------------------------------------
# VULN-S3-005: Public via S3 Access Point policy, NOT the bucket policy.
# The bucket policy only delegates: it trusts requests arriving through any
# access point owned by this account (the standard
# s3:DataAccessPointAccount pattern), which is not itself classified as
# "public" by AWS and is unaffected by the bucket's own Block Public Access
# settings. The access point's OWN policy is what's actually wide open
# (Principal "*"). Both the bucket's and the access point's Block Public
# Access settings must be relaxed for the public grant to actually be
# reachable — AWS enforces the more restrictive of the two.
#
# Verified empirically post-apply: Access Points reject every unsigned
# request outright (InvalidRequest: "use Signature Version 4"), regardless
# of policy content. So Principal "*" on an access point policy means "any
# AWS principal that can produce a valid SigV4 signature" — any AWS
# customer on earth, but not a literally anonymous/unauthenticated caller
# the way a public bucket policy or bucket ACL is. That's a real
# distinction a "is this bucket reachable with no credentials at all"-style
# CSPM check can miss entirely, while IAM Access Analyzer's external-access
# model (which reasons about any-external-principal reachability, not raw
# anonymity) should still flag it.
# ---------------------------------------------------------------------------
module "s3_public_access_point" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-005"
  account_id   = var.account_id
  description  = "Bucket policy only delegates to access points owned by this account. The access points own policy grants public read access"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"

  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "s3_public_access_point" {
  bucket = module.s3_public_access_point.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DelegateToAccountAccessPoints"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        module.s3_public_access_point.bucket_arn,
        "${module.s3_public_access_point.bucket_arn}/*",
      ]
      Condition = {
        StringEquals = {
          "s3:DataAccessPointAccount" = var.account_id
        }
      }
    }]
  })

  depends_on = [module.s3_public_access_point]
}

resource "aws_s3_access_point" "s3_public_access_point" {
  name       = "vuln-s3-005-ap"
  bucket     = module.s3_public_access_point.bucket_id
  account_id = var.account_id

  public_access_block_configuration {
    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
  }

  depends_on = [aws_s3_bucket_policy.s3_public_access_point]
}

resource "aws_s3control_access_point_policy" "s3_public_access_point" {
  access_point_arn = aws_s3_access_point.s3_public_access_point.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadViaAccessPoint"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_access_point.s3_public_access_point.arn}/object/*"
    }]
  })
}

# ---------------------------------------------------------------------------
# VULN-S3-006: Same delegation shape as VULN-S3-005 (bucket policy just
# trusts this account's access points, which is not "public"), but the
# access point's own policy grants read access to one named external AWS
# account rather than the world. The bucket is never "public" here at all —
# this tests whether a tool follows the delegation through to the access
# point policy to notice the cross-account grant, the same way VULN-S3-002
# tests it for a plain bucket policy.
# ---------------------------------------------------------------------------
module "s3_external_access_point" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-006"
  account_id   = var.account_id
  description  = "Bucket policy only delegates to access points owned by this account. The access points own policy grants read access to a named external AWS account"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"
}

resource "aws_s3_bucket_policy" "s3_external_access_point" {
  bucket = module.s3_external_access_point.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DelegateToAccountAccessPoints"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        module.s3_external_access_point.bucket_arn,
        "${module.s3_external_access_point.bucket_arn}/*",
      ]
      Condition = {
        StringEquals = {
          "s3:DataAccessPointAccount" = var.account_id
        }
      }
    }]
  })

  depends_on = [module.s3_external_access_point]
}

resource "aws_s3_access_point" "s3_external_access_point" {
  name       = "vuln-s3-006-ap"
  bucket     = module.s3_external_access_point.bucket_id
  account_id = var.account_id

  depends_on = [aws_s3_bucket_policy.s3_external_access_point]
}

resource "aws_s3control_access_point_policy" "s3_external_access_point" {
  access_point_arn = aws_s3_access_point.s3_external_access_point.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ExternalAccountReadViaAccessPoint"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.example_external_account_id}:root"
      }
      Action   = "s3:GetObject"
      Resource = "${aws_s3_access_point.s3_external_access_point.arn}/object/*"
    }]
  })
}

# ---------------------------------------------------------------------------
# VULN-S3-007: Cross-account replication to a bucket in a real AWS account
# OUTSIDE this organization (owned by the same person but not a member of
# it - no org-wide guardrail applies to it). This project has no
# credentials for that account, so only the source side is built here. The
# matching destination-side config lives in ./destination_account/ and
# must be applied separately, with credentials for that account - see this
# project's README for the handshake details.
#
# IAM Access Analyzer does not evaluate replication configuration at all,
# so this is expected to be a clean blind spot for it specifically, even
# though the data is leaving the org just as surely as any of the other
# test cases here.
# ---------------------------------------------------------------------------
module "s3_replication_source" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-007"
  account_id   = var.account_id
  description  = "Bucket replicates objects to a bucket in a real AWS account outside this org"

  expected_access_analyzer_finding = "no"
  expected_cspm_finding            = "partial"

  enable_versioning = true
}

locals {
  replication_destination_bucket_name = "cloud-vuln-range-vuln-s3-007-dest-${var.replication_destination_account_id}"
  replication_destination_bucket_arn  = "arn:aws:s3:::${local.replication_destination_bucket_name}"
}

resource "aws_iam_role" "s3_replication" {
  name = "vuln-s3-007-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Project        = "cloud-vuln-range"
    VulnTestCaseId = "VULN-S3-007"
  }
}

resource "aws_iam_role_policy" "s3_replication" {
  name = "vuln-s3-007-replication-policy"
  role = aws_iam_role.s3_replication.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SourceBucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
        ]
        Resource = [
          module.s3_replication_source.bucket_arn,
          "${module.s3_replication_source.bucket_arn}/*",
        ]
      },
      {
        Sid    = "DestinationBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
        ]
        Resource = "${local.replication_destination_bucket_arn}/*"
      },
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "s3_replication_source" {
  bucket = module.s3_replication_source.bucket_id
  role   = aws_iam_role.s3_replication.arn

  rule {
    id     = "replicate-to-external-account"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket  = local.replication_destination_bucket_arn
      account = var.replication_destination_account_id
    }
  }

  # Needs bucket versioning (enabled inside the module) in place first, and
  # the role's permissions to already exist before S3 will accept the
  # replication config.
  depends_on = [module.s3_replication_source, aws_iam_role_policy.s3_replication]
}

# ---------------------------------------------------------------------------
# VULN-S3-008: Public WRITE, not read. Bucket policy grants Principal "*"
# Action s3:PutObject only - no read grant at all. Distinguishes tools/
# pipelines that alert on public read exposure from ones that also catch
# public write (tamper / data-poisoning / malware-staging risk), which in
# practice are sometimes wired up differently even within the same tool.
# ---------------------------------------------------------------------------
module "s3_public_write" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-008"
  account_id   = var.account_id
  description  = "Bucket policy grants Principal wildcard Action PutObject public write access with no public read grant"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "yes"

  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "s3_public_write" {
  bucket = module.s3_public_write.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicWriteOnly"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${module.s3_public_write.bucket_arn}/*"
    }]
  })

  depends_on = [module.s3_public_write]
}

# ---------------------------------------------------------------------------
# VULN-S3-009: Read access gated only by an aws:Referer condition instead of
# a real identity boundary - the S3 analogue of VULN-IAM-004. Referer is a
# client-supplied HTTP header, trivially spoofed by anyone, so this is
# "security" in appearance only.
#
# Confirmed empirically: tried this first at default Block Public Access
# (all true) and AWS rejected the PutBucketPolicy call outright -
# "AccessDenied: ... public policies are prevented by the BlockPublicPolicy
# setting" - the same rejection a bare Principal "*" grant gets. AWS's own
# public-policy classifier does not treat aws:Referer as a real
# restriction, and neither should you. BPA is relaxed below only because
# that confirmation already happened once.
# ---------------------------------------------------------------------------
module "s3_weak_condition" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-009"
  account_id   = var.account_id
  description  = "Bucket policy grants Principal wildcard read access gated only by a spoofable aws Referer header condition"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"

  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "s3_weak_condition" {
  bucket = module.s3_weak_condition.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "RefererGatedPublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${module.s3_weak_condition.bucket_arn}/*"
      Condition = {
        StringLike = {
          "aws:Referer" = "https://trusted-partner.example.com/*"
        }
      }
    }]
  })

  depends_on = [module.s3_weak_condition]
}

resource "aws_s3_object" "s3_weak_condition" {
  bucket  = module.s3_weak_condition.bucket_id
  key     = "vuln-s3-009-referer-gated-object.txt"
  content = "VULN-S3-009: readable only by requests that spoof the expected Referer header."

  tags = {
    Project        = "cloud-vuln-range"
    VulnTestCaseId = "VULN-S3-009"
  }

  depends_on = [module.s3_weak_condition]
}

# ---------------------------------------------------------------------------
# VULN-S3-010: Bucket policy open to any account inside this AWS
# Organization (aws:PrincipalOrgID), the direct S3 analogue of VULN-IAM-003
# and VULN-SQS-003. A real gap the catalog had until now - IAM and SQS both
# had an org-wide shape, plain S3 bucket policies didn't.
# ---------------------------------------------------------------------------
module "s3_org_wide" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-010"
  account_id   = var.account_id
  description  = "Bucket policy allows any AWS principal in any account belonging to the AWS Organization full read access"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"
}

resource "aws_s3_bucket_policy" "s3_org_wide" {
  bucket = module.s3_org_wide.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgWideReadAccess"
      Effect    = "Allow"
      Principal = "*"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
      ]
      Resource = [
        module.s3_org_wide.bucket_arn,
        "${module.s3_org_wide.bucket_arn}/*",
      ]
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = var.org_id
        }
      }
    }]
  })

  depends_on = [module.s3_org_wide]
}

# ---------------------------------------------------------------------------
# VULN-S3-011: Bucket-level canned ACL set to authenticated-read, NOT
# public-read (VULN-S3-003 already covers public-read). AuthenticatedUsers
# is not "logged into my app" - it is any AWS principal with any AWS
# account whatsoever, a distinction that has caused real large-scale
# breaches when teams mistook it for an app-level auth boundary. Distinct
# grantee URI from AllUsers, so a scanner keyed specifically on the
# public-read/AllUsers grant can plausibly miss this one.
# ---------------------------------------------------------------------------
module "s3_authenticated_users_acl" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-011"
  account_id   = var.account_id
  description  = "Bucket-level canned ACL set to authenticated-read granting any AWS account read access often mistaken for app-level authentication"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"

  enable_acls = true
  bucket_acl  = "authenticated-read"

  block_public_acls  = false
  ignore_public_acls = false
}

# ---------------------------------------------------------------------------
# VULN-S3-012: CloudFront origin-access bypass. The bucket is meant to be
# reachable ONLY through this CloudFront distribution via Origin Access
# Control (OAC) - that part is configured correctly (bucket policy trusts
# cloudfront.amazonaws.com scoped to this exact distribution's ARN). The
# vulnerability is a SECOND bucket policy statement that independently
# grants public s3:GetObject with no condition at all, bypassing
# CloudFront - and with it, the CDN's caching, logging, and any WAF/edge
# controls - entirely. Nothing is wrong with the CloudFront/OAC grant
# itself; the bug is the extra statement sitting next to it.
#
# CloudFront settings below are deliberately cost-minimized: PriceClass_100
# (fewest edge locations), the free default *.cloudfront.net certificate
# (no ACM cert, no custom domain), no access logging, no WAF, no Lambda@Edge
# / CloudFront Functions, no custom error pages.
# ---------------------------------------------------------------------------
module "s3_cloudfront_bypass" {
  source = "../../modules/s3_bucket_vuln"

  test_case_id = "VULN-S3-012"
  account_id   = var.account_id
  description  = "Bucket is meant to be reachable only via CloudFront OAC but a second bucket policy statement independently grants public read access bypassing it entirely"

  expected_access_analyzer_finding = "yes"
  expected_cspm_finding            = "partial"

  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_cloudfront_origin_access_control" "s3_cloudfront_bypass" {
  name                              = "vuln-s3-012-oac"
  description                       = "OAC for VULN-S3-012"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "s3_cloudfront_bypass" {
  enabled             = true
  comment             = "cloud-vuln-range VULN-S3-012"
  price_class         = "PriceClass_100"
  is_ipv6_enabled     = true
  retain_on_delete    = false
  wait_for_deployment = true

  origin {
    domain_name              = module.s3_cloudfront_bypass.bucket_regional_domain_name
    origin_id                = "s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3_cloudfront_bypass.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Project        = "cloud-vuln-range"
    VulnTestCaseId = "VULN-S3-012"
  }
}

resource "aws_s3_bucket_policy" "s3_cloudfront_bypass" {
  bucket = module.s3_cloudfront_bypass.bucket_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipalReadOnly"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${module.s3_cloudfront_bypass.bucket_arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.s3_cloudfront_bypass.arn
          }
        }
      },
      {
        Sid       = "PublicBypassDirectAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${module.s3_cloudfront_bypass.bucket_arn}/*"
      },
    ]
  })

  depends_on = [aws_cloudfront_distribution.s3_cloudfront_bypass]
}

resource "aws_s3_object" "s3_cloudfront_bypass" {
  bucket       = module.s3_cloudfront_bypass.bucket_id
  key          = "vuln-s3-012-cloudfront-bypass-test.txt"
  content      = "VULN-S3-012: reachable directly over plain S3 HTTPS, bypassing the CloudFront distribution this bucket is meant to require."
  content_type = "text/plain"

  tags = {
    Project        = "cloud-vuln-range"
    VulnTestCaseId = "VULN-S3-012"
  }

  depends_on = [module.s3_cloudfront_bypass]
}
