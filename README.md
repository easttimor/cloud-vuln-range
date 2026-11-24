# cloud-vuln-range

A suite of intentionally vulnerable AWS resources, deployed to a dedicated
sandbox account, used as test cases for detection (and eventually
prevention) controls. Every resource here is built to demonstrate exactly
one misconfiguration pattern — nothing more. IAM roles have zero attached
permissions; the vulnerability under test is always the configuration
itself (trust policy, resource policy, ACL, setting, etc.), never what an
attacker could *do* after exploiting it.

## Target account

All account IDs, org IDs, and profile names are environment-specific and
deliberately kept out of this repo:

- `terraform.tfvars` (gitignored, never committed) holds the real values —
  copy `terraform.tfvars.example` to get started.
- `versions.tf` hard-locks the AWS provider to `var.sandbox_account_id` via
  `allowed_account_ids` — applies against any other account fail fast.
- Resource names bake in `var.sandbox_account_id` for readability/global
  uniqueness (e.g. `cloud-vuln-range-vuln-s3-001-<account-id>`), but that
  value always comes from a variable, never a literal in source.

## Deploy role (bootstrap, not a test case)

Some AWS Organizations run a guardrail (an SCP) that denies
`s3:CreateBucket` everywhere unless the calling principal carries a
specific tag — a common pattern for curbing bucket sprawl org-wide. If
your org does this too, a plain admin session won't be able to create any
of the S3 test cases here. `deploy_role.tf` creates one role,
`cloud-vuln-range-deploy`, in the sandbox account only, carrying the tag
such a guardrail checks for (`etotag-scp-s3 = true` by default — adjust to
match your own org's actual gate, or delete `deploy_role.tf` and the
`assume_role` block in `versions.tf` entirely if your org has no such
guardrail). `versions.tf`'s provider assumes into this role for every
apply.

Bootstrapping a brand-new account for the first time: the role itself must
be created via a plain admin session first (`iam:CreateRole`/`TagRole`
aren't typically what a bucket-creation guardrail blocks) —
`terraform apply -target=aws_iam_role.deploy -target=aws_iam_role_policy_attachment.deploy_admin`
— before the rest of the config (which assumes into that role) will work.

## Layout

```
.
├── main.tf                     # root: wires up each test-case category module
├── variables.tf                # shared sandbox/org/placeholder variables
├── versions.tf                 # provider (assumes the deploy role) + account guardrail
├── deploy_role.tf              # bootstrap role satisfying an org bucket-creation guardrail, if any (see above)
├── terraform.tfvars            # real values for this environment (gitignored, never committed)
├── terraform.tfvars.example    # checked-in template of what terraform.tfvars needs
├── modules/
│   ├── iam_trust_vuln/          # reusable: one IAM role, caller-supplied trust policy, zero permissions
│   ├── s3_bucket_vuln/          # reusable: one S3 bucket + Block Public Access + optional ACL/versioning knobs
│   ├── sqs_queue_vuln/          # reusable: one SQS queue, caller-supplied queue policy
│   └── kms_key_vuln/            # reusable: one KMS key, caller-supplied key policy
└── test_cases/
    ├── iam_trust_policy/        # category module: IAM external trust policy misconfigs
    ├── s3_exposure/             # category module: S3 bucket/object/access-point/replication/CloudFront exposure misconfigs
    │   └── destination_account/  # separate root: destination side of VULN-S3-007, applied with
    │                              # credentials for a second, different account - not this project's
    ├── sqs_exposure/            # category module: SQS queue policy misconfigs
    └── kms_key_policy/          # category module: KMS key policy misconfigs that mediate access to other resources
```

Each vulnerability category lives under `test_cases/<category>/` as its own
module, called once from root `main.tf`. New categories (SG rules, Lambda
resource policies, Secrets Manager resource policies, etc.) should follow
the same pattern: a category module under `test_cases/`, built from
reusable building blocks under `modules/` where it makes sense to share
one.

## Tag legend

Every resource in the catalog is tagged for traceability and to record a
*hypothesis* about detection coverage — these are informed guesses to
validate empirically once real tools are pointed at this account, not
verified fact. Correct the tag values based on what you actually observe.

- `VulnTestCaseId` — catalog ID (e.g. `VULN-S3-004`), also baked into the
  resource name where the resource type allows it.
- `VulnDescription` — plain-language description of the misconfiguration.
  Keep these ASCII/charset-boring: AWS resource tag values reject commas,
  parentheses, quotes, apostrophes, semicolons, and asterisks (learned the
  hard way — see the IAM and S3 sections below).
- `ExpectedAccessAnalyzerFinding` — `yes` / `no` / `partial` / `unverified`:
  hypothesis for whether IAM Access Analyzer's external-access analyzer
  flags this resource.
- `ExpectedCspmFinding` — same scale, for a generic third-party CSPM.
- `DetectionControl` — name of the specific detection (GuardDuty finding
  type, custom Config rule, SIEM detection name) this test case validates,
  once one is built. Defaults to `unassigned`.

## Catalog: IAM external trust policy (`test_cases/iam_trust_policy`)

`example_external_account_id` should be set to a real external AWS
account ID (e.g. a SaaS vendor's published integration account) — IAM
validates that principal account IDs in trust policies correspond to real
accounts, so a made-up placeholder (e.g. AWS's reserved doc example
`123456789012`) is rejected at `CreateRole` time with
`MalformedPolicyDocument: Invalid principal in policy`.

| ID | Role name | Vulnerability | Notes |
|----|-----------|----------------|-------|
| VULN-IAM-001 | `vuln-iam-trust-external-account` | Trust policy scoped to one named external AWS account, no `ExternalId`/condition | Classic "vendor cross-account role done wrong." |
| VULN-IAM-002 | `vuln-iam-trust-any-account` | `Principal: {"AWS": "*"}`, no condition | Most severe variant: any AWS principal in any account (including attacker-controlled ones) can assume. |
| VULN-IAM-003 | `vuln-iam-trust-org-wide` | `Principal: {"AWS": "*"}` + `aws:PrincipalOrgID` condition | Scoped to the org, but still trusts every current and future member account. |
| VULN-IAM-004 | `vuln-iam-trust-principal-tag` | `Principal: {"AWS": "*"}` + `aws:PrincipalTag/PartnerAccess` condition | Looks scoped, isn't a real boundary: `aws:PrincipalTag` is set by the *calling* account's own IAM admins on their own principal, so any external account can self-apply the matching tag and satisfy the condition. Good test of whether a reviewer/tool distinguishes a tag condition from an actual account/org boundary. |

## Catalog: S3 exposure (`test_cases/s3_exposure`)

Bucket names are `cloud-vuln-range-<test-case-id>-<account-id>`.

| ID | Resource | Vulnerability | Access Analyzer | CSPM | Notes |
|----|----------|----------------|:---:|:---:|-------|
| VULN-S3-001 | `s3_public_policy` | Bucket policy: `Principal "*"`, `Action "s3:*"`, no condition | yes | yes | Full public read/write/delete. Most severe, most universally detected. Verified anonymously listable post-apply. |
| VULN-S3-002 | `s3_external_account_trust` | Bucket policy grants read to one named external account (`example_external_account_id`), no `ExternalId` | yes | yes | Not "public" by AWS's own definition, so default Block Public Access is left fully on deliberately — tests whether a tool catches cross-account over-sharing even when BPA looks locked down. Verified: anonymous `ListBucket` denied. |
| VULN-S3-003 | `s3_public_acl` | Bucket-level canned ACL `public-read`, no bucket policy at all | yes | yes | Pure legacy-ACL path. Verified anonymously listable post-apply. |
| VULN-S3-004 | `s3_public_object_acl` | Bucket is private; one object inside has a `public-read` object ACL | **no** | partial | Known blind spot: IAM Access Analyzer for S3 evaluates bucket policies, bucket ACLs, and access point policies — not individual object ACLs. Verified: anonymous bucket listing denied, but the object itself returns `200` over plain HTTPS with zero credentials. |
| VULN-S3-005 | `s3_public_access_point` | Bucket policy only delegates to this account's access points (`s3:DataAccessPointAccount`); the access point's own policy grants `Principal "*"` | yes | partial | See finding below — Access Points reject all unsigned requests, so this is "any AWS principal," not literally anonymous. |
| VULN-S3-006 | `s3_external_access_point` | Same delegation shape as 005, but the access point's own policy grants read to one named external account instead of the world | yes | partial | Tests whether a tool follows bucket→access-point delegation through to notice the cross-account grant, the access-point analogue of VULN-S3-002. |
| VULN-S3-007 | `s3_replication_source` | Bucket replicates objects to a bucket in a real AWS account you own, outside this org (`replication_destination_account_id`) | **no** | partial | Source side only — see "Cross-account replication" below. IAM Access Analyzer does not evaluate replication configuration at all, a clean blind spot regardless of how the destination is configured. |
| VULN-S3-008 | `s3_public_write` | Bucket policy: `Principal "*"`, `Action "s3:PutObject"` only — no read grant | yes | yes | Public *write*, not read: tamper/data-poisoning/malware-staging risk, sometimes alerted on differently than public read even by the same tool. Verified: anonymous `PutObject` succeeds (confirmed via a signed `HeadObject`, then cleaned up). |
| VULN-S3-009 | `s3_weak_condition` | Bucket policy: `Principal "*"`, `Action "s3:GetObject"`, gated only by `aws:Referer` | yes | partial | The S3 analogue of VULN-IAM-004 — Referer is a client-supplied header, trivially spoofed. **Confirmed twice over:** AWS's own Block Public Access classifier rejected this policy at default BPA settings with the same `AccessDenied: public policies are prevented by BlockPublicPolicy` error a bare wildcard grant gets (so AWS agrees a Referer condition isn't a real restriction); and once BPA was relaxed, an anonymous `GET` with no `Referer` header returns `403`, while one with the expected (spoofed) header returns `200`. |
| VULN-S3-010 | `s3_org_wide` | Bucket policy: `Principal "*"` + `aws:PrincipalOrgID` condition | yes | partial | S3 analogue of VULN-IAM-003/VULN-SQS-003 — a real gap the catalog had until now. Verified: anonymous `ListBucket` denied, as expected (org-scoped, not public). |
| VULN-S3-011 | `s3_authenticated_users_acl` | Bucket-level canned ACL `authenticated-read`, distinct from `public-read` (VULN-S3-003) | yes | partial | Grants read to any AWS account on earth — not literally the internet, but commonly mistaken for "authenticated to my app," a confusion that has caused real large-scale breaches. Verified: anonymous `ListBucket` denied (correct — `AuthenticatedUsers` isn't the internet), while a signed call from any real AWS account succeeds. |
| VULN-S3-012 | `s3_cloudfront_bypass` | Bucket is meant to be reachable only via a CloudFront distribution (OAC), but a second bucket policy statement independently grants public `s3:GetObject` with no condition | yes | partial | Nothing's wrong with the CloudFront/OAC grant itself — the bug is the extra statement next to it. **Verified both paths work:** the CloudFront URL (`cloudfront_domain_name` output) returns the object correctly through the CDN, and the plain S3 HTTPS URL returns the identical content anonymously, with no CloudFront involved at all — confirming the CDN's caching/logging/WAF are fully bypassable. CloudFront settings are cost-minimized: `PriceClass_100`, the free default `*.cloudfront.net` certificate, no access logging, no WAF. |

**Empirical finding (VULN-S3-005/006):** S3 Access Points reject every
unsigned request with `InvalidRequest: ... use Signature Version 4`,
regardless of what the access point's own policy says. So `Principal "*"`
on an access point policy means "any AWS principal that can produce a
valid SigV4 signature" (i.e. any AWS customer on earth) — not a literally
anonymous/unauthenticated caller, unlike a public bucket policy or bucket
ACL. A CSPM check that specifically tests "is this reachable with zero
credentials" can miss this entirely; IAM Access Analyzer's external-access
model (any-external-principal reachability, not raw anonymity) should
still catch it. This is why `ExpectedCspmFinding` is `partial` rather than
`yes` for both.

**Also learned empirically, applies suite-wide:** S3 resource tags (bucket
and object) reject `*`, `;`, and apostrophes in addition to the characters
IAM tags already reject (commas, parentheses, quotes) — keep
`VulnDescription` values plain.

## Catalog: SQS exposure (`test_cases/sqs_exposure`)

Direct SQS analogue of the IAM trust-policy catalog — same four shapes,
applied to a queue's resource-based policy. Queue names follow the same
`cloud-vuln-range-<test-case-id>-<account-id>` convention.

| ID | Resource | Vulnerability | Access Analyzer | CSPM | Notes |
|----|----------|----------------|:---:|:---:|-------|
| VULN-SQS-001 | `sqs_external_account_trust` | Queue policy grants one named external account (`example_external_account_id`) send/receive/delete/read-attributes, no condition | yes | yes | Cross-account queue over-sharing, the SQS analogue of VULN-S3-002/VULN-IAM-001. |
| VULN-SQS-002 | `sqs_any_account` | `Principal "*"`, `Action "sqs:*"`, no condition | yes | yes | Most severe variant — see finding below. |
| VULN-SQS-003 | `sqs_org_wide` | `Principal "*"` + `aws:PrincipalOrgID` condition | yes | partial | SQS analogue of VULN-IAM-003 — org-scoped but trusts every current and future member account. |
| VULN-SQS-004 | `sqs_principal_tag` | `Principal "*"` + `aws:PrincipalTag/PartnerAccess` condition | yes | partial | SQS analogue of VULN-IAM-004 — same self-assignable-tag weak boundary. |

**Empirical finding, applies to every case in this category:** unlike S3,
SQS has no concept of an unauthenticated/anonymous request at all — every
SQS API call requires a valid SigV4 signature regardless of what the queue
policy says. Confirmed directly: an anonymous (`--no-sign-request`)
`SendMessage` against VULN-SQS-002 (`Principal "*"`) fails, while the
identical call signed with real AWS credentials succeeds. So `Principal
"*"` on an SQS queue policy means "any authenticated AWS principal in any
account," never literal internet-anonymous access — the SQS equivalent of
the S3 Access Point finding above, except here it's true of *every* SQS
resource, not one feature within the service.

## Catalog: KMS key policy (`test_cases/kms_key_policy`)

Unlike every other category, the vulnerable resource here isn't the one
that looks exposed. The S3 bucket in this category (`s3_kms_exposure_bucket`)
has no bucket policy and no public ACL — any scanner that only inspects S3
resource policies/ACLs correctly sees nothing wrong with it. The actual
exposure is one layer down, in the KMS key used for that bucket's default
encryption.

| ID | Resource | Vulnerability | Access Analyzer | CSPM | Notes |
|----|----------|----------------|:---:|:---:|-------|
| VULN-KMS-001 | `kms_public_decrypt` | Key policy grants `kms:Decrypt`/`DescribeKey` to `Principal "*"`, no condition. Companion bucket `s3_kms_exposure_bucket` is fully private and uses this key for default encryption | yes (on the key) | partial | Latent, not directly exploitable on its own: nobody outside the account can call `s3:GetObject` on the companion bucket at all, so there's no path to the ciphertext through S3 itself. The risk is that this key would decrypt for literally anyone the moment the ciphertext becomes reachable through *any* other path — a future bucket policy change, a stolen snapshot, an intercepted replication stream. Verified: the companion bucket denies anonymous access (correctly, as intended), and the test object's `SSEKMSKeyId` and the key's stored policy (`aws kms get-key-policy`) both confirm the wide-open grant is real, not just planned. IAM Access Analyzer supports KMS keys natively as a resource type, so it's expected to flag the *key*; it has nothing to say about the bucket, which is exactly the point of this test case — don't assume a clean bucket policy means the data is safe. |

Why its own category rather than folding into `s3_exposure`: SQS, SNS, and
Lambda can all be mediated by a permissive CMK the exact same way S3 is —
this category is scoped to the key policy itself, with room to add
non-S3-mediated variants later without restructuring anything.

## Cross-account replication (VULN-S3-007): the destination-side handshake

Unlike every other test case, this one spans two AWS accounts this project
doesn't have uniform access to: the source bucket/role live in the
sandbox account (`var.sandbox_account_id`, this repo's Terraform), but the
destination bucket must live in a second, real AWS account you own
(`var.replication_destination_account_id`), confirmed outside this org
(check with `aws organizations list-accounts` from your org's management
account). This project has no credentials for that second account, so the
destination side can't be applied from here.

**What's already done (source side, this repo):** a versioned bucket, an
IAM role (`vuln-s3-007-replication-role`, trusted by `s3.amazonaws.com`)
with exactly the permissions S3 replication needs on the source side, and
a replication configuration pointed at a bucket named
`cloud-vuln-range-vuln-s3-007-dest-<replication_destination_account_id>`
in that second account. Applying this alone fails with `InvalidRequest:
Destination bucket must exist` — expected, and confirmed.

**The handshake required on the destination side**, in
`test_cases/s3_exposure/destination_account/` (its own Terraform root,
separate state, not wired into this project's root module or its
`allowed_account_ids` guardrail):

1. A bucket named exactly `cloud-vuln-range-vuln-s3-007-dest-<destination-account-id>`.
2. Versioning enabled on it (S3 replication requires versioning on both
   sides).
3. Object Ownership set to `BucketOwnerEnforced` (sidesteps ACL/ownership
   handling for replicated objects entirely — avoids needing an
   `access_control_translation` block on the source side).
4. A bucket policy granting the source account's replication role
   (`arn:aws:iam::<sandbox-account-id>:role/vuln-s3-007-replication-role`)
   `s3:ReplicateObject`, `s3:ReplicateDelete`, and `s3:ReplicateTags` on
   `<destination-bucket-arn>/*`.

All four are already written as Terraform in
`destination_account/main.tf`. To apply:

```
cd test_cases/s3_exposure/destination_account
terraform init
terraform apply \
  -var="aws_profile=<your profile/credentials for the destination account>" \
  -var="destination_account_id=<destination account id>" \
  -var="source_account_id=<sandbox account id>"
```

No equivalent trust needs to be configured in the sandbox account — the
replication role and its permissions already exist there. Once the
destination bucket exists, re-running `terraform apply` from this
project's root will pick up the now-satisfiable replication configuration.

## Proposed / not yet built

Other ways an S3 bucket or its contents can end up exposed, beyond what's
already built:

- **VPC-endpoint delegation gap**: the access-point lesson (VULN-S3-005/006
  — bucket delegates to "any access point I own," real restriction lives
  one level down) has a structural twin here: a bucket policy that trusts
  `aws:SourceVpce` for a specific VPC endpoint is only as tight as that
  endpoint's own policy. An S3 VPC endpoint with a wide-open endpoint
  policy (`Action: "*"`, `Resource: "*"`) makes the "requests must come
  through our VPC" bucket-policy condition far less meaningful than it
  looks.
- **Egress via other "deliver output to a bucket ARN" S3 features**:
  replication (VULN-S3-007) is one instance of a broader pattern — S3
  Inventory, Storage Class Analytics export, and server access logging can
  all be configured to write to a bucket in an external account the same
  way. Same underlying lesson, but tools may check these inconsistently
  (e.g. flag replication but not inventory destinations), so each is
  arguably its own test case rather than one "egress" catch-all.

## Usage

```
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your real account/org IDs - it's gitignored, never committed

aws sso login --profile <your-sso-profile>
terraform init
terraform plan
terraform apply
```
