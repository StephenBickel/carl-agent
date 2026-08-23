# AWS autonomy control plane

This Terraform root is the least-privilege AWS reference profile for Carl's autonomous improvement control plane. It creates durable state, immutable inputs/evidence, independent signing, audit telemetry, and six exact GitHub OIDC identities. It does not deploy Carl, publish a release, or grant an AWS identity to candidate code.

## Security boundaries

| OIDC role | Exact subject | AWS authority |
| --- | --- | --- |
| coordinator | protected repository `main` ref | connect only as `carl_coordinator` |
| builder | `carl-autonomy-builder` environment | builder DB identity, public immutable inputs, builder model secret |
| validator | `carl-autonomy-validator` environment | validator DB identity, private holdouts, validator model secret |
| promoter | `carl-autonomy-promoter` environment | promoter DB identity and promotion GitHub App secret only |
| soak | `carl-autonomy-soak` environment | soak DB identity, soak inputs, exact-revert GitHub App secret |
| observer | `carl-autonomy-observer` environment | observer DB identity, evidence archive, KMS sign/verify only |

Every OIDC trust binds `sts.amazonaws.com` plus one exact repository ref or Environment subject. Role policies contain no role assumption, role passing, wildcard action, or account-wide resource. Candidate jobs receive no OIDC role, database access, object access, secret access, or signing authority.

The profile creates:

- private Multi-AZ RDS PostgreSQL 16+ with KMS encryption, IAM database authentication, deletion protection, final snapshots, 35-day backups, log exports, and storage alarms;
- private versioned input and evidence buckets with Object Lock, KMS encryption, public-access blocks, TLS-only policies, and deletion prevention;
- a non-exportable P-256 KMS signing key for `ECDSA_SHA_256` receipts, separate from the symmetric storage key;
- immutable CloudTrail storage, management and protected-object data events, log validation, CloudWatch retention, and denied-operation alarms.

## Provisioning inputs

Supply `aws_account_id`, `vpc_id`, at least two genuinely private subnet IDs in distinct availability zones, and one or more private executor security groups. Supply exact existing Secrets Manager ARNs for builder/validator model credentials and promoter/soak GitHub App identities. Secret values are never Terraform inputs or outputs.

The private executors represented by `database_ingress_security_group_ids` must have a routed private path to the RDS subnets. This module deliberately creates no CIDR ingress, public database endpoint, public bucket, runner fleet, NAT gateway, Carl deployment, or release path.

## Validate without creating resources

```bash
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
terraform test
```

The tests use Terraform's mocked AWS provider and require no cloud credentials. Provisioning is a separate commissioning action and must use reviewed variables and a protected remote state backend.
