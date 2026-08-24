output "database" {
  description = "Private PostgreSQL endpoint and AWS-managed bootstrap secret reference."
  value = {
    endpoint          = aws_db_instance.control_plane.address
    port              = aws_db_instance.control_plane.port
    database_name     = aws_db_instance.control_plane.db_name
    resource_id       = aws_db_instance.control_plane.resource_id
    master_secret_arn = try(aws_db_instance.control_plane.master_user_secret[0].secret_arn, null)
  }
}

output "protected_buckets" {
  description = "Immutable protected input, evidence, and audit storage."
  value = {
    inputs = {
      name = aws_s3_bucket.inputs.id
      arn  = aws_s3_bucket.inputs.arn
    }
    evidence = {
      name = aws_s3_bucket.evidence.id
      arn  = aws_s3_bucket.evidence.arn
    }
    audit = {
      name = aws_s3_bucket.audit.id
      arn  = aws_s3_bucket.audit.arn
    }
  }
}

output "signing_key" {
  description = "Pinned non-exportable receipt-signing key identity and algorithm."
  value = {
    arn       = aws_kms_key.signing.arn
    key_id    = aws_kms_key.signing.key_id
    alias     = aws_kms_alias.signing.name
    algorithm = "ECDSA_SHA_256"
  }
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions OIDC provider used by exact role subjects."
  value       = aws_iam_openid_connect_provider.github.arn
}

output "github_environment_values" {
  description = "Non-secret values to configure on each protected GitHub Environment."
  value = {
    for role, resource in aws_iam_role.autonomy : role => {
      AWS_ROLE_ARN = resource.arn
      AWS_REGION   = var.aws_region
      OIDC_SUBJECT = local.oidc_subjects[role]
    }
  }
}

output "audit" {
  description = "Durable CloudTrail and CloudWatch audit endpoints."
  value = {
    trail_arn            = aws_cloudtrail.audit.arn
    cloudtrail_log_group = aws_cloudwatch_log_group.cloudtrail.arn
    postgresql_log_group = aws_cloudwatch_log_group.postgresql.arn
  }
}
