mock_provider "aws" {}

override_resource {
  target          = aws_kms_key.storage
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:123456789012:key/storage"
  }
}

override_resource {
  target          = aws_s3_bucket.evidence
  override_during = plan
  values = {
    arn = "arn:aws:s3:::carl-autonomy-123456789012-us-east-1-evidence"
  }
}

variables {
  aws_account_id = "123456789012"
  aws_region     = "us-east-1"
  vpc_id         = "vpc-0123456789abcdef0"
  private_subnet_ids = [
    "subnet-0123456789abcdef0",
    "subnet-0fedcba9876543210",
  ]
  database_ingress_security_group_ids = ["sg-0123456789abcdef0"]
  secret_arns = {
    builder_model       = "arn:aws:secretsmanager:us-east-1:123456789012:secret:carl/builder"
    validator_model     = "arn:aws:secretsmanager:us-east-1:123456789012:secret:carl/validator"
    promoter_github_app = "arn:aws:secretsmanager:us-east-1:123456789012:secret:carl/promoter"
    soak_github_app     = "arn:aws:secretsmanager:us-east-1:123456789012:secret:carl/soak"
  }
}

run "inputs_and_evidence_are_immutable_private_objects" {
  command = plan

  assert {
    condition     = aws_s3_bucket.inputs.object_lock_enabled && aws_s3_bucket.evidence.object_lock_enabled
    error_message = "Both protected input and evidence buckets must enable Object Lock at creation."
  }

  assert {
    condition     = aws_s3_bucket_versioning.inputs.versioning_configuration[0].status == "Enabled" && aws_s3_bucket_versioning.evidence.versioning_configuration[0].status == "Enabled"
    error_message = "Both protected input and evidence buckets must retain every object version."
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.inputs.rule[0].default_retention[0].days >= 30 && aws_s3_bucket_object_lock_configuration.evidence.rule[0].default_retention[0].mode == "COMPLIANCE" && aws_s3_bucket_object_lock_configuration.evidence.rule[0].default_retention[0].days >= 365
    error_message = "Inputs need bounded retention and evidence needs at least one year of compliance retention."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.inputs.block_public_acls && aws_s3_bucket_public_access_block.inputs.block_public_policy && aws_s3_bucket_public_access_block.inputs.ignore_public_acls && aws_s3_bucket_public_access_block.inputs.restrict_public_buckets
    error_message = "The protected input bucket must block every public access path."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.evidence.block_public_acls && aws_s3_bucket_public_access_block.evidence.block_public_policy && aws_s3_bucket_public_access_block.evidence.ignore_public_acls && aws_s3_bucket_public_access_block.evidence.restrict_public_buckets
    error_message = "The evidence bucket must block every public access path."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.inputs.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" && one(aws_s3_bucket_server_side_encryption_configuration.evidence.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" && one(aws_s3_bucket_server_side_encryption_configuration.evidence.rule).bucket_key_enabled
    error_message = "Protected objects must use the dedicated KMS storage key."
  }

  assert {
    condition = try(alltrue([
      one([
        for statement in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : statement
        if statement.Sid == "DenyMissingEvidenceEncryptionAlgorithm"
      ]).Condition.Null["s3:x-amz-server-side-encryption"] == "true",
      one([
        for statement in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : statement
        if statement.Sid == "DenyWrongEvidenceEncryptionAlgorithm"
      ]).Condition.StringNotEquals["s3:x-amz-server-side-encryption"] == "aws:kms",
      one([
        for statement in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : statement
        if statement.Sid == "DenyMissingEvidenceKmsKey"
      ]).Condition.Null["s3:x-amz-server-side-encryption-aws-kms-key-id"] == "true",
      one([
        for statement in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : statement
        if statement.Sid == "DenyWrongEvidenceKmsKey"
      ]).Condition.ArnNotEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == aws_kms_key.storage.arn,
      length([
        for statement in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : statement
        if contains([
          "DenyMissingEvidenceEncryptionAlgorithm",
          "DenyWrongEvidenceEncryptionAlgorithm",
          "DenyMissingEvidenceKmsKey",
          "DenyWrongEvidenceKmsKey",
        ], statement.Sid)
      ]) == 4,
      alltrue([
        for statement in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement :
        statement.Effect == "Deny" &&
        statement.Principal == "*" &&
        statement.Action == "s3:PutObject" &&
        statement.Resource == "${aws_s3_bucket.evidence.arn}/*"
        if contains([
          "DenyMissingEvidenceEncryptionAlgorithm",
          "DenyWrongEvidenceEncryptionAlgorithm",
          "DenyMissingEvidenceKmsKey",
          "DenyWrongEvidenceKmsKey",
        ], statement.Sid)
      ]),
    ]), false)
    error_message = "Evidence uploads must be denied when the SSE-KMS algorithm or exact dedicated key is missing or wrong."
  }
}
