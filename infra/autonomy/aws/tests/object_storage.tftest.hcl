mock_provider "aws" {}

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
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.inputs.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" && one(aws_s3_bucket_server_side_encryption_configuration.evidence.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "Protected objects must use the dedicated KMS storage key."
  }
}
