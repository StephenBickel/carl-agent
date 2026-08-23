mock_provider "aws" {}

override_resource {
  target          = aws_kms_key.storage
  override_during = plan
  values = {
    arn    = "arn:aws:kms:us-east-1:123456789012:key/storage"
    key_id = "storage"
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

run "database_is_durable_encrypted_and_private" {
  command = plan

  assert {
    condition     = aws_db_instance.control_plane.engine == "postgres" && tonumber(split(".", aws_db_instance.control_plane.engine_version)[0]) >= 16
    error_message = "The control-plane database must run PostgreSQL 16 or newer."
  }

  assert {
    condition     = aws_db_instance.control_plane.storage_encrypted && aws_db_instance.control_plane.kms_key_id == aws_kms_key.storage.arn
    error_message = "The control-plane database must use the dedicated KMS storage key."
  }

  assert {
    condition     = !aws_db_instance.control_plane.publicly_accessible && length(aws_db_subnet_group.control_plane.subnet_ids) >= 2
    error_message = "The database must be private and span at least two private subnets."
  }

  assert {
    condition     = aws_db_instance.control_plane.deletion_protection && aws_db_instance.control_plane.skip_final_snapshot == false
    error_message = "The database must reject deletion and require a final snapshot."
  }

  assert {
    condition     = aws_db_instance.control_plane.backup_retention_period >= 7 && aws_db_instance.control_plane.copy_tags_to_snapshot
    error_message = "The database must retain backups for at least seven days with provenance tags."
  }

  assert {
    condition     = aws_db_instance.control_plane.iam_database_authentication_enabled && aws_db_instance.control_plane.manage_master_user_password
    error_message = "Database access must use short-lived IAM auth and an AWS-managed bootstrap password."
  }
}
