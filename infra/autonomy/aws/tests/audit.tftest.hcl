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

run "signing_and_audit_are_protected" {
  command = plan

  assert {
    condition     = aws_kms_key.signing.key_usage == "SIGN_VERIFY" && startswith(aws_kms_key.signing.customer_master_key_spec, "ECC_")
    error_message = "Trusted receipts must use a non-exportable asymmetric KMS signing key."
  }

  assert {
    condition     = aws_cloudtrail.audit.is_multi_region_trail && aws_cloudtrail.audit.enable_log_file_validation && aws_cloudtrail.audit.include_global_service_events
    error_message = "Audit logging must cover all regions and validate the CloudTrail log chain."
  }

  assert {
    condition     = contains(aws_db_instance.control_plane.enabled_cloudwatch_logs_exports, "postgresql") && contains(aws_db_instance.control_plane.enabled_cloudwatch_logs_exports, "upgrade")
    error_message = "PostgreSQL and upgrade logs must be exported for independent audit."
  }

  assert {
    condition     = aws_cloudwatch_log_group.cloudtrail.retention_in_days >= 365 && aws_cloudwatch_log_group.postgresql.retention_in_days >= 90
    error_message = "CloudTrail and PostgreSQL logs need durable bounded retention."
  }

  assert {
    condition = try((
      one([
        for statement in jsondecode(aws_kms_key.storage.policy).Statement : statement
        if statement.Sid == "CloudWatchLogsUseKey"
      ]).Principal.Service == "logs.us-east-1.amazonaws.com" &&
      toset(one([
        for statement in jsondecode(aws_kms_key.storage.policy).Statement : statement
        if statement.Sid == "CloudWatchLogsUseKey"
        ]).Action) == toset([
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
      ]) &&
      toset(one([
        for statement in jsondecode(aws_kms_key.storage.policy).Statement : statement
        if statement.Sid == "CloudWatchLogsUseKey"
        ]).Condition.ArnEquals["kms:EncryptionContext:aws:logs:arn"]) == toset([
        "arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudtrail/carl-autonomy-audit",
        "arn:aws:logs:us-east-1:123456789012:log-group:/aws/rds/instance/carl-autonomy-state/postgresql",
      ]) &&
      one([
        for statement in jsondecode(aws_kms_key.storage.policy).Statement : statement
        if statement.Sid == "CloudWatchLogsUseKey"
      ]).Condition.StringEquals["kms:ViaService"] == "logs.us-east-1.amazonaws.com" &&
      one([
        for statement in jsondecode(aws_kms_key.storage.policy).Statement : statement
        if statement.Sid == "CloudWatchLogsUseKey"
      ]).Effect == "Allow"
    ), false)
    error_message = "The regional CloudWatch Logs service may use the storage key only for the two exact protected log groups."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.unauthorized_api_calls.threshold == 1 && aws_cloudwatch_metric_alarm.database_cpu.threshold <= 85 && aws_cloudwatch_metric_alarm.database_free_storage.threshold > 0
    error_message = "The profile must alarm on unauthorized API calls and database resource exhaustion."
  }
}
