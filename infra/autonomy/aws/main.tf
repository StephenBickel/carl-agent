provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = local.common_tags
  }
}

locals {
  database_identifier = "${var.name_prefix}-state"
  cloudtrail_name     = "${var.name_prefix}-audit"
  cloudtrail_arn      = "arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/${local.cloudtrail_name}"
  bucket_names = {
    inputs   = "${var.name_prefix}-${var.aws_account_id}-${var.aws_region}-inputs"
    evidence = "${var.name_prefix}-${var.aws_account_id}-${var.aws_region}-evidence"
    audit    = "${var.name_prefix}-${var.aws_account_id}-${var.aws_region}-audit"
  }
  common_tags = merge(var.tags, {
    Application = "carl-autonomy"
    ManagedBy   = "terraform"
    Repository  = var.github_repository
    Scope       = "control-plane"
  })
}

resource "aws_kms_key" "storage" {
  description              = "Carl autonomy database, object, audit, and secret encryption"
  deletion_window_in_days  = 30
  enable_key_rotation      = true
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudTrailDescribeKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = {
          StringEquals = { "AWS:SourceArn" = local.cloudtrail_arn }
        }
      },
      {
        Sid       = "CloudTrailGenerateDataKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn"                            = local.cloudtrail_arn
            "kms:EncryptionContext:aws:cloudtrail:arn" = local.cloudtrail_arn
          }
        }
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${var.name_prefix}-storage"
  target_key_id = aws_kms_key.storage.key_id
}

resource "aws_kms_key" "signing" {
  description              = "Non-exportable signer for independently verified Carl autonomy receipts"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "signing" {
  name          = "alias/${var.name_prefix}-signing"
  target_key_id = aws_kms_key.signing.key_id
}

resource "aws_db_subnet_group" "control_plane" {
  name       = "${var.name_prefix}-private"
  subnet_ids = var.private_subnet_ids

  lifecycle {
    precondition {
      condition     = length(distinct(var.private_subnet_ids)) >= 2
      error_message = "The control-plane database requires at least two distinct private subnets."
    }
  }
}

resource "aws_security_group" "database" {
  name        = "${var.name_prefix}-postgresql"
  description = "PostgreSQL ingress from explicitly approved private cloud executors"
  vpc_id      = var.vpc_id
  ingress     = []
  egress      = []

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "database" {
  for_each = var.database_ingress_security_group_ids

  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = each.value
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Exact private executor security group"
}

resource "aws_db_parameter_group" "control_plane" {
  name   = "${var.name_prefix}-postgres16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }
}

resource "aws_cloudwatch_log_group" "postgresql" {
  name              = "/aws/rds/instance/${local.database_identifier}/postgresql"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.storage.arn

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_db_instance" "control_plane" {
  identifier = local.database_identifier

  engine         = "postgres"
  engine_version = var.database_engine_version
  instance_class = var.database_instance_class
  db_name        = "carl_autonomy"
  username       = "carl_bootstrap"
  port           = 5432

  manage_master_user_password         = true
  master_user_secret_kms_key_id       = aws_kms_key.storage.arn
  iam_database_authentication_enabled = true

  allocated_storage     = var.database_allocated_storage_gib
  max_allocated_storage = var.database_max_allocated_storage_gib
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.storage.arn

  db_subnet_group_name   = aws_db_subnet_group.control_plane.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = true

  deletion_protection        = true
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${local.database_identifier}-final"
  copy_tags_to_snapshot      = true
  backup_retention_period    = var.database_backup_retention_days
  backup_window              = "03:00-04:00"
  maintenance_window         = "sun:05:00-sun:06:00"
  auto_minor_version_upgrade = true

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  parameter_group_name            = aws_db_parameter_group.control_plane.name
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.storage.arn

  depends_on = [aws_cloudwatch_log_group.postgresql]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "inputs" {
  bucket              = local.bucket_names.inputs
  force_destroy       = false
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "evidence" {
  bucket              = local.bucket_names.evidence
  force_destroy       = false
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "audit" {
  bucket              = local.bucket_names.audit
  force_destroy       = false
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "inputs" {
  bucket = aws_s3_bucket.inputs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "inputs" {
  bucket                  = aws_s3_bucket.inputs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "inputs" {
  bucket = aws_s3_bucket.inputs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "inputs" {
  bucket = aws_s3_bucket.inputs.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.input_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.inputs]
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "inputs" {
  bucket = aws_s3_bucket.inputs.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.storage.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.storage.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.storage.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "inputs" {
  bucket = aws_s3_bucket.inputs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.inputs.arn, "${aws_s3_bucket.inputs.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.cloudtrail_name}"
  retention_in_days = 2557
  kms_key_id        = aws_kms_key.storage.arn

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  name = "${var.name_prefix}-cloudtrail-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.cloudtrail_arn } }
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "${var.name_prefix}-cloudtrail-logs"
  role = aws_iam_role.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"
    }]
  })
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.audit.arn
        Condition = { StringEquals = { "AWS:SourceArn" = local.cloudtrail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit.arn}/cloudtrail/AWSLogs/${var.aws_account_id}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = local.cloudtrail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "audit" {
  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.audit.id
  s3_key_prefix                 = "cloudtrail"
  kms_key_id                    = aws_kms_key.storage.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true

  advanced_event_selector {
    name = "Management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "Protected autonomy objects"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.inputs.arn}/", "${aws_s3_bucket.evidence.arn}/"]
    }
  }

  depends_on = [
    aws_iam_role_policy.cloudtrail_logs,
    aws_s3_bucket_policy.audit,
    aws_s3_bucket_object_lock_configuration.audit,
  ]
}

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "${var.name_prefix}-unauthorized-api-calls"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedApiCalls"
    namespace = "Carl/AutonomyAudit"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "${var.name_prefix}-unauthorized-api-calls"
  alarm_description   = "Any denied autonomy control-plane API operation requires investigation."
  namespace           = "Carl/AutonomyAudit"
  metric_name         = "UnauthorizedApiCalls"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_topic_arns
}

resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "${var.name_prefix}-database-cpu"
  alarm_description   = "Sustained autonomy state database CPU saturation."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 80
  treat_missing_data  = "breaching"
  alarm_actions       = var.alarm_topic_arns
  dimensions          = { DBInstanceIdentifier = aws_db_instance.control_plane.identifier }
}

resource "aws_cloudwatch_metric_alarm" "database_free_storage" {
  alarm_name          = "${var.name_prefix}-database-free-storage"
  alarm_description   = "Autonomy state database free storage below 20 GiB."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  comparison_operator = "LessThanThreshold"
  threshold           = 21474836480
  treat_missing_data  = "breaching"
  alarm_actions       = var.alarm_topic_arns
  dimensions          = { DBInstanceIdentifier = aws_db_instance.control_plane.identifier }
}
