resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

locals {
  oidc_subjects = {
    coordinator = "repo:${var.github_repository}:ref:${var.github_ref}"
    builder     = "repo:${var.github_repository}:environment:${var.github_environments.builder}"
    validator   = "repo:${var.github_repository}:environment:${var.github_environments.validator}"
    promoter    = "repo:${var.github_repository}:environment:${var.github_environments.promoter}"
    soak        = "repo:${var.github_repository}:environment:${var.github_environments.soak}"
    observer    = "repo:${var.github_repository}:environment:${var.github_environments.observer}"
  }

  database_usernames = {
    coordinator = "carl_coordinator"
    builder     = "carl_builder"
    validator   = "carl_validator"
    promoter    = "carl_promoter"
    soak        = "carl_soak"
    observer    = "carl_observer"
  }

  database_user_arns = {
    for role, username in local.database_usernames :
    role => "arn:aws:rds-db:${var.aws_region}:${var.aws_account_id}:dbuser/${aws_db_instance.control_plane.resource_id}/${username}"
  }

  role_policy_documents = {
    coordinator = jsonencode(jsondecode(templatefile("${path.module}/policies/coordinator.json", {
      database_user_arn = jsonencode(local.database_user_arns.coordinator)
    })))
    builder = jsonencode(jsondecode(templatefile("${path.module}/policies/builder.json", {
      database_user_arn = jsonencode(local.database_user_arns.builder)
      input_object_arn  = jsonencode("${aws_s3_bucket.inputs.arn}/public/*")
      input_bucket_arn  = jsonencode(aws_s3_bucket.inputs.arn)
      s3_via_service    = jsonencode(local.s3_service)
      storage_key_arn   = jsonencode(aws_kms_key.storage.arn)
      secret_arn        = jsonencode(var.secret_arns.builder_model)
    })))
    validator = jsonencode(jsondecode(templatefile("${path.module}/policies/validator.json", {
      database_user_arn = jsonencode(local.database_user_arns.validator)
      input_object_arn  = jsonencode("${aws_s3_bucket.inputs.arn}/holdout/*")
      input_bucket_arn  = jsonencode(aws_s3_bucket.inputs.arn)
      s3_via_service    = jsonencode(local.s3_service)
      storage_key_arn   = jsonencode(aws_kms_key.storage.arn)
      secret_arn        = jsonencode(var.secret_arns.validator_model)
    })))
    promoter = jsonencode(jsondecode(templatefile("${path.module}/policies/promoter.json", {
      database_user_arn = jsonencode(local.database_user_arns.promoter)
      secret_arn        = jsonencode(var.secret_arns.promoter_github_app)
    })))
    soak = jsonencode(jsondecode(templatefile("${path.module}/policies/soak.json", {
      database_user_arn = jsonencode(local.database_user_arns.soak)
      input_object_arn  = jsonencode("${aws_s3_bucket.inputs.arn}/soak/*")
      input_bucket_arn  = jsonencode(aws_s3_bucket.inputs.arn)
      s3_via_service    = jsonencode(local.s3_service)
      storage_key_arn   = jsonencode(aws_kms_key.storage.arn)
      secret_arn        = jsonencode(var.secret_arns.soak_github_app)
    })))
    observer = jsonencode(jsondecode(templatefile("${path.module}/policies/observer.json", {
      database_user_arn   = jsonencode(local.database_user_arns.observer)
      evidence_object_arn = jsonencode("${aws_s3_bucket.evidence.arn}/archive/*")
      evidence_bucket_arn = jsonencode(aws_s3_bucket.evidence.arn)
      s3_via_service      = jsonencode(local.s3_service)
      storage_key_arn     = jsonencode(aws_kms_key.storage.arn)
      signing_key_arn     = jsonencode(aws_kms_key.signing.arn)
    })))
  }
}

resource "aws_iam_role" "autonomy" {
  for_each = local.oidc_subjects

  name                 = "${var.name_prefix}-${each.key}"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ExactGitHubIdentity"
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = each.value
        }
      }
    }]
  })

  lifecycle {
    precondition {
      condition     = !strcontains(each.value, "*")
      error_message = "OIDC subjects must never contain wildcards."
    }
  }
}

resource "aws_iam_role_policy" "autonomy" {
  for_each = local.role_policy_documents

  name   = "${var.name_prefix}-${each.key}"
  role   = aws_iam_role.autonomy[each.key].id
  policy = each.value
}
