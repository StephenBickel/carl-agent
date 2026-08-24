mock_provider "aws" {}

override_resource {
  target          = aws_iam_openid_connect_provider.github
  override_during = plan
  values = {
    arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  }
}

override_resource {
  target          = aws_db_instance.control_plane
  override_during = plan
  values = {
    resource_id = "db-EXACTRESOURCEID"
  }
}

override_resource {
  target          = aws_s3_bucket.inputs
  override_during = plan
  values = {
    arn = "arn:aws:s3:::carl-autonomy-123456789012-us-east-1-inputs"
  }
}

override_resource {
  target          = aws_s3_bucket.evidence
  override_during = plan
  values = {
    arn = "arn:aws:s3:::carl-autonomy-123456789012-us-east-1-evidence"
  }
}

override_resource {
  target          = aws_kms_key.signing
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:123456789012:key/signing"
  }
}

override_resource {
  target          = aws_kms_key.storage
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:123456789012:key/storage"
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

run "github_oidc_subjects_and_permissions_are_exact" {
  command = plan

  assert {
    condition     = toset(keys(local.oidc_subjects)) == toset(["coordinator", "builder", "validator", "promoter", "soak", "observer"])
    error_message = "Exactly six protected controller identities are allowed; candidate code receives no AWS role."
  }

  assert {
    condition     = local.oidc_subjects.coordinator == "repo:StephenBickel/carl-agent:ref:refs/heads/main"
    error_message = "The coordinator trust must bind the exact repository and protected main ref."
  }

  assert {
    condition = alltrue([
      for role, subject in local.oidc_subjects :
      jsondecode(aws_iam_role.autonomy[role].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com" &&
      jsondecode(aws_iam_role.autonomy[role].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == subject &&
      !strcontains(subject, "*")
    ])
    error_message = "Every OIDC role must bind the exact audience and repository ref or environment subject without wildcards."
  }

  assert {
    condition = alltrue([
      for role in keys(local.oidc_subjects) :
      !strcontains(aws_iam_role_policy.autonomy[role].policy, "\"Action\":\"*\"") &&
      !strcontains(aws_iam_role_policy.autonomy[role].policy, "\"Resource\":\"*\"") &&
      !strcontains(lower(aws_iam_role_policy.autonomy[role].policy), "sts:assumerole") &&
      !strcontains(lower(aws_iam_role_policy.autonomy[role].policy), "iam:passrole")
    ])
    error_message = "Controller policies must use exact actions/resources and cannot assume or pass another role."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.autonomy["observer"].policy, "kms:Sign") && !strcontains(aws_iam_role_policy.autonomy["builder"].policy, "kms:Sign") && !strcontains(aws_iam_role_policy.autonomy["validator"].policy, "kms:Sign") && !strcontains(aws_iam_role_policy.autonomy["promoter"].policy, "kms:Sign") && !strcontains(aws_iam_role_policy.autonomy["soak"].policy, "kms:Sign")
    error_message = "Only the observer may request non-exportable signatures."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.autonomy["promoter"].policy, aws_s3_bucket.inputs.arn) && !strcontains(aws_iam_role_policy.autonomy["promoter"].policy, aws_s3_bucket.evidence.arn) && !strcontains(aws_iam_role_policy.autonomy["observer"].policy, "secretsmanager:GetSecretValue")
    error_message = "Production, archive, and signing identities must remain narrower than the builder controller."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.autonomy["builder"].policy, "kms:Decrypt") && strcontains(aws_iam_role_policy.autonomy["validator"].policy, "kms:Decrypt") && strcontains(aws_iam_role_policy.autonomy["soak"].policy, "kms:Decrypt") && strcontains(aws_iam_role_policy.autonomy["observer"].policy, "kms:GenerateDataKey") && !strcontains(aws_iam_role_policy.autonomy["promoter"].policy, aws_kms_key.storage.arn)
    error_message = "Only object readers and the archive writer may use the exact storage key required by SSE-KMS."
  }

  assert {
    condition = try(alltrue([
      for role, expected in {
        builder   = { bucket_arn = aws_s3_bucket.inputs.arn, actions = ["kms:Decrypt"] }
        validator = { bucket_arn = aws_s3_bucket.inputs.arn, actions = ["kms:Decrypt"] }
        soak      = { bucket_arn = aws_s3_bucket.inputs.arn, actions = ["kms:Decrypt"] }
        observer  = { bucket_arn = aws_s3_bucket.evidence.arn, actions = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"] }
        } : (
        length([
          for statement in jsondecode(aws_iam_role_policy.autonomy[role].policy).Statement : statement
          if try(statement.Resource, "") == aws_kms_key.storage.arn
        ]) == 1 &&
        one([
          for statement in jsondecode(aws_iam_role_policy.autonomy[role].policy).Statement : statement
          if try(statement.Resource, "") == aws_kms_key.storage.arn
        ]).Condition.StringEquals["kms:ViaService"] == "s3.us-east-1.amazonaws.com" &&
        one([
          for statement in jsondecode(aws_iam_role_policy.autonomy[role].policy).Statement : statement
          if try(statement.Resource, "") == aws_kms_key.storage.arn
        ]).Condition.StringEquals["kms:EncryptionContext:aws:s3:arn"] == expected.bucket_arn &&
        toset(try(tolist(one([
          for statement in jsondecode(aws_iam_role_policy.autonomy[role].policy).Statement : statement
          if try(statement.Resource, "") == aws_kms_key.storage.arn
          ]).Action), [one([
          for statement in jsondecode(aws_iam_role_policy.autonomy[role].policy).Statement : statement
          if try(statement.Resource, "") == aws_kms_key.storage.arn
        ]).Action])) == toset(expected.actions)
      )
    ]), false)
    error_message = "Every workload storage-key grant must bind S3 in-region and the exact bucket encryption context."
  }
}
