variable "aws_account_id" {
  description = "Twelve-digit AWS account that owns the autonomy control plane."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be exactly twelve decimal digits."
  }
}

variable "aws_region" {
  description = "AWS region for every control-plane resource."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must be a valid AWS region identifier."
  }
}

variable "name_prefix" {
  description = "Globally unique lowercase prefix used for autonomy resources."
  type        = string
  default     = "carl-autonomy"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,24}$", var.name_prefix))
    error_message = "name_prefix must be 3-25 lowercase letters, digits, or hyphens."
  }
}

variable "vpc_id" {
  description = "VPC containing the private PostgreSQL subnets and cloud execution connector."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must be an AWS VPC identifier."
  }
}

variable "private_subnet_ids" {
  description = "At least two private subnet IDs in distinct availability zones; none may route directly to an internet gateway."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2 && alltrue([for id in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
    error_message = "private_subnet_ids must contain at least two AWS subnet IDs."
  }
}

variable "database_ingress_security_group_ids" {
  description = "Security groups for private cloud executors allowed to reach PostgreSQL; CIDR ingress is never created."
  type        = set(string)

  validation {
    condition     = length(var.database_ingress_security_group_ids) > 0 && alltrue([for id in var.database_ingress_security_group_ids : can(regex("^sg-[0-9a-f]+$", id))])
    error_message = "database_ingress_security_group_ids must contain at least one AWS security group ID."
  }
}

variable "github_repository" {
  description = "Exact owner/repository accepted by GitHub Actions OIDC trust."
  type        = string
  default     = "StephenBickel/carl-agent"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository)) && !strcontains(var.github_repository, "*")
    error_message = "github_repository must be one exact owner/repository without wildcards."
  }
}

variable "github_ref" {
  description = "Exact protected default-branch ref accepted by the coordinator OIDC role."
  type        = string
  default     = "refs/heads/main"

  validation {
    condition     = startswith(var.github_ref, "refs/heads/") && !strcontains(var.github_ref, "*")
    error_message = "github_ref must be one exact branch ref without wildcards."
  }
}

variable "github_environments" {
  description = "Exact protected GitHub Environment names bound to controller-specific OIDC roles."
  type = object({
    builder   = string
    validator = string
    promoter  = string
    soak      = string
    observer  = string
  })
  default = {
    builder   = "carl-autonomy-builder"
    validator = "carl-autonomy-validator"
    promoter  = "carl-autonomy-promoter"
    soak      = "carl-autonomy-soak"
    observer  = "carl-autonomy-observer"
  }

  validation {
    condition     = alltrue([for value in values(var.github_environments) : length(value) > 0 && !strcontains(value, "*") && !strcontains(value, ":")])
    error_message = "GitHub Environment names must be exact non-empty names without wildcards or colons."
  }
}

variable "secret_arns" {
  description = "Existing Secrets Manager ARNs; Terraform never accepts or stores secret values."
  type = object({
    builder_model       = string
    validator_model     = string
    promoter_github_app = string
    soak_github_app     = string
  })

  validation {
    condition = alltrue([
      for arn in values(var.secret_arns) :
      startswith(arn, "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:") && !strcontains(arn, "*")
    ])
    error_message = "Every secret_arns value must be one exact Secrets Manager ARN in aws_account_id and aws_region."
  }
}

variable "database_instance_class" {
  description = "RDS instance class for the transactional autonomy state authority."
  type        = string
  default     = "db.t4g.small"
}

variable "database_engine_version" {
  description = "PostgreSQL engine version pinned to the supported major version 16."
  type        = string
  default     = "16"

  validation {
    condition     = can(regex("^16(\\.[0-9]+)*$", var.database_engine_version))
    error_message = "database_engine_version must select PostgreSQL major version 16."
  }
}

variable "database_allocated_storage_gib" {
  description = "Initial encrypted gp3 storage allocation in GiB."
  type        = number
  default     = 100

  validation {
    condition     = var.database_allocated_storage_gib >= 20
    error_message = "database_allocated_storage_gib must be at least 20 GiB."
  }
}

variable "database_max_allocated_storage_gib" {
  description = "Maximum autoscaled encrypted database storage in GiB."
  type        = number
  default     = 500

  validation {
    condition     = var.database_max_allocated_storage_gib >= var.database_allocated_storage_gib
    error_message = "database_max_allocated_storage_gib cannot be below the initial allocation."
  }
}

variable "database_backup_retention_days" {
  description = "Automated RDS backup retention."
  type        = number
  default     = 35

  validation {
    condition     = var.database_backup_retention_days >= 7 && var.database_backup_retention_days <= 35
    error_message = "database_backup_retention_days must be between 7 and 35 days."
  }
}

variable "input_retention_days" {
  description = "Default Object Lock retention for versioned protected inputs."
  type        = number
  default     = 90

  validation {
    condition     = var.input_retention_days >= 30
    error_message = "input_retention_days must be at least 30 days."
  }
}

variable "evidence_retention_days" {
  description = "Compliance Object Lock retention for immutable evidence and receipts."
  type        = number
  default     = 2555

  validation {
    condition     = var.evidence_retention_days >= 365
    error_message = "evidence_retention_days must be at least 365 days."
  }
}

variable "audit_retention_days" {
  description = "Compliance Object Lock retention for CloudTrail objects."
  type        = number
  default     = 2555

  validation {
    condition     = var.audit_retention_days >= 365
    error_message = "audit_retention_days must be at least 365 days."
  }
}

variable "alarm_topic_arns" {
  description = "Optional exact SNS topic ARNs for CloudWatch alarm actions."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.alarm_topic_arns : startswith(arn, "arn:aws:sns:${var.aws_region}:${var.aws_account_id}:") && !strcontains(arn, "*")])
    error_message = "alarm_topic_arns must contain only exact SNS ARNs in the configured account and region."
  }
}

variable "tags" {
  description = "Additional non-secret tags applied to every supported resource."
  type        = map(string)
  default     = {}
}
