terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Configure via -backend-config flags or backend.hcl
    # bucket         = "your-tfstate-bucket"
    # key            = "security-baseline/terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "your-lock-table"
    # encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "security-baseline"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "security-team"
    }
  }
}

# ---------------------------------------------------------------------------
# VPC — 3-tier network with flow logs
# ---------------------------------------------------------------------------
module "vpc" {
  source             = "./modules/vpc"
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  environment        = var.environment
  log_bucket_arn     = module.s3_logs.bucket_arn
}

# ---------------------------------------------------------------------------
# KMS — one CMK per logical service; automatic rotation enabled
# ---------------------------------------------------------------------------
module "kms" {
  source      = "./modules/kms"
  environment = var.environment
  services    = ["s3", "ebs", "secrets-manager", "cloudtrail"]
}

# ---------------------------------------------------------------------------
# S3 — centralised log bucket (encrypted, versioned, MFA Delete)
# ---------------------------------------------------------------------------
module "s3_logs" {
  source      = "./modules/s3"
  bucket_name = "${var.environment}-security-logs-${var.aws_account_id}"
  kms_key_arn = module.kms.key_arns["s3"]
  environment = var.environment
  purpose     = "logs"
  mfa_delete  = false # set true after MFA device enrolled on root
}

# ---------------------------------------------------------------------------
# IAM — least-privilege roles with permission boundaries
# ---------------------------------------------------------------------------
module "iam" {
  source      = "./modules/iam"
  environment = var.environment
}

# ---------------------------------------------------------------------------
# GuardDuty — threat detection with SNS alerts
# ---------------------------------------------------------------------------
module "guardduty" {
  source         = "./modules/guardduty"
  environment    = var.environment
  alert_email    = var.security_alert_email
}

# ---------------------------------------------------------------------------
# CloudTrail — immutable, encrypted audit log in all regions
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-cloudtrail"
  s3_bucket_name                = module.s3_logs.bucket_id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = module.kms.key_arns["cloudtrail"]

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  tags = {
    Name = "${var.environment}-cloudtrail"
  }
}

# ---------------------------------------------------------------------------
# Config — continuous compliance evaluation
# ---------------------------------------------------------------------------
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.environment}-config-recorder"
  role_arn = module.iam.config_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.environment}-config-delivery"
  s3_bucket_name = module.s3_logs.bucket_id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}
