# modules/kms/main.tf
# One CMK per service with automatic annual rotation.
# Key policies follow least-privilege: only specified principals
# can use the key; only the security team can administer it.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_kms_key" "service" {
  for_each = toset(var.services)

  description             = "CMK for ${each.key} — ${var.environment}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRootAccountFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/security-admin"
        }
        Action = [
          "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
          "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
          "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
          "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowServiceUsage"
        Effect = "Allow"
        Principal = {
          Service = "${each.key}.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "aws:SourceRegion"  = data.aws_region.current.name
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-cmk-${each.key}"
    Service     = each.key
    Environment = var.environment
  }
}

resource "aws_kms_alias" "service" {
  for_each      = toset(var.services)
  name          = "alias/${var.environment}-${each.key}"
  target_key_id = aws_kms_key.service[each.key].id
}
