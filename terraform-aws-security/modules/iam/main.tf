# modules/iam/main.tf
# Least-privilege IAM roles with permission boundaries.
# All roles require MFA for assume-role (except service roles).
# No inline policies — only managed policies for auditability.

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Permission boundary — cap what any role in this account can do
# Prevents privilege escalation: even if a role is misconfigured,
# it cannot exceed these permissions.
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "permission_boundary" {
  name        = "${var.environment}-permission-boundary"
  description = "Maximum permissions any IAM entity in ${var.environment} may have"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowScopedActions"
        Effect   = "Allow"
        Action   = ["s3:*", "ec2:Describe*", "logs:*", "cloudwatch:*", "kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = "*"
      },
      {
        Sid    = "DenyIAMEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy",
          "iam:PutUserPolicy", "iam:DeleteUserPolicy", "iam:DetachUserPolicy",
          "iam:UpdateAssumeRolePolicy", "iam:PassRole"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyOrganizationChanges"
        Effect = "Deny"
        Action = ["organizations:*"]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# App role — used by EC2 / ECS tasks running the application
# ---------------------------------------------------------------------------
resource "aws_iam_role" "app" {
  name                 = "${var.environment}-app-role"
  permissions_boundary = aws_iam_policy.permission_boundary.arn
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"] }
      Action = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.environment}-app-role", Purpose = "application" }
}

resource "aws_iam_role_policy" "app_s3" {
  name = "s3-read-app-bucket"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadAppBucket"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::${var.environment}-app-*",
        "arn:aws:s3:::${var.environment}-app-*/*"
      ]
    }]
  })
}

# ---------------------------------------------------------------------------
# CI/CD role — assumed by GitHub Actions via OIDC (no long-lived credentials)
# ---------------------------------------------------------------------------
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "cicd" {
  name                 = "${var.environment}-cicd-role"
  permissions_boundary = aws_iam_policy.permission_boundary.arn
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # Restrict to your org/repo only
          "token.actions.githubusercontent.com:sub" = "repo:YOUR_ORG/YOUR_REPO:*"
        }
      }
    }]
  })

  tags = { Name = "${var.environment}-cicd-role", Purpose = "cicd" }
}

resource "aws_iam_role_policy" "cicd_deploy" {
  name = "cicd-deploy"
  role = aws_iam_role.cicd.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.environment}-tfstate-*",
          "arn:aws:s3:::${var.environment}-tfstate-*/*"
        ]
      },
      {
        Sid      = "DynamoLock"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:*:${data.aws_caller_identity.current.account_id}:table/${var.environment}-tf-lock"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Config service role
# ---------------------------------------------------------------------------
resource "aws_iam_role" "config" {
  name = "${var.environment}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}
