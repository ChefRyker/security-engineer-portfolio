# modules/guardduty/main.tf
# Enables GuardDuty with SNS alerting for HIGH and CRITICAL findings.
# EventBridge rule filters findings before sending to SNS.

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name        = "${var.environment}-guardduty"
    Environment = var.environment
  }
}

# SNS topic for alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "${var.environment}-guardduty-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name        = "${var.environment}-guardduty-alerts"
    Environment = var.environment
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SNS topic policy — only EventBridge can publish
resource "aws_sns_topic_policy" "guardduty_alerts" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowEventBridgePublish"
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}

# EventBridge rule: only HIGH and CRITICAL findings trigger alerts
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.environment}-guardduty-high-findings"
  description = "Capture GuardDuty HIGH and CRITICAL severity findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })

  tags = {
    Name        = "${var.environment}-guardduty-findings-rule"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      description = "$.detail.description"
      region      = "$.region"
      account     = "$.account"
      time        = "$.time"
    }
    input_template = <<-EOT
      "GuardDuty Finding — <type>"
      "Severity: <severity> | Account: <account> | Region: <region> | Time: <time>"
      "<description>"
    EOT
  }
}
