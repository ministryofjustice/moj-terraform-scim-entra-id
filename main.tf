data "aws_caller_identity" "current" {}

locals {
  name = "entra-id-scim-lambda"
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "default" {
  #checkov:skip=CKV_AWS_158:Won't implement
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.default.arn}:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "identitystore:CreateGroup",
      "identitystore:CreateGroupMembership",
      "identitystore:CreateUser",
      "identitystore:DeleteGroup",
      "identitystore:DeleteGroupMembership",
      "identitystore:DeleteUser",
      "identitystore:DescribeGroup",
      "identitystore:DescribeGroupMembership",
      "identitystore:ListGroupMemberships",
      "identitystore:ListGroups",
      "identitystore:ListUsers",
      "identitystore:DescribeUser",
    ]
    resources = [
      "arn:aws:identitystore::${data.aws_caller_identity.current.account_id}:identitystore/*",
      "arn:aws:identitystore:::user/*",
      "arn:aws:identitystore:::group/*",
      "arn:aws:identitystore:::membership/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "sso:ListInstances",
    ]
    resources = [
      "arn:aws:sso:::instance/*"
    ]
  }
}

resource "aws_iam_policy" "default" {
  name   = local.name
  policy = data.aws_iam_policy_document.default.json
}

resource "aws_iam_role" "default" {
  name               = "${local.name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "default" {
  role       = aws_iam_role.default.name
  policy_arn = aws_iam_policy.default.arn
}

resource "aws_cloudwatch_log_group" "default" {
  #checkov:skip=CKV_AWS_158:Won't implement
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 365
}

data "archive_file" "function" {
  type        = "zip"
  source_dir  = "${path.module}/function"
  output_path = "${path.module}/function.zip"
}

resource "aws_lambda_function" "default" {
  #checkov:skip=CKV_AWS_116:No DLQ needed for this function
  #checkov:skip=CKV_AWS_115:No function-level concurrency limit required
  #checkov:skip=CKV_AWS_272:No code-signing configuration required
  #checkov:skip=CKV_AWS_117:Not configuring a VPC for this Lambda
  #checkov:skip=CKV_AWS_173:All sensitive envvars are retrieved from secrets manager
  #checkov:skip=CKV_AWS_158:Won't implement
  #ts:skip=AWS.LambdaFunction.Logging.0472:No VPC configuration needed for this Lambda function
  #ts:skip=AWS.LambdaFunction.EncryptionandKeyManagement.0471:Sensitive vars are read from secrets manager

  function_name = local.name
  role          = aws_iam_role.default.arn
  handler       = "app.lambda_handler"
  runtime       = "python3.11"
  timeout       = 300

  filename         = data.archive_file.function.output_path
  source_code_hash = data.archive_file.function.output_base64sha256

  environment {
    variables = {
      AZURE_TENANT_ID     = var.azure_tenant_id
      AZURE_CLIENT_ID     = var.azure_client_id
      AZURE_CLIENT_SECRET = var.azure_client_secret
    }
  }

  # Enable X-Ray tracing
  tracing_config {
    mode = "Active" # Enables active tracing for Lambda function
  }

  tags = var.tags
}

# Schedule rule to trigger the Lambda function every 2 hours
resource "aws_cloudwatch_event_rule" "lambda_schedule" {
  name                = "${local.name}-schedule"
  description         = "Scheduled rule to trigger the EntraID SCIM Lambda function"
  schedule_expression = "rate(2 hours)" # Triggers the function every 2 hours
}

# Target for the CloudWatch event rule to invoke the Lambda function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.lambda_schedule.name
  target_id = local.name
  arn       = aws_lambda_function.default.arn

  input = jsonencode({
    "dry_run" = "False"
  })
}

# Permission for CloudWatch Events to invoke the Lambda function
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.default.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_schedule.arn
}

# ========================================
# Monitoring and Alerting Resources
# ========================================

# SNS Topic for Lambda alarms
resource "aws_sns_topic" "lambda_alarms" {
  count = var.enable_monitoring && var.alarm_sns_topic_arn == "" ? 1 : 0

  name              = "${local.name}-alarms"
  display_name      = "SCIM Lambda Alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = var.tags
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "lambda_alarms" {
  count = var.enable_monitoring && var.alarm_sns_topic_arn == "" ? 1 : 0

  arn = aws_sns_topic.lambda_alarms[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.lambda_alarms[0].arn
      }
    ]
  })
}

# Email subscriptions for SNS topic
resource "aws_sns_topic_subscription" "email" {
  count = var.enable_monitoring && var.alarm_sns_topic_arn == "" ? length(var.alarm_email_endpoints) : 0

  topic_arn = aws_sns_topic.lambda_alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email_endpoints[count.index]
}

# Local variable for SNS topic ARN (use existing or newly created)
locals {
  sns_topic_arn = var.enable_monitoring ? (
    var.alarm_sns_topic_arn != "" ? var.alarm_sns_topic_arn : try(aws_sns_topic.lambda_alarms[0].arn, "")
  ) : ""
}

# CloudWatch Alarm: Lambda Errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count = var.enable_monitoring && var.enable_error_alarm ? 1 : 0

  alarm_name          = "${local.name}-errors"
  alarm_description   = "Alerts when Lambda function has errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.error_alarm_evaluation_periods
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = var.error_alarm_period
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.default.function_name
  }

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = var.tags
}

# CloudWatch Alarm: Lambda Error Rate
resource "aws_cloudwatch_metric_alarm" "lambda_error_rate" {
  count = var.enable_monitoring && var.enable_error_rate_alarm ? 1 : 0

  alarm_name          = "${local.name}-error-rate"
  alarm_description   = "Alerts when Lambda error rate exceeds ${var.error_rate_threshold}%"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.error_rate_alarm_evaluation_periods
  threshold           = var.error_rate_threshold
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "error_rate"
    expression  = "(errors / invocations) * 100"
    label       = "Error Rate (%)"
    return_data = true
  }

  metric_query {
    id = "errors"
    metric {
      metric_name = "Errors"
      namespace   = "AWS/Lambda"
      period      = var.error_rate_alarm_period
      stat        = "Sum"
      dimensions = {
        FunctionName = aws_lambda_function.default.function_name
      }
    }
  }

  metric_query {
    id = "invocations"
    metric {
      metric_name = "Invocations"
      namespace   = "AWS/Lambda"
      period      = var.error_rate_alarm_period
      stat        = "Sum"
      dimensions = {
        FunctionName = aws_lambda_function.default.function_name
      }
    }
  }

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = var.tags
}

# CloudWatch Alarm: Lambda Duration
resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  count = var.enable_monitoring && var.enable_duration_alarm ? 1 : 0

  alarm_name          = "${local.name}-duration"
  alarm_description   = "Alerts when Lambda duration approaches timeout (${var.duration_threshold_ms}ms)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.duration_alarm_evaluation_periods
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = var.duration_alarm_period
  statistic           = "Maximum"
  threshold           = var.duration_threshold_ms
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.default.function_name
  }

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = var.tags
}

# CloudWatch Alarm: Lambda Throttles
resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  count = var.enable_monitoring && var.enable_throttle_alarm ? 1 : 0

  alarm_name          = "${local.name}-throttles"
  alarm_description   = "Alerts when Lambda function is throttled"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.throttle_alarm_evaluation_periods
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = var.throttle_alarm_period
  statistic           = "Sum"
  threshold           = var.throttle_threshold
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.default.function_name
  }

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = var.tags
}

# CloudWatch Alarm: Scheduled Job Failure
resource "aws_cloudwatch_metric_alarm" "scheduled_job_failure" {
  count = var.enable_monitoring && var.enable_scheduled_job_alarm ? 1 : 0

  alarm_name          = "${local.name}-scheduled-failure"
  alarm_description   = "Alerts when scheduled Lambda invocation fails"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.scheduled_job_alarm_evaluation_periods
  metric_name         = "FailedInvocations"
  namespace           = "AWS/Events"
  period              = var.scheduled_job_alarm_period
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    RuleName = aws_cloudwatch_event_rule.lambda_schedule.name
  }

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = var.tags
}
