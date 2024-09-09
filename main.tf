data "aws_caller_identity" "current" {}

locals {
  name = "entra-id-scim-lambda"
}

# KMS alias for encrypting environment variables, if needed
data "aws_kms_alias" "lambda" {
  name = "alias/aws/lambda"
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
    ]
    resources = [
      "arn:aws:identitystore::${data.aws_caller_identity.current.account_id}:identitystore/*",
      "arn:aws:identitystore:::user/*",
      "arn:aws:identitystore:::group/*",
      "arn:aws:identitystore:::membership/*"
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
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 14
}

data "archive_file" "function" {
  type        = "zip"
  source_dir  = "${path.module}/function"
  output_path = "${path.module}/function.zip"
}

resource "aws_lambda_function" "default" {
  function_name = local.name
  role          = aws_iam_role.default.arn
  handler       = "app.lambda_handler"
  runtime       = "python3.11"

  filename         = data.archive_file.function.output_path
  source_code_hash = data.archive_file.function.output_base64sha256

  kms_key_arn = data.aws_kms_alias.lambda.arn

  environment {
    variables = {
      AZURE_TENANT_ID     = var.azure_tenant_id
      AZURE_CLIENT_ID     = var.azure_client_id
      AZURE_CLIENT_SECRET = var.azure_client_secret
    }
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
