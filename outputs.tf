output "lambda_function_name" {
  description = "Name of the deployed Lambda function"
  value       = aws_lambda_function.default.function_name
}

output "lambda_function_arn" {
  description = "ARN of the deployed Lambda function"
  value       = aws_lambda_function.default.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for the Lambda function"
  value       = aws_cloudwatch_log_group.default.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for Lambda alarms (if monitoring is enabled)"
  value       = var.enable_monitoring ? local.sns_topic_arn : null
}

output "alarm_names" {
  description = "Names of all CloudWatch alarms created for monitoring"
  value = var.enable_monitoring ? [
    try(aws_cloudwatch_metric_alarm.lambda_errors[0].alarm_name, ""),
    try(aws_cloudwatch_metric_alarm.lambda_error_rate[0].alarm_name, ""),
    try(aws_cloudwatch_metric_alarm.lambda_duration[0].alarm_name, ""),
    try(aws_cloudwatch_metric_alarm.lambda_throttles[0].alarm_name, ""),
    try(aws_cloudwatch_metric_alarm.scheduled_job_failure[0].alarm_name, "")
  ] : []
}
