# Monitoring and Alerting

This document describes the monitoring and alerting configuration for the EntraID SCIM Lambda function.

## Overview

The module includes comprehensive CloudWatch monitoring with alarms for various failure scenarios. When enabled, it creates:

- **SNS Topic** for alert notifications
- **CloudWatch Alarms** for errors, throttles, duration, and scheduled job failures
- **Email subscriptions** (optional)
- **Integration support** for Slack, PagerDuty, or other notification services

## CloudWatch Alarms

### 1. Lambda Errors Alarm

- **Metric**: `AWS/Lambda` - Errors
- **Threshold**: Any error (> 0)
- **Period**: 5 minutes
- **Purpose**: Detects any Lambda execution errors

### 2. Lambda Error Rate Alarm

- **Metric**: Calculated error rate percentage
- **Threshold**: Configurable (default: 5%)
- **Period**: 10 minutes (2 evaluation periods)
- **Purpose**: Alerts on sustained high error rates

### 3. Lambda Duration Alarm

- **Metric**: `AWS/Lambda` - Duration
- **Threshold**: Configurable (default: 270,000ms = 4.5 minutes)
- **Period**: 5 minutes
- **Purpose**: Warns when executions approach the 5-minute timeout

### 4. Lambda Throttles Alarm

- **Metric**: `AWS/Lambda` - Throttles
- **Threshold**: Any throttle (> 0)
- **Period**: 5 minutes
- **Purpose**: Detects when function is being rate-limited

### 5. Scheduled Job Failure Alarm

- **Metric**: `AWS/Events` - FailedInvocations
- **Threshold**: Any failure (> 0)
- **Period**: 2 hours (matches schedule)
- **Purpose**: Alerts when EventBridge fails to invoke the Lambda

## Configuration

### Basic Setup (Email Notifications)

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # Required variables
  azure_tenant_id     = var.azure_tenant_id
  azure_client_id     = var.azure_client_id
  azure_client_secret = var.azure_client_secret

  # Monitoring configuration
  enable_monitoring      = true
  alarm_email_endpoints  = [
    "team@example.com",
    "oncall@example.com"
  ]
}
```

### Using Existing SNS Topic (e.g., for Slack/PagerDuty)

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # Required variables
  azure_tenant_id     = var.azure_tenant_id
  azure_client_id     = var.azure_client_id
  azure_client_secret = var.azure_client_secret

  # Use existing SNS topic already integrated with Slack/PagerDuty
  enable_monitoring   = true
  alarm_sns_topic_arn = "arn:aws:sns:eu-west-2:123456789012:platform-alerts"
}
```

### Custom Thresholds

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # Required variables
  azure_tenant_id     = var.azure_tenant_id
  azure_client_id     = var.azure_client_id
  azure_client_secret = var.azure_client_secret

  # Monitoring with custom thresholds
  enable_monitoring       = true
  alarm_email_endpoints   = ["team@example.com"]
  error_rate_threshold    = 10      # Alert at 10% error rate
  duration_threshold_ms   = 240000  # Alert at 4 minutes
  throttle_threshold      = 5       # Alert after 5 throttles
}
```

### Disable Monitoring

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # Required variables
  azure_tenant_id     = var.azure_tenant_id
  azure_client_id     = var.azure_client_id
  azure_client_secret = var.azure_client_secret

  # Disable monitoring
  enable_monitoring = false
}
```

### Selective Alarm Configuration

Disable specific alarms while keeping others enabled:

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # Required variables
  azure_tenant_id     = var.azure_tenant_id
  azure_client_id     = var.azure_client_id
  azure_client_secret = var.azure_client_secret

  # Enable monitoring but disable specific alarms
  enable_monitoring         = true
  alarm_email_endpoints     = ["team@example.com"]

  # Disable throttle alarm if not needed
  enable_throttle_alarm     = false

  # Disable duration alarm if execution time is not critical
  enable_duration_alarm     = false

  # Keep error alarms enabled
  enable_error_alarm        = true
  enable_error_rate_alarm   = true
  enable_scheduled_job_alarm = true
}
```

### Advanced Configuration

Full control over alarm behavior:

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # Required variables
  azure_tenant_id     = var.azure_tenant_id
  azure_client_id     = var.azure_client_id
  azure_client_secret = var.azure_client_secret

  # Monitoring configuration
  enable_monitoring       = true
  alarm_sns_topic_arn     = "arn:aws:sns:eu-west-2:123456789012:platform-alerts"

  # Threshold configuration
  error_rate_threshold    = 10
  duration_threshold_ms   = 240000
  throttle_threshold      = 5

  # Evaluation periods (how many consecutive periods must breach before alarming)
  error_alarm_evaluation_periods            = 1   # Alarm immediately on any error
  error_rate_alarm_evaluation_periods       = 2   # Wait for 2 consecutive periods
  duration_alarm_evaluation_periods         = 2   # Wait for 2 consecutive periods
  throttle_alarm_evaluation_periods         = 1   # Alarm immediately
  scheduled_job_alarm_evaluation_periods    = 1   # Alarm immediately

  # Alarm periods (time window in seconds for metric evaluation)
  error_alarm_period                        = 300   # 5 minutes
  error_rate_alarm_period                   = 600   # 10 minutes
  duration_alarm_period                     = 300   # 5 minutes
  throttle_alarm_period                     = 300   # 5 minutes
  scheduled_job_alarm_period                = 7200  # 2 hours (matches schedule)

  # Individual alarm toggles
  enable_error_alarm                        = true
  enable_error_rate_alarm                   = true
  enable_duration_alarm                     = true
  enable_throttle_alarm                     = false  # Disable if not needed
  enable_scheduled_job_alarm                = true
}
```

## Integrating with Slack

### Option 1: AWS Chatbot (Recommended)

1. Create an AWS Chatbot configuration in the AWS Console
2. Connect it to your Slack workspace and channel
3. Use the Chatbot's SNS topic ARN:

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # ... required variables ...

  enable_monitoring   = true
  alarm_sns_topic_arn = "arn:aws:sns:eu-west-2:123456789012:chatbot-slack-topic"
}
```

### Option 2: Lambda Webhook Forwarder

Create a Lambda function that forwards SNS notifications to Slack webhook and subscribe it to the SNS topic.

## Integrating with PagerDuty

1. Create a PagerDuty service with AWS CloudWatch integration
2. PagerDuty will provide an SNS topic ARN
3. Use that ARN in the module configuration:

```hcl
module "entra_id_scim_lambda" {
  source = "git::https://github.com/ministryofjustice/moj-terraform-scim-entra-id.git"

  # ... required variables ...

  enable_monitoring   = true
  alarm_sns_topic_arn = "arn:aws:sns:eu-west-2:123456789012:pagerduty-cloudwatch"
}
```

## Configuration Reference

### Core Monitoring Variables

| Variable                | Type         | Default | Description                                    |
| ----------------------- | ------------ | ------- | ---------------------------------------------- |
| `enable_monitoring`     | bool         | `true`  | Master switch to enable/disable all monitoring |
| `alarm_email_endpoints` | list(string) | `[]`    | Email addresses for alarm notifications        |
| `alarm_sns_topic_arn`   | string       | `""`    | Existing SNS topic ARN (creates new if empty)  |

### Alarm Enable/Disable Toggles

| Variable                     | Type | Default | Description                                 |
| ---------------------------- | ---- | ------- | ------------------------------------------- |
| `enable_error_alarm`         | bool | `true`  | Enable alarm for any Lambda errors          |
| `enable_error_rate_alarm`    | bool | `true`  | Enable alarm for high error rate percentage |
| `enable_duration_alarm`      | bool | `true`  | Enable alarm for long execution duration    |
| `enable_throttle_alarm`      | bool | `true`  | Enable alarm for throttled invocations      |
| `enable_scheduled_job_alarm` | bool | `true`  | Enable alarm for scheduled job failures     |

### Threshold Configuration

| Variable                | Type   | Default  | Description                                       |
| ----------------------- | ------ | -------- | ------------------------------------------------- |
| `error_rate_threshold`  | number | `5`      | Error rate percentage (0-100) that triggers alarm |
| `duration_threshold_ms` | number | `270000` | Duration in milliseconds (default: 4.5 minutes)   |
| `throttle_threshold`    | number | `1`      | Number of throttles that triggers alarm           |

### Evaluation Periods

Number of consecutive periods that must breach threshold before alarming:

| Variable                                 | Type   | Default | Description                                |
| ---------------------------------------- | ------ | ------- | ------------------------------------------ |
| `error_alarm_evaluation_periods`         | number | `1`     | Evaluation periods for error alarm         |
| `error_rate_alarm_evaluation_periods`    | number | `2`     | Evaluation periods for error rate alarm    |
| `duration_alarm_evaluation_periods`      | number | `1`     | Evaluation periods for duration alarm      |
| `throttle_alarm_evaluation_periods`      | number | `1`     | Evaluation periods for throttle alarm      |
| `scheduled_job_alarm_evaluation_periods` | number | `1`     | Evaluation periods for scheduled job alarm |

### Alarm Periods

Time window in seconds for metric evaluation:

| Variable                     | Type   | Default | Description                              |
| ---------------------------- | ------ | ------- | ---------------------------------------- |
| `error_alarm_period`         | number | `300`   | Period for error alarm (5 minutes)       |
| `error_rate_alarm_period`    | number | `300`   | Period for error rate alarm (5 minutes)  |
| `duration_alarm_period`      | number | `300`   | Period for duration alarm (5 minutes)    |
| `throttle_alarm_period`      | number | `300`   | Period for throttle alarm (5 minutes)    |
| `scheduled_job_alarm_period` | number | `7200`  | Period for scheduled job alarm (2 hours) |

## Viewing Metrics

### CloudWatch Dashboard

You can view Lambda metrics in the CloudWatch console:

1. Navigate to CloudWatch → Dashboards
2. View Lambda metrics under `AWS/Lambda` namespace
3. Filter by function name: `entra-id-scim-lambda`

### Key Metrics to Monitor

- **Invocations**: Total number of times the function is invoked
- **Errors**: Number of failed invocations
- **Duration**: How long the function takes to execute
- **Throttles**: Number of throttled invocation attempts
- **Concurrent Executions**: Number of function instances processing events

### CloudWatch Logs Insights Queries

Useful queries for investigating issues:

#### Find all errors

```sql
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 100
```

#### Execution duration statistics

```sql
fields @duration
| stats avg(@duration), max(@duration), min(@duration), count()
```

#### Failed sync operations

```sql
fields @timestamp, @message
| filter @message like /Error/
| parse @message /Error: (?<error_details>.*)/
| stats count() by error_details
```

## Testing Alerts

### Test Email Subscription

After applying the Terraform configuration with email endpoints:

1. Check the email inbox(es) for SNS subscription confirmation
2. Click the confirmation link in each email
3. Verify subscriptions in AWS Console → SNS → Subscriptions

### Trigger Test Alarm

You can manually set an alarm to trigger state to test notifications:

```bash
aws cloudwatch set-alarm-state \
  --alarm-name "entra-id-scim-lambda-errors" \
  --state-value ALARM \
  --state-reason "Testing alert delivery" \
  --region eu-west-2
```

Then return it to OK:

```bash
aws cloudwatch set-alarm-state \
  --alarm-name "entra-id-scim-lambda-errors" \
  --state-value OK \
  --state-reason "Test complete" \
  --region eu-west-2
```

## Troubleshooting

### No Alerts Received

1. **Check SNS Subscriptions**: Verify subscriptions are confirmed

   ```bash
   aws sns list-subscriptions-by-topic \
     --topic-arn <topic-arn> \
     --region eu-west-2
   ```

2. **Check Alarm State**: Verify alarm is actually in ALARM state

   ```bash
   aws cloudwatch describe-alarms \
     --alarm-names "entra-id-scim-lambda-errors" \
     --region eu-west-2
   ```

3. **Check CloudWatch Logs**: Verify Lambda is actually being invoked
   ```bash
   aws logs tail /aws/lambda/entra-id-scim-lambda --follow
   ```

### Alarm Not Triggering

- Verify the metric is actually being recorded
- Check the evaluation period and threshold settings
- Review CloudWatch Logs for the Lambda function

### Too Many Alerts

Adjust thresholds in the module configuration:

- Increase `error_rate_threshold`
- Increase `duration_threshold_ms`
- Increase `throttle_threshold`

## Cost Considerations

- **CloudWatch Alarms**: $0.10 per alarm per month (5 alarms = $0.50/month)
- **SNS**: First 1,000 notifications free, then $0.50 per million notifications
- **CloudWatch Logs**: Already included in Lambda execution
- **Metrics**: Standard Lambda metrics are free

Total estimated cost: **~$1-2/month** for full monitoring setup.

## Ownership and Maintenance

- **Owner**: Modernisation Platform Team
- **Escalation**: [Team contact/channel]
- **Documentation**: This file and inline Terraform comments
- **Review Schedule**: Quarterly review of alarm thresholds and alert routing

## References

- [AWS Lambda Monitoring](https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html)
- [CloudWatch Alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html)
- [AWS Chatbot](https://aws.amazon.com/chatbot/)
- [PagerDuty AWS Integration](https://support.pagerduty.com/docs/aws-cloudwatch-integration-guide)
