# moj-terraform-scim-entra-id

[![Ministry of Justice Repository Compliance Badge](https://github-community.service.justice.gov.uk/repository-standards/api/moj-terraform-scim-entra-id/badge)](https://github-community.service.justice.gov.uk/repository-standards/moj-terraform-scim-entra-id)

This Terraform module configures a Lambda function for provisioning (and deprovisioning) AWS SSO Identity Store users and groups from EntraID.

The Lambda function used to use the SCIM endpoints (hence its name, _moj-terraform-scim-github_), but now uses the direct [Identity Store API](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Operations.html).
The SCIM API has limitations such as not being able to list more than 50 groups or members (and doesn't support startIndex, so you can't paginate them), whereas the Identity Store API does allow pagination.
This allows us to deprovision users and groups using the Identity Store API, which you cannot do easily with the SCIM API.

This function only syncs EntraID groups that begin with `azure-aws-sso-`

## Usage

```hcl
module "scim" {
  source                = "github.com/ministryofjustice/moj-terraform-scim-entra-id"
  # Required variables for the module
  azure_tenant_id     = "your-tenant-id"
  azure_client_id     = "your-client-id"
  azure_client_secret = "your-client-secret"
}
```

## Monitoring and Alerting

This module includes comprehensive CloudWatch monitoring and alerting. By default, monitoring is **enabled** and creates alarms for:

- Lambda execution errors
- High error rates
- Long execution durations
- Throttling issues
- Scheduled job failures

For detailed configuration options and integration with Slack/PagerDuty, see [MONITORING.md](./MONITORING.md).

### Quick Start - Email Alerts

```hcl
module "scim" {
  source = "github.com/ministryofjustice/moj-terraform-scim-entra-id"

  # Required
  azure_tenant_id     = "your-tenant-id"
  azure_client_id     = "your-client-id"
  azure_client_secret = "your-client-secret"

  # Monitoring
  alarm_email_endpoints = ["team@example.com"]
}
```

### Using Existing SNS Topic (Slack/PagerDuty)

```hcl
module "scim" {
  source = "github.com/ministryofjustice/moj-terraform-scim-entra-id"

  # Required
  azure_tenant_id     = "your-tenant-id"
  azure_client_id     = "your-client-id"
  azure_client_secret = "your-client-secret"

  # Use existing alert channel
  alarm_sns_topic_arn = "arn:aws:sns:eu-west-2:123456789012:platform-alerts"
}
```

<!-- BEGIN_TF_DOCS -->

## Requirements

| Name                                                                     | Version  |
| ------------------------------------------------------------------------ | -------- |
| <a name="requirement_terraform"></a> [terraform](#requirement_terraform) | >= 1.0   |
| <a name="requirement_archive"></a> [archive](#requirement_archive)       | >= 2.4.0 |
| <a name="requirement_aws"></a> [aws](#requirement_aws)                   | >= 5.0.0 |

## Providers

| Name                                                         | Version  |
| ------------------------------------------------------------ | -------- |
| <a name="provider_archive"></a> [archive](#provider_archive) | >= 2.4.0 |
| <a name="provider_aws"></a> [aws](#provider_aws)             | >= 5.0.0 |

## Modules

No modules.

## Resources

| Name                                                                                                                                             | Type        |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------- |
| [aws_cloudwatch_event_rule.lambda_schedule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule)   | resource    |
| [aws_cloudwatch_event_target.lambda_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource    |
| [aws_cloudwatch_log_group.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group)             | resource    |
| [aws_iam_policy.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy)                                 | resource    |
| [aws_iam_role.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role)                                     | resource    |
| [aws_iam_role_policy_attachment.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource    |
| [aws_lambda_function.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function)                       | resource    |
| [aws_lambda_permission.allow_eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission)         | resource    |
| [archive_file.function](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file)                                 | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity)                    | data source |
| [aws_iam_policy_document.assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document)        | data source |
| [aws_iam_policy_document.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document)            | data source |
| [aws_kms_alias.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_alias)                                 | data source |

## Inputs

| Name                                                                                       | Description                           | Type       | Default | Required |
| ------------------------------------------------------------------------------------------ | ------------------------------------- | ---------- | ------- | :------: |
| <a name="input_azure_client_id"></a> [azure_client_id](#input_azure_client_id)             | Client ID for AzureAD application     | `string`   | n/a     |   yes    |
| <a name="input_azure_client_secret"></a> [azure_client_secret](#input_azure_client_secret) | Client Secret for AzureAD application | `string`   | n/a     |   yes    |
| <a name="input_azure_tenant_id"></a> [azure_tenant_id](#input_azure_tenant_id)             | Tenant ID for to use for user sync    | `string`   | n/a     |   yes    |
| <a name="input_tags"></a> [tags](#input_tags)                                              | Tags to apply to resources            | `map(any)` | `{}`    |    no    |

## Outputs

| Name                                                                                            | Description                          |
| ----------------------------------------------------------------------------------------------- | ------------------------------------ |
| <a name="output_lambda_function_name"></a> [lambda_function_name](#output_lambda_function_name) | Name of the deployed Lambda function |

<!-- END_TF_DOCS -->
