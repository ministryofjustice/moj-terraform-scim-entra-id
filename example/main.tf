terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = "eu-west-2"
}

module "entra_id_scim_lambda" {
  source = "../."

  # Required variables for the module
  azure_tenant_id     = "your-tenant-id"     # Replace with your Azure Tenant ID
  azure_client_id     = "your-client-id"     # Replace with your Azure Client ID
  azure_client_secret = "your-client-secret" # Replace with your Azure Client Secret
}
