variable "azure_tenant_id" {
  type        = string
  description = "Tenant ID for to use for user sync"
  sensitive   = true
}

variable "azure_client_id" {
  type        = string
  description = "Client ID for AzureAD application"
  sensitive   = true
}

variable "azure_client_secret" {
  type        = string
  description = "Client Secret for AzureAD application"
  sensitive   = true
}


variable "tags" {
  type        = map(any)
  description = "Tags to apply to resources"
  default     = {}
}
