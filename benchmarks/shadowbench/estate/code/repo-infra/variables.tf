variable "environment" {
  type        = string
  description = "Deployment environment tag"
  default     = "prod"
}

variable "bedrock_foundation_model" {
  type        = string
  description = "Model identifier for the dispatch quoting agent"
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}
