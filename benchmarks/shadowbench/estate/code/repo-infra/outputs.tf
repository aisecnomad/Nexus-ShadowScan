output "dispatch_quoter_agent_id" {
  description = "Bedrock agent id consumed by the dispatch desk tooling"
  value       = aws_bedrockagent_agent.dispatch_quoter.agent_id
}

output "azure_openai_endpoint" {
  description = "Endpoint for the dock document deployment"
  value       = "https://${azurerm_cognitive_account.dock_openai.custom_subdomain_name}.openai.azure.com/"
}
