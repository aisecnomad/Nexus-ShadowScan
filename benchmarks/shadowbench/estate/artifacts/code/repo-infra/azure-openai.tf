resource "azurerm_resource_group" "dock_ai" {
  name     = "rg-adatum-dock"
  location = "westeurope"
}

resource "azurerm_cognitive_account" "dock_openai" {
  name                  = "adatum-dock-aoai"
  location              = azurerm_resource_group.dock_ai.location
  resource_group_name   = azurerm_resource_group.dock_ai.name
  kind                  = "OpenAI"
  sku_name              = "S0"
  custom_subdomain_name = "adatum-dock-aoai"

  tags = {
    environment = var.environment
    team        = "dock-docs"
  }
}

resource "azurerm_cognitive_deployment" "dock_chat" {
  name                 = "dock-chat"
  cognitive_account_id = azurerm_cognitive_account.dock_openai.id

  model {
    format  = "OpenAI"
    name    = "gpt-35-turbo"
    version = "0125"
  }

  sku {
    name     = "Standard"
    capacity = 30
  }
}
