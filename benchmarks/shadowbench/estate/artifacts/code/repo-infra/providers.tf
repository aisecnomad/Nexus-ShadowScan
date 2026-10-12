terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.8"
    }
  }
}

provider "aws" {
  region              = "eu-central-1"
  allowed_account_ids = ["210987654321"]
}

provider "azurerm" {
  features {}
  subscription_id = "sub-adatum-1"
}
