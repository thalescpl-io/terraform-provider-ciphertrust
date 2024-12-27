terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}

provider "ciphertrust" {
  address = "https://3.81.114.229"
  username = "admin"
  password = "SamplePassword@1"
  bootstrap = "no"
}

resource "ciphertrust_azure_connection" "azure_connection" {
  name        = "azure-connection"
    products = [
      "cckm"
    ]
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name= "AzureCloud"
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name  = "azure"
  description = "connection description"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }

}

output "azure_connection_id" {
  value = ciphertrust_azure_connection.azure_connection.id
}

output "azure_connection_name" {
  value = ciphertrust_azure_connection.azure_connection.name
}