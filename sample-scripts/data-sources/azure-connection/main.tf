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
  password = "Zxcv1234."
  bootstrap = "no"
}

data "ciphertrust_azure_connection_list" "example_azure_connection" {
   filters = {
     labels = "key=value"
   }
}

output "azure_connection_details" {
  value = data.ciphertrust_azure_connection_list.example_azure_connection
}