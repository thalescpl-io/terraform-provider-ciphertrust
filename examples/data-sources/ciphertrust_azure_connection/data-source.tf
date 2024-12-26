# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the Azure connection.

terraform {
  # Specify required providers
  required_providers {
    ciphertrust = {
      # Source location for the CipherTrust provider
      source = "thalesgroup.com/oss/ciphertrust"
      # Version of the provider to be used
      version = "1.0.0"
    }
  }
}

# Configuration for the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance
  # Replace with the actual address of your CipherTrust instance
  address = "https://52.87.160.91"

  # Username to authenticate against the CipherTrust appliance
  username = "admin"

  # Password to authenticate against the CipherTrust appliance
  password = "SamplePassword@1"

  bootstrap = "no"
}

# Data source for retrieving Azure connection details
data "ciphertrust_azure_connection_list" "example_azure_connection" {
  # Filters to narrow down the Azure connections
  filters = {
    # The unique ID of the Azure connection to fetch
    id = "88a90d8f-05b5-419f-bbe9-2dc3aa8ec216"
  }
  # Similarly can provide 'name', 'labels' etc to fetch the existing Azure connection
  # example for fetching an existing azure connection with labels
  # filters = {
  #   labels = "key=value"
  # }
}

# Output the details of the Azure connection
output "azure_connection_details" {
  # The value of the Azure connection details returned by the data source
  value = data.ciphertrust_azure_connection_list.example_azure_connection
}
