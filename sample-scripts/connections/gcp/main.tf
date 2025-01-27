terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}

provider "ciphertrust" {
  address = "https://52.87.160.91"
  username = "admin"
  password = "SamplePassword@1"
  bootstrap = "no"
}

resource "ciphertrust_gcp_connection" "gcp_connection" {
  name        = "gcp-connection"
  products = [
    "cckm"
  ]
  key_file    = "gcp-key-file.json"
  cloud_name  = "gcp"
  description = "connection description"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }

}

output "gcp_connection_id" {
  value = ciphertrust_gcp_connection.gcp_connection.id
}

output "gcp_connection_name" {
  value = ciphertrust_gcp_connection.gcp_connection.name
}