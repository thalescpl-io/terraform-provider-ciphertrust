terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}

provider "ciphertrust" {
  address = "https://52.86.120.81"
  username = "admin"
  password = "KeySecure_1"
  bootstrap = "no"
}

data "ciphertrust_cm_scp_connection_list" "example_scp_connection" {
  filters = {
    labels = "s=S"
  }
}

output "scp_connection_details" {
  value = data.ciphertrust_cm_scp_connection_list.example_scp_connection
}
