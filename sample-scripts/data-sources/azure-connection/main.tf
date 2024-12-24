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

data "ciphertrust_gcp_connection_list" "example_gcp_connection" {
   filters = {
     labels = "key=value"
   }
}

output "gcp_connection_details" {
  value = data.ciphertrust_gcp_connection_list.example_gcp_connection
}