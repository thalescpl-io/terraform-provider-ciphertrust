terraform {
	required_providers {
	  ciphertrust = {
		source = "thalesgroup.com/oss/ciphertrust"
		version = "1.0.0"
	  }
	}
  }

provider "ciphertrust" {
    address = "https://192.168.2.158"
    username = "admin"
    password = "ChangeIt01!"
    bootstrap = "no"
    alias = "primary"
}

resource "ciphertrust_cte_client" "cte_client" {
    provider = ciphertrust.primary
    name        = "TF_CTE_Client"
    client_type = "FS"
    registration_allowed = true
    communication_enabled = true
    description = "Created via TF"
    password_creation_method = "GENERATE"
    labels = {
      color = "blue"
    }
}