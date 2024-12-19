# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an GCP connection resource
# with the CipherTrust provider, including setting up GCP connection details,
# labels, and custom metadata.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "thalesgroup.com/oss/ciphertrust"
      # Version of the provider to use
      version = "1.0.0"
    }
  }
}

# Configure the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance (replace with the actual address)
  address = "https://52.87.160.91"

  # Username for authenticating with the CipherTrust appliance
  username = "admin"

  # Password for authenticating with the CipherTrust appliance
  password = "SamplePassword@1"

  bootstrap = "no"
}



# Define an GCP connection resource with CipherTrust
resource "ciphertrust_gcp_connection" "gcp_connection" {
  # Name of the GCP connection (unique identifier)
  name        = "gcp-connection"

  # List of products associated with this GCP connection
  # In this case, it's related to cckm
  products = [
    "cckm"
  ]

  # The contents of private key file of a GCP service account.
  key_file    = "{\"type\":\"service_account\",\"private_key_id\":\"y437c51g956b8ab4908yb41541262a2fa3b0f84f\",\"private_key\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQDnC1YYTtcpsbj6cV9M/1rOhEYWG9iNdnsMCK0AjMRtb79toU2v\\nyW0JfJR/sR2vqFMD1wJFgpayqo5GDPa8Us23I/vvyWCkatouGYO27r84y5G2h74a\\nZnnEaK7uLQ2OdGNHWcZv8gZhy7X5e6RJfKVVlYrgYtfEKv55E9dQSZrohQIDAQAB\\nAoGAbzre7P7vyQvdkPyJs+jvj6LQlw462AflPyriFvSuED2PPDk+zFU9oCaQ21Sq\\nhQmVRbD6T/qJkGRZ8FGHa6y1if6UVbUymr+0a1hIM7BbPwsG2hLXznYjXWZ8WFDb\\nQyRWTZh4Zj0Br2DtoRjQOG8CHhC7LuFx434acu12VXxN8vUCQQDtS8GRzktOWRBL\\n2l7MWCja3lkqyYR2Ns+tw79eEAYVrGsFZLu6gAMdmn53M+eO5h++Ypr7G+bazvwC\\nD1XtiN+7AkEA+UFuq04YR3lTpCN1OeJ0VKXatVMFMjAejulHF3d3tRc4pIfAjgTk\\n4M+K9y++4QtVdhsGO9sk1jwfHrRTn340vwJBAIJ25DYF9eFdllgd94Dh95ReKygb\\nI3jbKdOfi9drd+zynuSYPZ6MQypDhsSDBQzL+SfzjsIA1Sv4IRYA2H2Ag4ECQAYw\\nHKo+DxY/KddqVe+w8ohjcbGMtRVQ4oFTw0MO4Tbqs6pKAHrGHlSCcoW+drOpj16W\\nPypfP2PeLDub6HOOM4sCQGWUXaHqJzfy2nHRAkr9WJEGgEMCMlGtFuMPH/Jc7aUt\\nNXk9HfcpVO/spIVpyL7x480hq5DHn7KaGwi+Lk2W0A8=\\n-----END RSA PRIVATE KEY-----\\n\\n\",\"client_email\":\"test@some-project.iam.gserviceaccount.com\"}"

  # Name of the cloud. Default value is gcp.
  cloud_name  = "gcp"

  # Description of the GCP connection
  description = "connection description"

  # Labels for categorizing the GCP connection
  labels = {
    "environment" = "devenv"
  }

  # Custom metadata for the GCP connection
  # This can be used to store additional information related to the GCP connection
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }

}

# Output the unique ID of the created GCP connection
output "gcp_connection_id" {
  # The value will be the ID of the GCP connection resource
  value = ciphertrust_gcp_connection.gcp_connection.id
}

# Output the name of the created GCP connection
output "gcp_connection_name" {
  # The value will be the name of the GCP connection resource
  value = ciphertrust_gcp_connection.gcp_connection.name
}