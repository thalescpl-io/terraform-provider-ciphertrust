package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMAzureConnection(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// creating a Azure connection
			{
				Config: providerConfig + `
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "azure-connection"=
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"=
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"=
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"=
  cloud_name= "AzureCloud"
  products = [
    "cckm"
  ]
  description = "a description of the connection"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"  # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2"  # Another custom metadata entry
  }
}
`,
				// verifying the resources for id, authmethod, protocol and port
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_azure_connection.azure_connection", "id"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "auth_method", "key"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "protocol", "azure"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "port", "22"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + `
resource "ciphertrust_azure_connection" "azure_connection" {
  name        = "TestAzureConnection"
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"=
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"=
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"=
  cloud_name= "AzureCloud"
  products = [
    "cckm"
  ]
  description = "a description of the connection"
  labels = {
    "environment" = "test"
    "department"  = "IT"
  }
  products = ["backup/restore"]
}
				`,
				// verifying the updated field username,port and protocol
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "protocol", "sftp"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "port", "2022"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "username", "updated-user"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
