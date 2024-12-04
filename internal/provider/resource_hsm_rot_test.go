package provider

import (
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"testing"
)

func TestResourceHSMRootOfTrustSetupLuna(t *testing.T) {
	// Remove skip after actual HSM data is used in test
	t.Skip("Skipped!! dummy data in resource parameters")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: providerConfig + `
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "luna"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  initial_config = {
    host           = "172.20.32.11"
    serial         = "1234"
    server-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert-key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
  reset = true
  delay = 5
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "type", "luna"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.%", "4"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.host", "172.20.32.11"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.partition_name", "kylo-partition"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.serial", "1234"),
				),
			},
		},
	})
}

func TestResourceHSMRootOfTrustSetupLunatct(t *testing.T) {
	// Remove skip after actual HSM data is used in test
	//t.Skip("Skipped!! dummy data in resource parameters")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: providerConfig + `
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "lunatct"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "password"
  }
  initial_config = {
    host           = "172.20.32.11"
    serial         = "1234"
    server-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert-key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
  reset = true
  delay = 5
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "type", "lunatct"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.%", "4"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.host", "172.20.32.11"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.partition_name", "kylo-partition"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.serial", "1234"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
