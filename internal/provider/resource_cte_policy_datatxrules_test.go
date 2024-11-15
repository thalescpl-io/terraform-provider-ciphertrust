package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicyDataTXRules(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = "TestResourceSet"
  resources = [
    {
      directory="/tmp"
      file="*"
	  hdfs=false
	  include_subfolders=false
    }
  ]
  type="Directory"
}

resource "ciphertrust_cm_key" "cte_key" {
  name="TestKey"
  algorithm="aes"
  size=256
  usage_mask=13
}

resource "ciphertrust_cte_policy" "cte_policy" {
  name = "TestPolicy"
  policy_type = "Standard"
  never_deny = false
  security_rules = [
    {
      effect="permit"
	  action="all_ops"
      partial_match=false
      resource_set_id="TestResourceSet"
      exclude_resource_set=true
    }
  ]
}

resource "ciphertrust_cte_policy_data_tx_rule" "dataTxRule" {
	policy_id = ciphertrust_cte_policy.cte_policy.id
	rule = {
		key_id="TestKey"
		key_type="name"
		resource_set_id=ciphertrust_cte_resource_set.resource_set.id
	}
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "id"),
				),
			},
			// ImportState testing
			//{
			//	ResourceName:      "ciphertrust_cm_reg_token.reg_token",
			//	ImportState:       true,
			//	ImportStateVerify: true,
			//	ImportStateVerifyIgnore: []string{"last_updated"},
			//},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy_data_tx_rule" "dataTxRule" {
	policy_id = ciphertrust_cte_policy.cte_policy.id
	rule = {
		key_id="TestKey"
		key_type="name"
		resource_set_id=ciphertrust_cte_resource_set.resource_set.id
	}
	order_number=1
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
