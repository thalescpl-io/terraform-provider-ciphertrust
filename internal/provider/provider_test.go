package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	providerConfig = `
provider "ciphertrust" {
	address = "https://54.159.102.166"
	username = "admin"
	password = "KeySecure_1"
	bootstrap = "no"
}
`
)

var (
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"ciphertrust": providerserver.NewProtocol6WithError(New("ciphertrust")()),
	}
)
