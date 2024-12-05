# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an HSM Root of trust setup of type luna,lunatct
# with the CipherTrust provider.

# HSM root of trust setup of type luna
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

# HSM root of trust setup of type Luna Network HSM using the STC protocol
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
    stc-par-identity= "VGhpcyBpcyB0aGUgZXhhbXB...sZSBvZiBzdGMtcGFyLWlkZW50aXR5"
  }
  reset = true
  delay = 5
}

# HSM root of trust setup of type lunatct
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "lunatct"
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
