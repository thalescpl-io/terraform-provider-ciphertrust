# Create an HSM Root of Trust Setup

This example shows how to:
- Create an HSM Root of Trust Setup of type "luna"

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure HSM parameters required to perform initial setup of the system to use HSM of type "luna"
- Run the example

## Configure CipherTrust Manager

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
  domain   = "cm-domain"
  bootstrap = "no"
}
```

## Configure HSM Root of Trust setup parameter for type "luna"
Edit the hsm setup resource in main.tf with actual values for type "luna"
```bash
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "luna"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  initial_config = {
    host           = "172.20.32.11"
    serial         = "hsm-partition-sn"
    server-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert-key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
  reset = true
  delay = 5
}
```

Edit the hsm setup resource in main.tf with actual values for type "luna" using STC protocol
```bash
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
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources
Resources must be destroyed before another sample script using the same cloud is run.

```bash
terraform destroy
```

Run this step even if the apply step fails.