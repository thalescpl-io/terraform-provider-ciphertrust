# Create an HSM Root of Trust Setup

This example shows how to:
- Create an HSM Root of Trust Setup of type "lunatct"

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure HSM parameters required to perform initial setup of the system to use HSM of type "lunatct"
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

## Configure HSM Root of Trust setup parameter for type "lunatct"
Edit the hsm setup resource in main.tf with actual values for type "lunatct"
```bash
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "lunatct"
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