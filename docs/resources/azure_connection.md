---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_azure_connection Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_azure_connection (Resource)

ciphertrust_azure_connection resource creates an azure connection on CipherTrust Manager.

## Example Usage

```terraform
# Create an azure connection resource with CipherTrust
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "azure-connection"
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name= "AzureCloud"
  products = [
    "cckm"
  ]
  description = "a description of the connection"
  labels = {
    "environment" = "devenv"
  meta = {
    "custom_meta_key1" = "custom_value1"  # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2"  # Another custom metadata entry
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Unique connection name.

### Optional

- `client_id` (String) Unique Identifier (client ID) for the Azure application.
- `tenant_id` (String) Tenant ID of the Azure application.
- `active_directory_endpoint` (String) Azure stack active directory authority URL
- `azure_stack_connection_type` (String) Azure stack connection type

	Options:
	
		AAD
		ADFS
- `azure_stack_server_cert` (String) Azure stack server certificate.The certificate should be provided in either \n (newline) or EOF (End of File) format.
- `cert_duration` (Number) Duration in days for which the azure certificate is valid, default (730 i.e. 2 Years).
- `certificate` (String) User has the option to upload external certificate for Azure Cloud connection. This option cannot be used with option is_certificate_used and client_secret.User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. User can also update the new external certificate in the existing connection. Any unused certificate will automatically deleted in 24 hours.The certificate should be provided in either \n (newline) or EOF (End of File) format.
- `client_secret` (String) Secret key for the Azure application. Required in Azure Stack connection.
- `cloud_name` (String) Name of the cloud.

	Options:
	
		AzureCloud
		AzureChinaCloud
		AzureUSGovernment
		AzureStack
- `created_at` (String)
- `description` (String) Description about the connection.
- `is_certificate_used` (Boolean) User has the option to choose the Certificate Authentication method instead of Client Secret for Azure Cloud connection. In order to use the Certificate, set it to true. Once the connection is created, in the response user will get a certificate. By default, the certificate is valid for 2 Years. User can update the certificate in the existing connection by setting it to true.
- `key_vault_dns_suffix` (String) Azure stack key vault dns suffix
- `labels` (Map of String) Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.

To add a label, set the label's value as follows.

    "labels": {
      "key1": "value1",
      "key2": "value2"
    }

To remove a key/value pair, pass value null to the particular key

    "labels": {
      "key1": null
    }
- `management_url` (String) Azure stack management URL
- `meta` (Map of String) Optional end-user or service data stored with the connection.
- `products` (List of String) Array of the CipherTrust products associated with the connection. Valid values are:

    "cckm" for:
        AWS
        Azure
        GCP
        Luna connections
        DSM
        Salesforce
        SAP Data Custodian
    "ddc" for:
        GCP
        Hadoop connections
    "cte" for:
        Hadoop connections
        SMB
        OIDC
        LDAP connections
    "data discovery" for Hadoop connections.
    "backup/restore" for SCP/SFTP connections.
    "logger" for:
        loki connections
        elasticsearch connections
        syslog connections
    "hsm_anchored_domain" for:
        Luna connections
- `resource_manager_url` (String) Azure stack resource manager URL.
- `vault_resource_url` (String) Azure stack vault service resource URL.

### Read-Only

- `id` (String) The ID of this resource.
- `external_certificate_used` (Boolean) true if the certificate associated with the connection is generated externally, false otherwise.
- `certificate_thumbprint` (String)