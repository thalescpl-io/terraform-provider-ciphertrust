---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_cte_policy_signature_rule Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_cte_policy_signature_rule (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `policy_id` (String) ID of the parent policy in which Signature Rule need to be added

### Optional

- `signature_set_id_list` (List of String) List of domainsList of identifiers of signature sets of Container_Image type for CSI Policy. The identifiers can be the Name, ID (a UUIDv4), URI, or slug of the signature sets.Only one sig set can be attached at once

### Read-Only

- `id` (String) ID of the Signature Rule created in the parent policy