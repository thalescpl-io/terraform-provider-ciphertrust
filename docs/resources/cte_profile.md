---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_cte_profile Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_cte_profile (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Name of the CTE profile.

### Optional

- `cache_settings` (Attributes) Cache settings for the server. (see [below for nested schema](#nestedatt--cache_settings))
- `client_logging_configuration` (Attributes) Logger configurations for the management service. (see [below for nested schema](#nestedatt--client_logging_configuration))
- `concise_logging` (Boolean) Whether to allow concise logging.
- `connect_timeout` (Number) Connect timeout in seconds. Valid values are 5 to 150.
- `description` (String) Description of the profile resource.
- `duplicate_settings` (Attributes) Duplicate setting parameters. (see [below for nested schema](#nestedatt--duplicate_settings))
- `file_settings` (Attributes) File settings for the profile. (see [below for nested schema](#nestedatt--file_settings))
- `labels` (Map of String) Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.
- `ldt_qos_cap_cpu_allocation` (Boolean) Whether to allow CPU allocation for Quality of Service (QoS) capabilities.
- `ldt_qos_cpu_percent` (Number) CPU application percentage if ldt_qos_cap_cpu_allocation is true. Valid values are 0 to 100.
- `ldt_qos_rekey_option` (String) Rekey option and applicable options are RekeyRate and CPU.
- `ldt_qos_rekey_rate` (Number) Rekey rate in terms of MB/s. Valid values are 0 to 32767.
- `ldt_qos_schedule` (String) Type of QoS schedule.
- `ldt_qos_status_check_rate` (Number) Frequency to check and update the LDT status on the CipherTrust Manager. The valid value ranges from 600 to 86400 seconds. The default value is 3600 seconds.
- `metadata_scan_interval` (Number) Time interval in seconds to scan files under the GuardPoint. The default value is 600.
- `mfa_exempt_user_set_id` (String) ID of the user set to be exempted from MFA. MFA will not be enforced on the users of this set.
- `oidc_connection_id` (String) ID of the OIDC connection.
- `qos_schedules` (Attributes List) Schedule of QoS capabilities. (see [below for nested schema](#nestedatt--qos_schedules))
- `rwp_operation` (String) Applicable to the Ransomware clients only. The valid values are permit(for Audit), deny(for Block), and disable. The default value is deny.
- `rwp_process_set` (String) ID of the process set to be whitelisted.
- `server_response_rate` (Number) the percentage value of successful API calls to the server, for which the agent will consider the server to be working fine. If the value is set to 75 then, if the server responds to 75 percent of the calls it is considered OK & no update is sent by agent. Valid values are between 0 to 100, both inclusive. Default value is 0.
- `server_settings` (Attributes List) Server configuration of cluster nodes. These settings are allowed only in cluster environment. (see [below for nested schema](#nestedatt--server_settings))
- `syslog_settings` (Attributes) Parameters to configure the Syslog server. (see [below for nested schema](#nestedatt--syslog_settings))
- `upload_settings` (Attributes Map) Configure log upload to the Syslog server. (see [below for nested schema](#nestedatt--upload_settings))

### Read-Only

- `id` (String) The ID of this resource.

<a id="nestedatt--cache_settings"></a>
### Nested Schema for `cache_settings`

Optional:

- `max_files` (Number) Maximum number of files. Minimum value is 200.
- `max_space` (Number) Max Space. Minimum value is 100 MB.


<a id="nestedatt--client_logging_configuration"></a>
### Nested Schema for `client_logging_configuration`

Optional:

- `duplicates` (String) Control duplicate entries, ALLOW or SUPPRESS
- `file_enabled` (Boolean) Whether to enable file upload.
- `syslog_enabled` (Boolean) Whether to enable support for the Syslog server.
- `threshold` (String) Threshold value
- `upload_enabled` (Boolean) Whether to enable log upload to the URL.


<a id="nestedatt--duplicate_settings"></a>
### Nested Schema for `duplicate_settings`

Optional:

- `suppress_interval` (Number) Suppress interval in seconds. Valid values are 1 to 1000.
- `suppress_threshold` (Number) Suppress threshold. Valid values are 1 to 100.


<a id="nestedatt--file_settings"></a>
### Nested Schema for `file_settings`

Optional:

- `allow_purge` (Boolean) Allows purge.
- `file_threshold` (String) Applicable file threshold.
- `max_file_size` (Number) Maximum file size(bytes) 1,000 - 1,000,000,000 (1KB to 1GB).
- `max_old_files` (Number) Maximum number of old files allowed. Valid values are 1 to 100.


<a id="nestedatt--qos_schedules"></a>
### Nested Schema for `qos_schedules`

Optional:

- `end_time_hour` (Number) QoS end hour. Valid values are 1 to 23.
- `end_time_min` (Number) QoS end minute. Valid values are 0 to 59.
- `end_weekday` (String) QoS end day.
- `start_time_hour` (Number) QOS start hour. Valid values are 1 to 23.
- `start_time_min` (Number) QOS start minute. Valid values are 0 to 59.
- `start_weekday` (String) QoS start day.


<a id="nestedatt--server_settings"></a>
### Nested Schema for `server_settings`

Optional:

- `host_name` (String) Host name of the cluster node.
- `priority` (String) Priority of the cluster node. Valid values are 1 to 100.


<a id="nestedatt--syslog_settings"></a>
### Nested Schema for `syslog_settings`

Optional:

- `local` (Boolean) Whether the Syslog server is local.
- `servers` (Attributes List) Configuration of the Syslog server. (see [below for nested schema](#nestedatt--syslog_settings--servers))
- `syslog_threshold` (String) Applicable threshold.

<a id="nestedatt--syslog_settings--servers"></a>
### Nested Schema for `syslog_settings.servers`

Optional:

- `ca_certificate` (String) CA certificate for syslog application provided by the client. for example: -----BEGIN CERTIFICATE-----
<certificate content>
-----END CERTIFICATE--------
- `certificate` (String) Client certificate for syslog application provided by the client. for example: -----BEGIN CERTIFICATE-----
<certificate content>
-----END CERTIFICATE--------
- `message_format` (String) Format of the message on the Syslog server.
- `name` (String) Name of the Syslog server.
- `port` (Number) Port for syslog server. Valid values are 1 to 65535.
- `private_key` (String) Client certificate for syslog application provided by the client. for example: -----BEGIN RSA PRIVATE KEY-----
<key content>
-----END RSA PRIVATE KEY-----
- `protocol` (String) Protocol of the Syslog server, TCP, UDP and TLS.



<a id="nestedatt--upload_settings"></a>
### Nested Schema for `upload_settings`

Optional:

- `duplicates` (String) Control duplicate entries, ALLOW or SUPPRESS
- `file_enabled` (Boolean) Whether to enable file upload.
- `syslog_enabled` (Boolean) Whether to enable support for the Syslog server.
- `threshold` (String) Threshold value
- `upload_enabled` (Boolean) Whether to enable log upload to the URL.