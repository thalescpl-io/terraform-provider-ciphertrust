package models

import "github.com/hashicorp/terraform-plugin-framework/types"

type DataTransformationRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type IDTKeyRule struct {
	CurrentKey            types.String `tfsdk:"current_key"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKey     types.String `tfsdk:"transformation_key"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
}

type KeyRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CurrentKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type TransformationKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type LDTKeyRule struct {
	CurrentKey        CurrentKey        `tfsdk:"current_key"`
	TransformationKey TransformationKey `tfsdk:"transformation_key"`
	IsExclusionRule   types.Bool        `tfsdk:"is_exclusion_rule"`
	ResourceSetID     types.String      `tfsdk:"resource_set_id"`
}

type CTEPolicyMetadata struct {
	RestrictUpdate types.Bool `tfsdk:"restrict_update"`
}

type SecurityRule struct {
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	UserSetID          types.String `tfsdk:"user_set_id"`
}

type SignatureRule struct {
	SignatureSetID types.String `tfsdk:"signature_set_id"`
}

type tfsdkCTEPolicyModel struct {
	ID                  types.String             `tfsdk:"id"`
	Name                types.String             `tfsdk:"name"`
	Description         types.String             `tfsdk:"description"`
	PolicyType          types.String             `tfsdk:"policy_type"`
	Metadata            CTEPolicyMetadata        `tfsdk:"metadata"`
	NeverDeny           types.Bool               `tfsdk:"never_deny"`
	DataTransformRules  []DataTransformationRule `tfsdk:"data_transform_rules"`
	IDTKeyRules         []IDTKeyRule             `tfsdk:"idt_key_rules"`
	KeyRules            []KeyRule                `tfsdk:"key_rules"`
	LDTKeyRules         []LDTKeyRule             `tfsdk:"ldt_key_rules"`
	SecurityRules       []SecurityRule           `tfsdk:"security_rules"`
	SignatureRules      []SignatureRule          `tfsdk:"signature_rules"`
	ForceRestrictUpdate types.Bool               `tfsdk:"force_restrict_update"`
}

type CTEProcess struct {
	Directory     types.String `tfsdk:"directory"`
	File          types.String `tfsdk:"file"`
	ResourceSetId types.String `tfsdk:"resource_set_id"`
	Signature     types.String `tfsdk:"signature"`
}

type tfsdkCTEProcessSetModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Processes   []CTEProcess `tfsdk:"processes"`
}

type ClassificationTagAttributes struct {
	DataType types.String `tfsdk:"data_type"`
	Name     types.String `tfsdk:"name"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

type ClassificationTag struct {
	Description types.String                  `tfsdk:"description"`
	Name        types.String                  `tfsdk:"name"`
	Attributes  []ClassificationTagAttributes `tfsdk:"attributes"`
}

type CTEResource struct {
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
}

type tfsdkCTEResourceSetModel struct {
	ID                 types.String        `tfsdk:"id"`
	Name               types.String        `tfsdk:"name"`
	Description        types.String        `tfsdk:"description"`
	Resources          []CTEResource       `tfsdk:"resources"`
	Type               types.String        `tfsdk:"type"`
	ClassificationTags []ClassificationTag `tfsdk:"classification_tags"`
}

type tfsdkCTESignatureSetModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Type        types.String   `tfsdk:"type"`
	Sources     []types.String `tfsdk:"source_list"`
}

type CTEUser struct {
	GID      types.Int64  `tfsdk:"gid"`
	GName    types.String `tfsdk:"gname"`
	OSDomain types.String `tfsdk:"os_domain"`
	UID      types.Int64  `tfsdk:"uid"`
	UName    types.String `tfsdk:"uname"`
}

type tfsdkCTEUserSetModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Users       []CTEUser    `tfsdk:"users"`
}

type tfsdkAddKeyRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	KeyRuleID         types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	KeyRule           KeyRule      `tfsdk:"rule"`
}

type tfsdkAddLDTKeyRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	LDTKeyRuleID      types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	LDTKeyRule        LDTKeyRule   `tfsdk:"rule"`
}

type tfsdkAddSecurityRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	SecurityRuleID    types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	SecurityRule      SecurityRule `tfsdk:"rule"`
}

type tfsdkAddSignatureRulePolicy struct {
	CTEClientPolicyID types.String   `tfsdk:"policy_id"`
	SignatureRuleID   types.String   `tfsdk:"rule_id"`
	SignatureSetList  []types.String `tfsdk:"signature_set_id_list"`
	SignatureSetID    types.String   `tfsdk:"signature_set_id"`
}

type tfsdkCTEProfileCacheSettings struct {
	MaxFiles types.Int64 `tfsdk:"max_files"`
	MaxSpace types.Int64 `tfsdk:"max_space"`
}

type tfsdkCTEProfileDuplicateSettings struct {
	SuppressInterval  types.Int64 `tfsdk:"suppress_interval"`
	SuppressThreshold types.Int64 `tfsdk:"suppress_threshold"`
}

type tfsdkCTEProfileFileSettings struct {
	AllowPurge    types.Bool   `tfsdk:"allow_purge"`
	FileThreshold types.String `tfsdk:"file_threshold"`
	MaxFileSize   types.Int64  `tfsdk:"max_file_size"`
	MaxOldFiles   types.Int64  `tfsdk:"max_old_files"`
}

type tfsdkCTEProfileManagementServiceLogger struct {
	Duplicates    types.String `tfsdk:"duplicates"`
	FileEnabled   types.Bool   `tfsdk:"file_enabled"`
	SyslogEnabled types.Bool   `tfsdk:"syslog_enabled"`
	Threshold     types.String `tfsdk:"threshold"`
	UploadEnabled types.Bool   `tfsdk:"upload_enabled"`
}

type tfsdkCTEProfileQOSSchedule struct {
	EndTimeHour   types.Int64  `tfsdk:"end_time_hour"`
	EndTimeMin    types.Int64  `tfsdk:"end_time_min"`
	EndWeekday    types.String `tfsdk:"end_weekday"`
	StartTimeHour types.Int64  `tfsdk:"start_time_hour"`
	StartTimeMin  types.Int64  `tfsdk:"start_time_min"`
	StartWeekday  types.String `tfsdk:"start_weekday"`
}

type tfsdkCTEProfileServiceSetting struct {
	HostName types.String `tfsdk:"host_name"`
	Priority types.Int64  `tfsdk:"priority"`
}

type tfsdkCTEProfileSyslogSettingServer struct {
	CACert        types.String `tfsdk:"caCertificate"`
	Certificate   types.String `tfsdk:"certificate"`
	MessageFormat types.String `tfsdk:"message_format"`
	Name          types.String `tfsdk:"name"`
	Port          types.Int64  `tfsdk:"port"`
	PrivateKey    types.String `tfsdk:"privateKey"`
	Protocol      types.String `tfsdk:"protocol"`
}

type tfsdkCTEProfileSyslogSettings struct {
	Local     types.Bool                           `tfsdk:"local"`
	Servers   []tfsdkCTEProfileSyslogSettingServer `tfsdk:"servers"`
	Threshold types.String                         `tfsdk:"syslog_threshold"`
}

type tfsdkCTEProfileUploadSettings struct {
	ConnectionTimeout    types.Int64  `tfsdk:"connection_timeout"`
	DropIfBusy           types.Bool   `tfsdk:"drop_if_busy"`
	JobCompletionTimeout types.Int64  `tfsdk:"job_completion_timeout"`
	MaxInterval          types.Int64  `tfsdk:"max_interval"`
	MaxMessages          types.Int64  `tfsdk:"max_messages"`
	MinInterval          types.Int64  `tfsdk:"min_interval"`
	Threshold            types.String `tfsdk:"upload_threshold"`
}

type tfsdkCTEProfileCreate struct {
	ID                      types.String                           `tfsdk:"id"`
	Name                    types.String                           `tfsdk:"name"`
	CacheSettings           tfsdkCTEProfileCacheSettings           `tfsdk:"cache_settings"`
	ConciseLogging          types.Bool                             `tfsdk:"concise_logging"`
	ConnectTimeout          types.Int64                            `tfsdk:"connect_timeout"`
	Description             types.String                           `tfsdk:"description"`
	DuplicateSettings       tfsdkCTEProfileDuplicateSettings       `tfsdk:"duplicate_settings"`
	FileSettings            tfsdkCTEProfileFileSettings            `tfsdk:"file_settings"`
	Labels                  types.Map                              `tfsdk:"labels"`
	LDTQOSCapCPUAllocation  types.Bool                             `tfsdk:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent     types.Int64                            `tfsdk:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption       types.String                           `tfsdk:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate         types.Int64                            `tfsdk:"ldt_qos_rekey_rate"`
	LDTQOSSchedule          types.String                           `tfsdk:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate   types.Int64                            `tfsdk:"ldt_qos_status_check_rate"`
	ManagementServiceLogger tfsdkCTEProfileManagementServiceLogger `tfsdk:"management_service_logger"`
	MetadataScanInterval    types.Int64                            `tfsdk:"metadata_scan_interval"`
	MFAExemptUserSetID      types.String                           `tfsdk:"mfa_exempt_user_set_id"`
	OIDCConnectionID        types.String                           `tfsdk:"oidc_connection_id"`
	PolicyEvaluationLogger  tfsdkCTEProfileManagementServiceLogger `tfsdk:"policy_evaluation_logger"`
	QOSSchedules            []tfsdkCTEProfileQOSSchedule           `tfsdk:"qos_schedules"`
	RWPOperation            types.String                           `tfsdk:"rwp_operation"`
	RWPProcessSet           types.String                           `tfsdk:"rwp_process_set"`
	SecurityAdminLogger     tfsdkCTEProfileManagementServiceLogger `tfsdk:"security_admin_logger"`
	ServerResponseRate      types.Int64                            `tfsdk:"server_response_rate"`
	ServerSettings          []tfsdkCTEProfileServiceSetting        `tfsdk:"server_settings"`
	SyslogSettings          tfsdkCTEProfileSyslogSettings          `tfsdk:"syslog_settings"`
	SystemAdminLogger       tfsdkCTEProfileManagementServiceLogger `tfsdk:"system_admin_logger"`
	UploadSettings          tfsdkCTEProfileUploadSettings          `tfsdk:"upload_settings"`
}
