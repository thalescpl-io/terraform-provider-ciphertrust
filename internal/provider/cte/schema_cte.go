package cte

import "github.com/hashicorp/terraform-plugin-framework/types"

type CTEClientsListTFSDK struct {
	ID                     types.String   `tfsdk:"id"`
	URI                    types.String   `tfsdk:"uri"`
	Account                types.String   `tfsdk:"account"`
	App                    types.String   `tfsdk:"application"`
	DevAccount             types.String   `tfsdk:"dev_account"`
	CreatedAt              types.String   `tfsdk:"created_at"`
	UpdatedAt              types.String   `tfsdk:"updated_at"`
	Name                   types.String   `tfsdk:"name"`
	OSType                 types.String   `tfsdk:"os_type"`
	OSSubType              types.String   `tfsdk:"os_sub_type"`
	ClientRegID            types.String   `tfsdk:"client_reg_id"`
	ServerHostname         types.String   `tfsdk:"server_host_name"`
	Description            types.String   `tfsdk:"description"`
	ClientLocked           types.Bool     `tfsdk:"client_locked"`
	SystemLocked           types.Bool     `tfsdk:"system_locked"`
	PasswordCreationMethod types.String   `tfsdk:"password_creation_method"`
	ClientVersion          types.Int64    `tfsdk:"client_version"`
	RegistrationAllowed    types.Bool     `tfsdk:"registration_allowed"`
	CommunicationEnabled   types.Bool     `tfsdk:"communication_enabled"`
	Capabilities           types.String   `tfsdk:"capabilities"`
	EnabledCapabilities    types.String   `tfsdk:"enabled_capabilities"`
	ProtectionMode         types.String   `tfsdk:"protection_mode"`
	ClientType             types.String   `tfsdk:"client_type"`
	ProfileName            types.String   `tfsdk:"profile_name"`
	ProfileID              types.String   `tfsdk:"profile_id"`
	LDTEnabled             types.Bool     `tfsdk:"ldt_enabled"`
	ClientHealthStatus     types.String   `tfsdk:"client_health_status"`
	Errors                 []types.String `tfsdk:"errors"`
	Warnings               []types.String `tfsdk:"warnings"`
	ClientErrors           []types.String `tfsdk:"client_errors"`
	ClientWarnings         []types.String `tfsdk:"client_warnings"`
}

type CTEClientsListJSON struct {
	ID                     string   `json:"id"`
	URI                    string   `json:"uri"`
	Account                string   `json:"account"`
	App                    string   `json:"application"`
	DevAccount             string   `json:"dev_account"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
	Name                   string   `json:"name"`
	OSType                 string   `json:"os_type"`
	OSSubType              string   `json:"os_sub_type"`
	ClientRegID            string   `json:"client_reg_id"`
	ServerHostname         string   `json:"server_host_name"`
	Description            string   `json:"description"`
	ClientLocked           bool     `json:"client_locked"`
	SystemLocked           bool     `json:"system_locked"`
	PasswordCreationMethod string   `json:"password_creation_method"`
	ClientVersion          int64    `json:"client_version"`
	RegistrationAllowed    bool     `json:"registration_allowed"`
	CommunicationEnabled   bool     `json:"communication_enabled"`
	Capabilities           string   `json:"capabilities"`
	EnabledCapabilities    string   `json:"enabled_capabilities"`
	ProtectionMode         string   `json:"protection_mode"`
	ClientType             string   `json:"client_type"`
	ProfileName            string   `json:"profile_name"`
	ProfileID              string   `json:"profile_id"`
	LDTEnabled             bool     `json:"ldt_enabled"`
	ClientHealthStatus     string   `json:"client_health_status"`
	Errors                 []string `json:"errors"`
	Warnings               []string `json:"warnings"`
	ClientErrors           []string `json:"client_errors"`
	ClientWarnings         []string `json:"client_warnings"`
}

type CTEClientTFSDK struct {
	ID                     types.String   `tfsdk:"id"`
	Name                   types.String   `tfsdk:"name"`
	ClientLocked           types.Bool     `tfsdk:"client_locked"`
	ClientType             types.String   `tfsdk:"client_type"`
	CommunicationEnabled   types.Bool     `tfsdk:"communication_enabled"`
	Description            types.String   `tfsdk:"description"`
	Password               types.String   `tfsdk:"password"`
	PasswordCreationMethod types.String   `tfsdk:"password_creation_method"`
	ProfileIdentifier      types.String   `tfsdk:"profile_identifier"`
	RegistrationAllowed    types.Bool     `tfsdk:"registration_allowed"`
	SystemLocked           types.Bool     `tfsdk:"system_locked"`
	ClientMFAEnabled       types.Bool     `tfsdk:"client_mfa_enabled"`
	DelClient              types.Bool     `tfsdk:"del_client"`
	DisableCapability      types.String   `tfsdk:"disable_capability"`
	DynamicParameters      types.String   `tfsdk:"dynamic_parameters"`
	EnableDomainSharing    types.Bool     `tfsdk:"enable_domain_sharing"`
	EnabledCapabilities    types.String   `tfsdk:"enabled_capabilities"`
	LGCSAccessOnly         types.Bool     `tfsdk:"lgcs_access_only"`
	MaxNumCacheLog         types.Int64    `tfsdk:"max_num_cache_log"`
	MaxSpaceCacheLog       types.Int64    `tfsdk:"max_space_cache_log"`
	ProfileID              types.String   `tfsdk:"profile_id"`
	ProtectionMode         types.String   `tfsdk:"protection_mode"`
	SharedDomainList       []types.String `tfsdk:"shared_domain_list"`
	Labels                 types.Map      `tfsdk:"labels"`
}

type CTEClientJSON struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	ClientLocked           bool                   `json:"client_locked"`
	ClientType             string                 `json:"client_type"`
	CommunicationEnabled   bool                   `json:"communication_enabled"`
	Description            string                 `json:"description"`
	Password               string                 `json:"password"`
	PasswordCreationMethod string                 `json:"password_creation_method"`
	ProfileIdentifier      string                 `json:"profile_identifier"`
	RegistrationAllowed    bool                   `json:"registration_allowed"`
	SystemLocked           bool                   `json:"system_locked"`
	ClientMFAEnabled       bool                   `json:"client_mfa_enabled"`
	DelClient              bool                   `json:"del_client"`
	DisableCapability      string                 `json:"disable_capability"`
	DynamicParameters      string                 `json:"dynamic_parameters"`
	EnableDomainSharing    bool                   `json:"enable_domain_sharing"`
	EnabledCapabilities    string                 `json:"enabled_capabilities"`
	LGCSAccessOnly         bool                   `json:"lgcs_access_only"`
	MaxNumCacheLog         int64                  `json:"max_num_cache_log"`
	MaxSpaceCacheLog       int64                  `json:"max_space_cache_log"`
	ProfileID              string                 `json:"profile_id"`
	ProtectionMode         string                 `json:"protection_mode"`
	SharedDomainList       []string               `json:"shared_domain_list"`
	Labels                 map[string]interface{} `json:"labels"`
}

// CTE Policy related structs
type DataTxRuleJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
}

type IDTRuleJSON struct {
	CurrentKey            string `json:"current_key"`
	CurrentKeyType        string `json:"current_key_type"`
	TransformationKey     string `json:"transformation_key"`
	TransformationKeyType string `json:"transformation_key_type"`
}

type KeyRuleJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
}

type CurrentKeyJSON struct {
	KeyID   string `json:"key_id"`
	KeyType string `json:"key_type"`
}

type TransformationKeyJSON struct {
	KeyID   string `json:"key_id"`
	KeyType string `json:"key_type"`
}

type LDTRuleJSON struct {
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	IsExclusionRule   bool                  `json:"is_exclusion_rule"`
	ResourceSetID     string                `json:"resource_set_id"`
}

type CTEPolicyMetadataJSON struct {
	RestrictUpdate bool `json:"restrict_update"`
}

type SecurityRuleJSON struct {
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	PartialMatch       bool   `json:"partial_match"`
	ProcessSetID       string `json:"process_set_id"`
	ResourceSetID      string `json:"resource_set_id"`
	UserSetID          string `json:"user_set_id"`
}

type SignatureRuleJSON struct {
	SignatureSetID string `json:"signature_set_id"`
}

type AddSignaturesToRuleJSON struct {
	SignatureSets []string `json:"signature_set_id_list"`
}

type CTEPolicyJSON struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	Description         string                `json:"description"`
	PolicyType          string                `json:"policy_type"`
	Metadata            CTEPolicyMetadataJSON `json:"metadata"`
	NeverDeny           bool                  `json:"never_deny"`
	DataTransformRules  []DataTxRuleJSON      `json:"data_transform_rules"`
	IDTKeyRules         []IDTRuleJSON         `json:"idt_key_rules"`
	KeyRules            []KeyRuleJSON         `json:"key_rules"`
	LDTKeyRules         []LDTRuleJSON         `json:"ldt_key_rules"`
	SecurityRules       []SecurityRuleJSON    `json:"security_rules"`
	SignatureRules      []SignatureRuleJSON   `json:"signature_rules"`
	ForceRestrictUpdate bool                  `json:"force_restrict_update"`
}

type DataTransformationRuleTFSDK struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type IDTKeyRuleTFSDK struct {
	CurrentKey            types.String `tfsdk:"current_key"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKey     types.String `tfsdk:"transformation_key"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
}

type KeyRuleTFSDK struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CurrentKeyTFSDK struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type TransformationKeyTFSDK struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type LDTKeyRuleTFSDK struct {
	CurrentKey        CurrentKeyTFSDK        `tfsdk:"current_key"`
	TransformationKey TransformationKeyTFSDK `tfsdk:"transformation_key"`
	IsExclusionRule   types.Bool             `tfsdk:"is_exclusion_rule"`
	ResourceSetID     types.String           `tfsdk:"resource_set_id"`
}

type CTEPolicyMetadataTFSDK struct {
	RestrictUpdate types.Bool `tfsdk:"restrict_update"`
}

type SecurityRuleTFSDK struct {
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

type SignatureRuleTFSDK struct {
	SignatureSetID types.String `tfsdk:"signature_set_id"`
}

type CTEPolicyTFSDK struct {
	ID                  types.String                  `tfsdk:"id"`
	Name                types.String                  `tfsdk:"name"`
	Description         types.String                  `tfsdk:"description"`
	PolicyType          types.String                  `tfsdk:"policy_type"`
	Metadata            CTEPolicyMetadataTFSDK        `tfsdk:"metadata"`
	NeverDeny           types.Bool                    `tfsdk:"never_deny"`
	DataTransformRules  []DataTransformationRuleTFSDK `tfsdk:"data_transform_rules"`
	IDTKeyRules         []IDTKeyRuleTFSDK             `tfsdk:"idt_key_rules"`
	KeyRules            []KeyRuleTFSDK                `tfsdk:"key_rules"`
	LDTKeyRules         []LDTKeyRuleTFSDK             `tfsdk:"ldt_key_rules"`
	SecurityRules       []SecurityRuleTFSDK           `tfsdk:"security_rules"`
	SignatureRules      []SignatureRuleTFSDK          `tfsdk:"signature_rules"`
	ForceRestrictUpdate types.Bool                    `tfsdk:"force_restrict_update"`
}

type CTEPolicyDataTxRulesListTFSDK struct {
	ID            types.String `tfsdk:"id"`
	URI           types.String `tfsdk:"uri"`
	Account       types.String `tfsdk:"account"`
	Application   types.String `tfsdk:"application"`
	DevAccount    types.String `tfsdk:"dev_account"`
	CreateAt      types.String `tfsdk:"created_at"`
	UpdatedAt     types.String `tfsdk:"updated_at"`
	PolicyID      types.String `tfsdk:"policy_id"`
	OrderNumber   types.Int64  `tfsdk:"order_number"`
	KeyID         types.String `tfsdk:"key_id"`
	NewKeyRule    types.Bool   `tfsdk:"new_key_rule"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CTEPolicyIDTKeyRulesListTFSDK struct {
	ID                types.String `tfsdk:"id"`
	PolicyID          types.String `tfsdk:"policy_id"`
	CurrentKey        types.String `tfsdk:"current_key"`
	TransformationKey types.String `tfsdk:"transformation_key"`
}

type CTEPolicyLDTKeyRulesListTFSDK struct {
	ID                    types.String `tfsdk:"id"`
	PolicyID              types.String `tfsdk:"policy_id"`
	OrderNumber           types.Int64  `tfsdk:"order_number"`
	ResourceSetID         types.String `tfsdk:"resource_set_id"`
	CurrentKeyID          types.String `tfsdk:"current_key_id"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKeyID   types.String `tfsdk:"transformation_key_id"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
	ISExclusionRule       types.Bool   `tfsdk:"is_exclusion_rule"`
}

type tfsdkCTEPolicyIDTKeyRulesListModel struct {
	ID                types.String `tfsdk:"id"`
	PolicyID          types.String `tfsdk:"policy_id"`
	CurrentKey        types.String `tfsdk:"current_key"`
	TransformationKey types.String `tfsdk:"transformation_key"`
}

type CTEPolicySecurityRulesListTFSDK struct {
	ID                 types.String `tfsdk:"id"`
	URI                types.String `tfsdk:"uri"`
	Account            types.String `tfsdk:"account"`
	Application        types.String `tfsdk:"application"`
	DevAccount         types.String `tfsdk:"dev_account"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
	PolicyID           types.String `tfsdk:"policy_id"`
	OrderNumber        types.Int64  `tfsdk:"order_number"`
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	UserSetID          types.String `tfsdk:"user_set_id"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
}

type CTEPolicySignatureRulesListTFSDK struct {
	ID               types.String `tfsdk:"id"`
	URI              types.String `tfsdk:"uri"`
	Account          types.String `tfsdk:"account"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	PolicyID         types.String `tfsdk:"policy_id"`
	SignatureSetID   types.String `tfsdk:"signature_set_id"`
	SignatureSetName types.String `tfsdk:"signature_set_name"`
}

type CTEPolicyDataTxRulesJSON struct {
	ID            string `json:"id"`
	URI           string `json:"uri"`
	Account       string `json:"account"`
	Application   string `json:"application"`
	DevAccount    string `json:"dev_account"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	PolicyID      string `json:"policy_id"`
	OrderNumber   int64  `json:"order_number"`
	KeyID         string `json:"key_id"`
	NewKeyRule    bool   `json:"new_key_rule"`
	ResourceSetID string `json:"resource_set_id"`
}

type CTEPolicyIDTKeyRulesJSON struct {
	ID                string `json:"id"`
	PolicyID          string `json:"policy_id"`
	CurrentKey        string `json:"current_key"`
	TransformationKey string `json:"transformation_key"`
}

type CTEPolicyLDTKeyRulesJSON struct {
	ID                string                `json:"id"`
	PolicyID          string                `json:"policy_id"`
	OrderNumber       int64                 `json:"order_number"`
	ResourceSetID     string                `json:"resource_set_id"`
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	ISExclusionRule   bool                  `json:"is_exclusion_rule"`
}

type CTEPolicySecurityRulesJSON struct {
	ID                 string `json:"id"`
	URI                string `json:"uri"`
	Account            string `json:"account"`
	Application        string `json:"application"`
	DevAccount         string `json:"dev_account"`
	CreatedAt          string `json:"createdAt"`
	UpdatedAt          string `json:"updatedAt"`
	PolicyID           string `json:"policy_id"`
	OrderNumber        int64  `json:"order_number"`
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	UserSetID          string `json:"user_set_id"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	ResourceSetID      string `json:"resource_set_id"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ProcessSetID       string `json:"process_set_id"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	PartialMatch       bool   `json:"partial_match"`
}

type CTEPolicySignatureRulesJSON struct {
	ID               string `json:"id"`
	URI              string `json:"uri"`
	Account          string `json:"account"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
	PolicyID         string `json:"policy_id"`
	SignatureSetID   string `json:"signature_set_id"`
	SignatureSetName string `json:"signature_set_name"`
}

type AddDataTXRulePolicyTFSDK struct {
	CTEClientPolicyID types.String                `tfsdk:"policy_id"`
	DataTXRuleID      types.String                `tfsdk:"rule_id"`
	OrderNumber       types.Int64                 `tfsdk:"order_number"`
	DataTXRule        DataTransformationRuleTFSDK `tfsdk:"rule"`
}

type DataTxRuleUpdateJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
	OrderNumber   int64  `json:"order_number"`
}

type KeyRuleUpdateJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
	OrderNumber   int64  `json:"order_number"`
}

type LDTRuleUpdateJSON struct {
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	IsExclusionRule   bool                  `json:"is_exclusion_rule"`
	ResourceSetID     string                `json:"resource_set_id"`
	OrderNumber       int64                 `json:"order_number"`
}

type SecurityRuleUpdateJSON struct {
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	PartialMatch       bool   `json:"partial_match"`
	ProcessSetID       string `json:"process_set_id"`
	ResourceSetID      string `json:"resource_set_id"`
	UserSetID          string `json:"user_set_id"`
	OrderNumber        int64  `json:"order_number"`
}

type UpdateIDTKeyRulePolicyTFSDK struct {
	CTEClientPolicyID types.String    `tfsdk:"policy_id"`
	IDTKeyRuleID      types.String    `tfsdk:"rule_id"`
	IDTKeyRule        IDTKeyRuleTFSDK `tfsdk:"rule"`
}

type CTEProcessSetListItemTFSDK struct {
	Index         types.Int64  `tfsdk:"index"`
	Directory     types.String `tfsdk:"directory"`
	File          types.String `tfsdk:"file"`
	Signature     types.String `tfsdk:"signature"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CTEProcessSetsListTFSDK struct {
	ID          types.String                 `tfsdk:"id"`
	Name        types.String                 `tfsdk:"name"`
	Description types.String                 `tfsdk:"description"`
	URI         types.String                 `tfsdk:"uri"`
	Account     types.String                 `tfsdk:"account"`
	CreateAt    types.String                 `tfsdk:"created_at"`
	UpdatedAt   types.String                 `tfsdk:"updated_at"`
	Processes   []CTEProcessSetListItemTFSDK `tfsdk:"resources"`
}

type CTEProcessSetListItemJSON struct {
	ID          string                   `json:"id"`
	URI         string                   `json:"uri"`
	Account     string                   `json:"account"`
	CreatedAt   string                   `json:"createdAt"`
	Name        string                   `json:"name"`
	UpdatedAt   string                   `json:"updatedAt"`
	Description string                   `json:"description"`
	Processes   []CTEProcessSetsListJSON `json:"resources"`
}

type CTEProcessSetsListJSON struct {
	Index         int64  `json:"index"`
	Directory     string `json:"directory"`
	File          string `json:"file"`
	Signature     string `json:"signature"`
	ResourceSetID string `json:"resource_set_id"`
}

type CTEProfilesListTFSDK struct {
	ID                     types.String `tfsdk:"id"`
	URI                    types.String `tfsdk:"uri"`
	Account                types.String `tfsdk:"account"`
	Application            types.String `tfsdk:"application"`
	CreatedAt              types.String `tfsdk:"created_at"`
	UpdatedAt              types.String `tfsdk:"updated_at"`
	Name                   types.String `tfsdk:"name"`
	Description            types.String `tfsdk:"description"`
	LDTQOSCapCPUAllocation types.Bool   `tfsdk:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent    types.Int64  `tfsdk:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption      types.String `tfsdk:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate        types.Int64  `tfsdk:"ldt_qos_rekey_rate"`
	ConciseLogging         types.Bool   `tfsdk:"concise_logging"`
	ConnectTimeout         types.Int64  `tfsdk:"connect_timeout"`
	LDTQOSSchedule         types.String `tfsdk:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate  types.Int64  `tfsdk:"ldt_qos_status_check_rate"`
	MetadataScanInterval   types.Int64  `tfsdk:"metadata_scan_interval"`
	MFAExemptUserSetID     types.String `tfsdk:"mfa_exempt_user_set_id"`
	MFAExemptUserSetName   types.String `tfsdk:"mfa_exempt_user_set_name"`
	OIDCConnectionID       types.String `tfsdk:"oidc_connection_id"`
	OIDCConnectionName     types.String `tfsdk:"oidc_connection_name"`
	RWPOperation           types.String `tfsdk:"rwp_operation"`
	RWPProcessSet          types.String `tfsdk:"rwp_process_set"`
	ServerResponseRate     types.Int64  `tfsdk:"server_response_rate"`
	//QOSSchedules            []tfsdkCTEProfileQOSSchedule           `tfsdk:"qos_schedules"`
	//ServerSettings          []tfsdkCTEProfileServiceSetting        `tfsdk:"server_settings"`
	// ManagementServiceLogger tfsdkCTEProfileManagementServiceLogger `tfsdk:"management_service_logger"`
	// PolicyEvaluationLogger  tfsdkCTEProfileManagementServiceLogger `tfsdk:"policy_evaluation_logger"`
	// SecurityAdminLogger     tfsdkCTEProfileManagementServiceLogger `tfsdk:"security_admin_logger"`
	// SystemAdminLogger       tfsdkCTEProfileManagementServiceLogger `tfsdk:"system_admin_logger"`
	// FileSettings            tfsdkCTEProfileFileSettings            `tfsdk:"file_settings"`
	// SyslogSettings          tfsdkCTEProfileSyslogSettings          `tfsdk:"syslog_settings"`
	// UploadSettings          tfsdkCTEProfileUploadSettings          `tfsdk:"upload_settings"`
	// DuplicateSettings       tfsdkCTEProfileDuplicateSettings       `tfsdk:"duplicate_settings"`
	// CacheSettings           tfsdkCTEProfileCacheSettings           `tfsdk:"cache_settings"`
}

type CTEProfilesListJSON struct {
	ID                     string `json:"id"`
	URI                    string `json:"uri"`
	Account                string `json:"account"`
	Application            string `json:"application"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
	Name                   string `json:"name"`
	Description            string `json:"description"`
	LDTQOSCapCPUAllocation bool   `json:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent    int64  `json:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption      string `json:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate        int64  `json:"ldt_qos_rekey_rate"`
	ConciseLogging         bool   `json:"concise_logging"`
	ConnectTimeout         int64  `json:"connect_timeout"`
	LDTQOSSchedule         string `json:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate  int64  `json:"ldt_qos_status_check_rate"`
	MetadataScanInterval   int64  `json:"metadata_scan_interval"`
	MFAExemptUserSetID     string `json:"mfa_exempt_user_set_id"`
	MFAExemptUserSetName   string `json:"mfa_exempt_user_set_name"`
	OIDCConnectionID       string `json:"oidc_connection_id"`
	OIDCConnectionName     string `json:"oidc_connection_name"`
	RWPOperation           string `json:"rwp_operation"`
	RWPProcessSet          string `json:"rwp_process_set"`
	ServerResponseRate     int64  `json:"server_response_rate"`
	// QOSSchedules            []jsonCTEProfileQOSSchedule           `json:"qos_schedules"`
	// ServerSettings          []jsonCTEProfileServiceSetting        `json:"server_settings"`
	// ManagementServiceLogger jsonCTEProfileManagementServiceLogger `json:"management_service_logger"`
	// PolicyEvaluationLogger  jsonCTEProfileManagementServiceLogger `json:"policy_evaluation_logger"`
	// SecurityAdminLogger     jsonCTEProfileManagementServiceLogger `json:"security_admin_logger"`
	// SystemAdminLogger       jsonCTEProfileManagementServiceLogger `json:"system_admin_logger"`
	// FileSettings            jsonCTEProfileFileSettings            `json:"file_settings"`
	// SyslogSettings          jsonCTEProfileSyslogSettings          `json:"syslog_settings"`
	// UploadSettings          jsonCTEProfileUploadSettings          `json:"upload_settings"`
	// DuplicateSettings       jsonCTEProfileDuplicateSettings       `json:"duplicate_settings"`
	// CacheSettings           jsonCTEProfileCacheSettings           `json:"cache_settings"`
}

type CTEResourceSetListItemTFSDK struct {
	Index             types.Int64  `tfsdk:"index"`
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
}

type CTEResourceSetsListTFSDK struct {
	ID          types.String                  `tfsdk:"id"`
	Name        types.String                  `tfsdk:"name"`
	Description types.String                  `tfsdk:"description"`
	URI         types.String                  `tfsdk:"uri"`
	Account     types.String                  `tfsdk:"account"`
	CreateAt    types.String                  `tfsdk:"created_at"`
	UpdatedAt   types.String                  `tfsdk:"updated_at"`
	Type        types.String                  `tfsdk:"type"`
	Resources   []CTEResourceSetListItemTFSDK `tfsdk:"resources"`
}

type CTEResourceSetsListJSON struct {
	ID          string                       `json:"id"`
	URI         string                       `json:"uri"`
	Account     string                       `json:"account"`
	CreatedAt   string                       `json:"createdAt"`
	Name        string                       `json:"name"`
	UpdatedAt   string                       `json:"updatedAt"`
	Description string                       `json:"description"`
	Type        string                       `json:"type"`
	Resources   []CTEResourceSetListItemJSON `json:"resources"`
}

type CTEResourceSetListItemJSON struct {
	Index             int64  `json:"index"`
	Directory         string `json:"directory"`
	File              string `json:"file"`
	IncludeSubfolders bool   `json:"include_subfolders"`
	HDFS              bool   `json:"hdfs"`
}

type CTESignatureSetsListTFSDK struct {
	ID                 types.String   `tfsdk:"id"`
	URI                types.String   `tfsdk:"uri"`
	Account            types.String   `tfsdk:"account"`
	CreatedAt          types.String   `tfsdk:"created_at"`
	UpdatedAt          types.String   `tfsdk:"updated_at"`
	Name               types.String   `tfsdk:"name"`
	Type               types.String   `tfsdk:"type"`
	Description        types.String   `tfsdk:"description"`
	ReferenceVersion   types.Int64    `tfsdk:"reference_version"`
	SourceList         []types.String `tfsdk:"source_list"`
	SigningStatus      types.String   `tfsdk:"signing_status"`
	PercentageComplete types.Int64    `tfsdk:"percentage_complete"`
	UpdatedBy          types.String   `tfsdk:"updated_by"`
	DockerImgID        types.String   `tfsdk:"docker_img_id"`
	DockerContID       types.String   `tfsdk:"docker_cont_id"`
}

type SignatureSetJSON struct {
	ID                 string   `json:"id"`
	URI                string   `json:"uri"`
	Account            string   `json:"account"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	Name               string   `json:"name"`
	Type               string   `json:"type"`
	Description        string   `json:"description"`
	ReferenceVersion   int64    `json:"reference_version"`
	SourceList         []string `json:"source_list"`
	SigningStatus      string   `json:"signing_status"`
	PercentageComplete int64    `json:"percentage_complete"`
	UpdatedBy          string   `json:"updated_by"`
	DockerImgID        string   `json:"docker_img_id"`
	DockerContID       string   `json:"docker_cont_id"`
}

type CTEUserSetsListItemTFSDK struct {
	Index    types.Int64  `tfsdk:"index"`
	GID      types.Int64  `tfsdk:"gid"`
	GName    types.String `tfsdk:"gname"`
	OSDomain types.String `tfsdk:"os_domain"`
	UID      types.Int64  `tfsdk:"uid"`
	UName    types.String `tfsdk:"uname"`
}

type CTEUserSetsListTFSDK struct {
	ID          types.String               `tfsdk:"id"`
	Name        types.String               `tfsdk:"name"`
	Description types.String               `tfsdk:"description"`
	URI         types.String               `tfsdk:"uri"`
	Account     types.String               `tfsdk:"account"`
	CreateAt    types.String               `tfsdk:"created_at"`
	UpdatedAt   types.String               `tfsdk:"updated_at"`
	Users       []CTEUserSetsListItemTFSDK `tfsdk:"users"`
}

type CTEUserSetsListJSON struct {
	ID          string                    `json:"id"`
	URI         string                    `json:"uri"`
	Account     string                    `json:"account"`
	CreatedAt   string                    `json:"createdAt"`
	Name        string                    `json:"name"`
	UpdatedAt   string                    `json:"updatedAt"`
	Description string                    `json:"description"`
	Users       []CTEUserSetsListItemJSON `json:"users"`
}

type CTEUserSetsListItemJSON struct {
	Index    int64  `json:"index"`
	GID      int64  `json:"gid"`
	GName    string `json:"gname"`
	OSDomain string `json:"os_domain"`
	UID      int64  `json:"uid"`
	UName    string `json:"uname"`
}

type CTEClientGuardPointParamsTFSDK struct {
	GPType                         types.String `tfsdk:"guard_point_type"`
	PolicyID                       types.String `tfsdk:"policy_id"`
	IsAutomountEnabled             types.Bool   `tfsdk:"automount_enabled"`
	IsCIFSEnabled                  types.Bool   `tfsdk:"cifs_enabled"`
	IsDataClassificationEnabled    types.Bool   `tfsdk:"data_classification_enabled"`
	IsDataLineageEnabled           types.Bool   `tfsdk:"data_lineage_enabled"`
	DiskName                       types.String `tfsdk:"disk_name"`
	DiskgroupName                  types.String `tfsdk:"diskgroup_name"`
	IsEarlyAccessEnabled           types.Bool   `tfsdk:"early_access"`
	IsIntelligentProtectionEnabled types.Bool   `tfsdk:"intelligent_protection"`
	IsDeviceIDTCapable             types.Bool   `tfsdk:"is_idt_capable_device"`
	IsMFAEnabled                   types.Bool   `tfsdk:"mfa_enabled"`
	NWShareCredentialsID           types.String `tfsdk:"network_share_credentials_id"`
	PreserveSparseRegions          types.Bool   `tfsdk:"preserve_sparse_regions"`
}

type CTEClientGuardPointTFSDK struct {
	CTEClientID      types.String                   `tfsdk:"cte_client_id"`
	GuardPaths       []types.String                 `tfsdk:"guard_paths"`
	GuardPointParams CTEClientGuardPointParamsTFSDK `tfsdk:"guard_point_params"`
}

type CTEClientGuardPointParamsJSON struct {
	GPType                         string `json:"guard_point_type"`
	PolicyID                       string `json:"policy_id"`
	IsAutomountEnabled             bool   `json:"automount_enabled"`
	IsCIFSEnabled                  bool   `json:"cifs_enabled"`
	IsDataClassificationEnabled    bool   `json:"data_classification_enabled"`
	IsDataLineageEnabled           bool   `json:"data_lineage_enabled"`
	DiskName                       string `json:"disk_name"`
	DiskgroupName                  string `json:"diskgroup_name"`
	IsEarlyAccessEnabled           bool   `json:"early_access"`
	IsIntelligentProtectionEnabled bool   `json:"intelligent_protection"`
	IsDeviceIDTCapable             bool   `json:"is_idt_capable_device"`
	IsMFAEnabled                   bool   `json:"mfa_enabled"`
	NWShareCredentialsID           string `json:"network_share_credentials_id"`
	PreserveSparseRegions          bool   `json:"preserve_sparse_regions"`
}

type CTEClientGuardPointJSON struct {
	CTEClientID      string                         `json:"cte_client_id"`
	GuardPaths       []string                       `json:"guard_paths"`
	GuardPointParams *CTEClientGuardPointParamsJSON `json:"guard_point_params"`
}

type UpdateCTEGuardPointTFSDK struct {
	CTEClientID                 types.String `tfsdk:"cte_client_id"`
	GPID                        types.String `tfsdk:"cte_client_gp_id"`
	IsDataClassificationEnabled types.Bool   `tfsdk:"data_classification_enabled"`
	IsDataLineageEnabled        types.Bool   `tfsdk:"data_lineage_enabled"`
	IsGuardEnabled              types.Bool   `tfsdk:"guard_enabled"`
	IsMFAEnabled                types.Bool   `tfsdk:"mfa_enabled"`
	NWShareCredentialsID        types.String `tfsdk:"network_share_credentials_id"`
}

type UpdateCTEGuardPointJSON struct {
	CTEClientID                 string `json:"cte_client_id"`
	GPID                        string `json:"cte_client_gp_id"`
	IsDataClassificationEnabled bool   `json:"data_classification_enabled"`
	IsDataLineageEnabled        bool   `json:"data_lineage_enabled"`
	IsGuardEnabled              bool   `json:"guard_enabled"`
	IsMFAEnabled                bool   `json:"mfa_enabled"`
	NWShareCredentialsID        string `json:"network_share_credentials_id"`
}

type CTEClientGroupTFSDK struct {
	ID                      types.String   `tfsdk:"id"`
	ClusterType             types.String   `tfsdk:"cluster_type"`
	Name                    types.String   `tfsdk:"name"`
	CommunicationEnabled    types.Bool     `tfsdk:"communication_enabled"`
	Description             types.String   `tfsdk:"description"`
	LDTDesignatedPrimarySet types.String   `tfsdk:"ldt_designated_primary_set"`
	Password                types.String   `tfsdk:"password"`
	PasswordCreationMethod  types.String   `tfsdk:"password_creation_method"`
	ProfileID               types.String   `tfsdk:"profile_id"`
	ClientLocked            types.Bool     `tfsdk:"client_locked"`
	EnableDomainSharing     types.Bool     `tfsdk:"enable_domain_sharing"`
	EnabledCapabilities     types.String   `tfsdk:"enabled_capabilities"`
	SharedDomainList        []types.String `tfsdk:"shared_domain_list"`
	SystemLocked            types.Bool     `tfsdk:"system_locked"`
	AuthBinaries            types.String   `tfsdk:"auth_binaries"`
	ReSign                  types.Bool     `tfsdk:"re_sign"`
	ClientList              []types.String `tfsdk:"client_list"`
	InheritAttributes       types.Bool     `tfsdk:"inherit_attributes"`
	ClientID                types.String   `tfsdk:"client_id"`
	OpType                  types.String   `tfsdk:"op_type"`
	Paused                  types.Bool     `tfsdk:"paused"`
}

type CTEClientGroupJSON struct {
	ID                      string   `json:"id"`
	ClusterType             string   `json:"cluster_type"`
	Name                    string   `json:"name"`
	CommunicationEnabled    bool     `json:"communication_enabled"`
	Description             string   `json:"description"`
	LDTDesignatedPrimarySet string   `json:"ldt_designated_primary_set"`
	Password                string   `json:"password"`
	PasswordCreationMethod  string   `json:"password_creation_method"`
	ProfileID               string   `json:"profile_id"`
	ClientLocked            bool     `json:"client_locked"`
	EnableDomainSharing     bool     `json:"enable_domain_sharing"`
	EnabledCapabilities     string   `json:"enabled_capabilities"`
	SharedDomainList        []string `json:"shared_domain_list"`
	SystemLocked            bool     `json:"system_locked"`
	AuthBinaries            string   `json:"auth_binaries"`
	ReSign                  bool     `json:"re_sign"`
	ClientList              []string `json:"client_list"`
	InheritAttributes       bool     `json:"inherit_attributes"`
	ClientID                string   `json:"client_id"`
	Paused                  bool     `json:"paused"`
}

type CTECSIGroupTFSDK struct {
	ID            types.String   `tfsdk:"id"`
	Namespace     types.String   `tfsdk:"kubernetes_namespace"`
	StorageClass  types.String   `tfsdk:"kubernetes_storage_class"`
	ClientProfile types.String   `tfsdk:"client_profile"`
	Name          types.String   `tfsdk:"name"`
	Description   types.String   `tfsdk:"description"`
	ClientList    []types.String `tfsdk:"client_list"`
	PolicyList    []types.String `tfsdk:"policy_list"`
	ClientID      types.String   `tfsdk:"client_id"`
	GuardEnabled  types.Bool     `tfsdk:"guard_enabled"`
	GPID          types.String   `tfsdk:"gp_id"`
	OpType        types.String   `tfsdk:"op_type"`
}

type CTECSIGroupJSON struct {
	ID            string   `json:"id"`
	Namespace     string   `json:"k8s_namespace"`
	StorageClass  string   `json:"k8s_storage_class"`
	ClientProfile string   `json:"client_profile"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	ClientList    []string `json:"client_list"`
	PolicyList    []string `json:"policy_list"`
	ClientID      string   `json:"client_id"`
	GuardEnabled  bool     `json:"guard_enabled"`
	GPID          string   `json:"gp_id"`
	OpType        string   `json:"op_type"`
}

type LDTGroupCommSvcTFSDK struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	OpType      types.String   `tfsdk:"op_type"`
	ClientList  []types.String `tfsdk:"client_list"`
}

type LDTGroupCommSvcJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	OpType      string   `json:"op_type"`
	ClientList  []string `json:"client_list"`
}

type CTEPolicyAddKeyRuleTFSDK struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	KeyRuleID         types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	KeyRule           KeyRuleTFSDK `tfsdk:"rule"`
}
