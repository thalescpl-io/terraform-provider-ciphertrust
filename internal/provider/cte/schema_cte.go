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
