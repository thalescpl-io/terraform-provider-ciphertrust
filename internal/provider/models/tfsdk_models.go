package models

import "github.com/hashicorp/terraform-plugin-framework/types"

type tfsdkCTEClientGroupModel struct {
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

type tfsdkCTECSIGroupModel struct {
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

type tfsdkCTEUserSet struct {
	Index    types.Int64  `tfsdk:"index"`
	GID      types.Int64  `tfsdk:"gid"`
	GName    types.String `tfsdk:"gname"`
	OSDomain types.String `tfsdk:"os_domain"`
	UID      types.Int64  `tfsdk:"uid"`
	UName    types.String `tfsdk:"uname"`
}

type tfsdkCTEUserSetsListModel struct {
	ID          types.String      `tfsdk:"id"`
	Name        types.String      `tfsdk:"name"`
	Description types.String      `tfsdk:"description"`
	URI         types.String      `tfsdk:"uri"`
	Account     types.String      `tfsdk:"account"`
	CreateAt    types.String      `tfsdk:"created_at"`
	UpdatedAt   types.String      `tfsdk:"updated_at"`
	Users       []tfsdkCTEUserSet `tfsdk:"users"`
}

type tfsdkCTEResourceSet struct {
	Index             types.Int64  `tfsdk:"index"`
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
}

type tfsdkCTEResourceSetsListModel struct {
	ID          types.String          `tfsdk:"id"`
	Name        types.String          `tfsdk:"name"`
	Description types.String          `tfsdk:"description"`
	URI         types.String          `tfsdk:"uri"`
	Account     types.String          `tfsdk:"account"`
	CreateAt    types.String          `tfsdk:"created_at"`
	UpdatedAt   types.String          `tfsdk:"updated_at"`
	Type        types.String          `tfsdk:"type"`
	Resources   []tfsdkCTEResourceSet `tfsdk:"resources"`
}

type tfsdkCTEProcessSet struct {
	Index         types.Int64  `tfsdk:"index"`
	Directory     types.String `tfsdk:"directory"`
	File          types.String `tfsdk:"file"`
	Signature     types.String `tfsdk:"signature"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type tfsdkCTEProcessSetsListModel struct {
	ID          types.String         `tfsdk:"id"`
	Name        types.String         `tfsdk:"name"`
	Description types.String         `tfsdk:"description"`
	URI         types.String         `tfsdk:"uri"`
	Account     types.String         `tfsdk:"account"`
	CreateAt    types.String         `tfsdk:"created_at"`
	UpdatedAt   types.String         `tfsdk:"updated_at"`
	Processes   []tfsdkCTEProcessSet `tfsdk:"resources"`
}

type tfsdkCTESignatureSetsListModel struct {
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

type tfsdkCTEClientGuardPointParamsModel struct {
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

type tfsdkCTEClientGuardPoint struct {
	CTEClientID      types.String                        `tfsdk:"cte_client_id"`
	GuardPaths       []types.String                      `tfsdk:"guard_paths"`
	GuardPointParams tfsdkCTEClientGuardPointParamsModel `tfsdk:"guard_point_params"`
}

type tfsdkUpdateGPModel struct {
	CTEClientID                 types.String `tfsdk:"cte_client_id"`
	GPID                        types.String `tfsdk:"cte_client_gp_id"`
	IsDataClassificationEnabled types.Bool   `tfsdk:"data_classification_enabled"`
	IsDataLineageEnabled        types.Bool   `tfsdk:"data_lineage_enabled"`
	IsGuardEnabled              types.Bool   `tfsdk:"guard_enabled"`
	IsMFAEnabled                types.Bool   `tfsdk:"mfa_enabled"`
	NWShareCredentialsID        types.String `tfsdk:"network_share_credentials_id"`
}

type tfsdkAddDataTXRulePolicy struct {
	CTEClientPolicyID types.String           `tfsdk:"policy_id"`
	DataTXRuleID      types.String           `tfsdk:"rule_id"`
	OrderNumber       types.Int64            `tfsdk:"order_number"`
	DataTXRule        DataTransformationRule `tfsdk:"rule"`
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

type tfsdkUpdateIDTKeyRulePolicy struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	IDTKeyRuleID      types.String `tfsdk:"rule_id"`
	IDTKeyRule        IDTKeyRule   `tfsdk:"rule"`
}

type tfsdkCTEPolicyDataTxRulesListModel struct {
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

type tfsdkCTEPolicyIDTKeyRulesListModel struct {
	ID                types.String `tfsdk:"id"`
	PolicyID          types.String `tfsdk:"policy_id"`
	CurrentKey        types.String `tfsdk:"current_key"`
	TransformationKey types.String `tfsdk:"transformation_key"`
}

type tfsdkCTEPolicyLDTKeyRulesListModel struct {
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

type tfsdkCTEPolicySecurityRulesListModel struct {
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

type tfsdkCTEPolicySignatureRulesListModel struct {
	ID               types.String `tfsdk:"id"`
	URI              types.String `tfsdk:"uri"`
	Account          types.String `tfsdk:"account"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	PolicyID         types.String `tfsdk:"policy_id"`
	SignatureSetID   types.String `tfsdk:"signature_set_id"`
	SignatureSetName types.String `tfsdk:"signature_set_name"`
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

type tfsdkCTEProfilesList struct {
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

type tfsdkLDTGroupCommSvc struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	OpType      types.String   `tfsdk:"op_type"`
	ClientList  []types.String `tfsdk:"client_list"`
}
