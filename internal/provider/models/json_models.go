package models

// CipherTrust Manager Key Management related attributes

type jsonCMRegTokensListModel struct {
	ID                string `json:"id"`
	URI               string `json:"uri"`
	Account           string `json:"account"`
	Application       string `json:"application"`
	DevAccount        string `json:"devAccount"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
	Token             string `json:"token"`
	ValidUntil        string `json:"valid_until"`
	MaxClients        int64  `json:"max_clients"`
	ClientsRegistered int64  `json:"clients_registered"`
	CAID              string `json:"ca_id"`
	NamePrefix        string `json:"name_prefix"`
}

// type jsonCMKeysListModel struct {
// 	ID               string `json:"id"`
// 	URI              string `json:"uri"`
// 	Account          string `json:"account"`
// 	Application      string `json:"application"`
// 	DevAccount       string `json:"devAccount"`
// 	CreateAt         string `json:"createdAt"`
// 	Name             string `json:"name"`
// 	UpdatedAt        string `json:"updatedAt"`
// 	UsageMask        int64  `json:"usageMask"`
// 	Version          int64  `json:"version"`
// 	Algorithm        string `json:"algorithm"`
// 	Size             int64  `json:"size"`
// 	Format           string `json:"format"`
// 	Unexportable     bool   `json:"unexportable"`
// 	Undeletable      bool   `json:"undeletable"`
// 	ObjectType       string `json:"objectType"`
// 	ActivationDate   string `json:"activationDate"`
// 	DeactivationDate string `json:"deactivationDate"`
// 	ArchiveDate      string `json:"archiveDate"`
// 	DestroyDate      string `json:"destroyDate"`
// 	RevocationReason string `json:"revocationReason"`
// 	State            string `json:"state"`
// 	UUID             string `json:"uuid"`
// 	Description      string `json:"description"`
// }

// CipherTrust Manager Key Management related attributes - END

// We might not need the below struct
// type KeyJSON struct {
// 	KeyID            string `json:"id"`
// 	URI              string `json:"uri"`
// 	Account          string `json:"account"`
// 	Application      string `json:"application"`
// 	DevAccount       string `json:"devAccount"`
// 	CreatedAt        string `json:"createdAt"`
// 	UpdatedAt        string `json:"updatedAt"`
// 	UsageMask        int64  `json:"usageMask"`
// 	Version          int64  `json:"version"`
// 	Algorithm        string `json:"algorithm"`
// 	Size             int64  `json:"size"`
// 	Format           string `json:"format"`
// 	Exportable       bool   `json:"unexportable"`
// 	Deletable        bool   `json:"undeletable"`
// 	ObjectType       string `json:"objectType"`
// 	ActivationDate   string `json:"activationDate"`
// 	DeactivationDate string `json:"deactivationDate"`
// 	ArchiveDate      string `json:"archiveDate"`
// 	DestroyDate      string `json:"destroyDate"`
// 	RevocationReason string `json:"revocationReason"`
// 	State            string `json:"state"`
// 	UUID             string `json:"uuid"`
// 	Description      string `json:"description"`
// 	Name             string `json:"name"`
// }

type CTEUserJSON struct {
	GID      int    `json:"gid"`
	GName    string `json:"gname"`
	OSDomain string `json:"os_domain"`
	UID      int    `json:"uid"`
	UName    string `json:"uname"`
}

type ClassificationTagAttributesJSON struct {
	DataType string `json:"data_type"`
	Name     string `json:"name"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type ClassificationTagJSON struct {
	Description string                            `json:"description"`
	Name        string                            `json:"name"`
	Attributes  []ClassificationTagAttributesJSON `json:"attributes"`
}

type CTEResourceJSON struct {
	Directory         string `json:"directory"`
	File              string `json:"file"`
	HDFS              bool   `json:"hdfs"`
	IncludeSubfolders bool   `json:"include_subfolders"`
}

type CTEResourceSetModelJSON struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	Description        string                  `json:"description"`
	Resources          []CTEResourceJSON       `json:"resources"`
	Type               string                  `json:"type"`
	ClassificationTags []ClassificationTagJSON `json:"classification_tags"`
}

type CTEProcessJSON struct {
	Directory     string `json:"directory"`
	File          string `json:"file"`
	ResourceSetId string `json:"resource_set_id"`
	Signature     string `json:"signature"`
}

type CTEProcessSetModelJSON struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Processes   []CTEProcessJSON `json:"processes"`
}

type CTESignatureSetModelJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Sources     []string `json:"source_list"`
}

// type jsonAddDataTXRulePolicy struct {
// 	CTEClientPolicyID string         `json:"policy_id"`
// 	DataTXRuleID      string         `json:"rule_id"`
// 	DataTXRule        DataTxRuleJSON `json:"rule"`
// }

// type jsonAddKeyRulePolicy struct {
// 	CTEClientPolicyID string      `json:"policy_id"`
// 	KeyRuleID         string      `json:"rule_id"`
// 	KeyRule           KeyRuleJSON `json:"rule"`
// }

// type jsonAddLDTKeyRulePolicy struct {
// 	CTEClientPolicyID string      `json:"policy_id"`
// 	LDTKeyRuleID      string      `json:"rule_id"`
// 	LDTKeyRule        LDTRuleJSON `json:"rule"`
// }

// type jsonAddSecurityRulePolicy struct {
// 	CTEClientPolicyID string           `json:"policy_id"`
// 	SecurityRuleID    string           `json:"rule_id"`
// 	SecurityRule      SecurityRuleJSON `json:"rule"`
// }

// type jsonAddSignatureRulePolicy struct {
// 	CTEClientPolicyID string            `json:"policy_id"`
// 	SignatureRuleID   string            `json:"rule_id"`
// 	SignatureRule     SignatureRuleJSON `json:"rule"`
// }

// CTE Profile
type jsonCTEProfileCacheSettings struct {
	MaxFiles int64 `json:"max_files"`
	MaxSpace int64 `json:"max_space"`
}

type jsonCTEProfileDuplicateSettings struct {
	SuppressInterval  int64 `json:"suppress_interval"`
	SuppressThreshold int64 `json:"suppress_threshold"`
}

type jsonCTEProfileFileSettings struct {
	AllowPurge    bool   `json:"allow_purge"`
	FileThreshold string `json:"file_threshold"`
	MaxFileSize   int64  `json:"max_file_size"`
	MaxOldFiles   int64  `json:"max_old_files"`
}

type jsonCTEProfileManagementServiceLogger struct {
	Duplicates    string `json:"duplicates"`
	FileEnabled   bool   `json:"file_enabled"`
	SyslogEnabled bool   `json:"syslog_enabled"`
	Threshold     string `json:"threshold"`
	UploadEnabled bool   `json:"upload_enabled"`
}

type jsonCTEProfileQOSSchedule struct {
	EndTimeHour   int64  `json:"end_time_hour"`
	EndTimeMin    int64  `json:"end_time_min"`
	EndWeekday    string `json:"end_weekday"`
	StartTimeHour int64  `json:"start_time_hour"`
	StartTimeMin  int64  `json:"start_time_min"`
	StartWeekday  string `json:"start_weekday"`
}

type jsonCTEProfileServiceSetting struct {
	HostName string `json:"hostName"`
	Priority int64  `json:"priority"`
}

type jsonCTEProfileSyslogSettingServer struct {
	CACert        string `json:"caCertificate"`
	Certificate   string `json:"certificate"`
	MessageFormat string `json:"message_format"`
	Name          string `json:"name"`
	Port          int64  `json:"port"`
	PrivateKey    string `json:"privateKey"`
	Protocol      string `json:"protocol"`
}

type jsonCTEProfileSyslogSettings struct {
	Local     bool                                `json:"local"`
	Servers   []jsonCTEProfileSyslogSettingServer `json:"servers"`
	Threshold string                              `json:"syslog_threshold"`
}

type jsonCTEProfileUploadSettings struct {
	ConnectionTimeout    int64  `json:"connection_timeout"`
	DropIfBusy           bool   `json:"drop_if_busy"`
	JobCompletionTimeout int64  `json:"job_completion_timeout"`
	MaxInterval          int64  `json:"max_interval"`
	MaxMessages          int64  `json:"max_messages"`
	MinInterval          int64  `json:"min_interval"`
	Threshold            string `json:"upload_threshold"`
}

type jsonCTEProfileCreate struct {
	Name                    string                                `json:"name"`
	CacheSettings           jsonCTEProfileCacheSettings           `json:"cache_settings"`
	ConciseLogging          bool                                  `json:"concise_logging"`
	ConnectTimeout          int64                                 `json:"connect_timeout"`
	Description             string                                `json:"description"`
	DuplicateSettings       jsonCTEProfileDuplicateSettings       `json:"duplicate_settings"`
	FileSettings            jsonCTEProfileFileSettings            `json:"file_settings"`
	Labels                  map[string]interface{}                `json:"labels"`
	LDTQOSCapCPUAllocation  bool                                  `json:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent     int64                                 `json:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption       string                                `json:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate         int64                                 `json:"ldt_qos_rekey_rate"`
	LDTQOSSchedule          string                                `json:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate   int64                                 `json:"ldt_qos_status_check_rate"`
	ManagementServiceLogger jsonCTEProfileManagementServiceLogger `json:"management_service_logger"`
	MetadataScanInterval    int64                                 `json:"metadata_scan_interval"`
	MFAExemptUserSetID      string                                `json:"mfa_exempt_user_set_id"`
	OIDCConnectionID        string                                `json:"oidc_connection_id"`
	PolicyEvaluationLogger  jsonCTEProfileManagementServiceLogger `json:"policy_evaluation_logger"`
	QOSSchedules            []jsonCTEProfileQOSSchedule           `json:"qos_schedules"`
	RWPOperation            string                                `json:"rwp_operation"`
	RWPProcessSet           string                                `json:"rwp_process_set"`
	SecurityAdminLogger     jsonCTEProfileManagementServiceLogger `json:"security_admin_logger"`
	ServerResponseRate      int64                                 `json:"server_response_rate"`
	ServerSettings          []jsonCTEProfileServiceSetting        `json:"server_settings"`
	SyslogSettings          jsonCTEProfileSyslogSettings          `json:"syslog_settings"`
	SystemAdminLogger       jsonCTEProfileManagementServiceLogger `json:"system_admin_logger"`
	UploadSettings          jsonCTEProfileUploadSettings          `json:"upload_settings"`
}

// CCKM Models
