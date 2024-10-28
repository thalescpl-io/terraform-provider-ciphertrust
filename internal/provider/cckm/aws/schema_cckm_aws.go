package cckm

import "github.com/hashicorp/terraform-plugin-framework/types"

type AWSParamTFSDK struct {
	CloudHSMClusterID              types.String `tfsdk:"cloud_hsm_cluster_id"`
	XKSType                        types.String `tfsdk:"custom_key_store_type"`
	KeyStorePassword               types.String `tfsdk:"key_store_password"`
	TrustAnchorCertificate         types.String `tfsdk:"trust_anchor_certificate"`
	XKSProxyConnectivity           types.String `tfsdk:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            types.String `tfsdk:"xks_proxy_uri_endpoint"`
	XKSProxyVPCEndpointServiceName types.String `tfsdk:"xks_proxy_vpc_endpoint_service_name"`
}
type LocalHostedParamsTFSDK struct {
	Blocked          types.Bool   `tfsdk:"blocked"`
	HealthCheckKeyID types.String `tfsdk:"health_check_key_id"`
	MaxCredentials   types.String `tfsdk:"max_credentials"`
	MTLSEnabled      types.Bool   `tfsdk:"mtls_enabled"`
	PartitionID      types.String `tfsdk:"partition_id"`
	SourceKeyTier    types.String `tfsdk:"source_key_tier"`
}
type AWSCustomKeyStoreTFSDK struct {
	ID                      types.String           `tfsdk:"id"`
	AccessKeyID             types.String           `tfsdk:"access_key_id"`
	CloudName               types.String           `tfsdk:"cloud_name"`
	CreatedAt               types.String           `tfsdk:"created_at"`
	CredentialVersion       types.String           `tfsdk:"credential_version"`
	KMSID                   types.String           `tfsdk:"kms_id"`
	SecretAccessKey         types.String           `tfsdk:"secret_access_key"`
	Type                    types.String           `tfsdk:"type"`
	UpdatedAt               types.String           `tfsdk:"updated_at"`
	AWSParams               AWSParamTFSDK          `tfsdk:"aws_param"`
	KMS                     types.String           `tfsdk:"kms"`
	Name                    types.String           `tfsdk:"name"`
	Region                  types.String           `tfsdk:"region"`
	EnableSuccessAuditEvent types.Bool             `tfsdk:"enable_success_audit_event"`
	LinkedState             types.Bool             `tfsdk:"linked_state"`
	LocalHostedParams       LocalHostedParamsTFSDK `tfsdk:"local_hosted_params"`
	UpdateOpType            types.String           `tfsdk:"update_op_type"`
}
type AWSKeyParamTagTFSDK struct {
	TagKey   types.String `tfsdk:"tag_key"`
	TagValue types.String `tfsdk:"tag_values"`
}
type AWSKeyParamTFSDK struct {
	Alias                          types.String          `tfsdk:"alias"`
	BypassPolicyLockoutSafetyCheck types.Bool            `tfsdk:"bypass_policy_lockout_safety_check"`
	CustomerMasterKeySpec          types.String          `tfsdk:"customer_master_key_spec"`
	Description                    types.String          `tfsdk:"description"`
	KeyUsage                       types.String          `tfsdk:"key_usage"`
	MultiRegion                    types.Bool            `tfsdk:"multi_region"`
	Origin                         types.String          `tfsdk:"origin"`
	Policy                         types.Map             `tfsdk:"policy"`
	Tags                           []AWSKeyParamTagTFSDK `tfsdk:"tags"`
}
type AWSKeyTFSDK struct {
	ID                                    types.String          `tfsdk:"id"`
	KMS                                   types.String          `tfsdk:"kms"`
	Region                                types.String          `tfsdk:"region"`
	AWSParam                              *AWSKeyParamTFSDK     `tfsdk:"aws_param"`
	ExternalAccounts                      []types.String        `tfsdk:"external_accounts"`
	KeyAdmins                             []types.String        `tfsdk:"key_admins"`
	KeyAdminRoles                         []types.String        `tfsdk:"key_admins_roles"`
	KeyUsers                              []types.String        `tfsdk:"key_users"`
	KeyUserRoles                          []types.String        `tfsdk:"key_users_roles"`
	PolicyTemplate                        types.String          `tfsdk:"policytemplate"`
	UpdateOpType                          types.String          `tfsdk:"update_op_type"`
	JobConfigID                           types.String          `tfsdk:"job_config_id"`
	AutoRotateDisableEncrypt              types.Bool            `tfsdk:"auto_rotate_disable_encrypt"`
	AutoRotateDisableEncryptOnAllAccounts types.Bool            `tfsdk:"auto_rotate_disable_encrypt_on_all_accounts"`
	AutoRotateDomainID                    types.String          `tfsdk:"auto_rotate_domain_id"`
	AutoRotateExternalCMDomainID          types.String          `tfsdk:"auto_rotate_external_cm_domain_id"`
	AutoRotateKeySource                   types.String          `tfsdk:"auto_rotate_key_source"`
	AutoRotatePartitionID                 types.String          `tfsdk:"auto_rotate_partition_id"`
	KeyExpiration                         types.Bool            `tfsdk:"key_expiration"`
	SourceKeyIdentifier                   types.String          `tfsdk:"source_key_identifier"`
	SourceKeyTier                         types.String          `tfsdk:"source_key_tier"`
	ValidTo                               types.String          `tfsdk:"valid_to"`
	DisableEncrypt                        types.Bool            `tfsdk:"disable_encrypt"`
	DisableEncryptOnAllAccounts           types.Bool            `tfsdk:"disable_encrypt_on_all_accounts"`
	RetainAlias                           types.Bool            `tfsdk:"retain_alias"`
	SourceKeyID                           types.String          `tfsdk:"source_key_id"`
	Days                                  types.Int64           `tfsdk:"days"`
	Tags                                  []AWSKeyParamTagTFSDK `tfsdk:"tags"`
	DeleteTags                            []types.String        `tfsdk:"delete_tags"`
	Alias                                 types.String          `tfsdk:"alias"`
	RotationPeriodInDays                  types.Int64           `tfsdk:"rotation_period_in_days"`
}

type AWSParamJSON struct {
	CloudHSMClusterID              string `json:"cloud_hsm_cluster_id"`
	XKSType                        string `json:"custom_key_store_type"`
	KeyStorePassword               string `json:"key_store_password"`
	TrustAnchorCertificate         string `json:"trust_anchor_certificate"`
	XKSProxyConnectivity           string `json:"xks_proxy_connectivity"`
	XKSProxyURIEndpoint            string `json:"xks_proxy_uri_endpoint"`
	XKSProxyVPCEndpointServiceName string `json:"xks_proxy_vpc_endpoint_service_name"`
}
type LocalHostedParamsJSON struct {
	Blocked          bool   `json:"blocked"`
	HealthCheckKeyID string `json:"health_check_key_id"`
	MaxCredentials   string `json:"max_credentials"`
	MTLSEnabled      bool   `json:"mtls_enabled"`
	PartitionID      string `json:"partition_id"`
	SourceKeyTier    string `json:"source_key_tier"`
}
type AWSCustomKeyStoreJSON struct {
	ID                      string                 `json:"id"`
	AWSParams               *AWSParamJSON          `json:"aws_param"`
	KMS                     string                 `json:"kms"`
	Name                    string                 `json:"name"`
	Region                  string                 `json:"region"`
	EnableSuccessAuditEvent bool                   `json:"enable_success_audit_event"`
	LinkedState             bool                   `json:"linked_state"`
	LocalHostedParams       *LocalHostedParamsJSON `json:"local_hosted_params"`
	KeyStorePassword        string                 `json:"key_store_password"`
}
type AWSKeyParamTagJSON struct {
	TagKey   string `json:"TagKey"`
	TagValue string `json:"TagValue"`
}
type AWSKeyParamJSON struct {
	Alias                          string                 `json:"Alias"`
	BypassPolicyLockoutSafetyCheck bool                   `json:"BypassPolicyLockoutSafetyCheck"`
	CustomerMasterKeySpec          string                 `json:"CustomerMasterKeySpec"`
	Description                    string                 `json:"Description"`
	KeyUsage                       string                 `json:"KeyUsage"`
	MultiRegion                    bool                   `json:"MultiRegion"`
	Origin                         string                 `json:"Origin"`
	Policy                         map[string]interface{} `json:"Policy"`
	Tags                           []AWSKeyParamTagJSON   `json:"Tags"`
}
type AWSKeyJSON struct {
	ID                                    string               `json:"id"`
	KMS                                   string               `json:"kms"`
	Region                                string               `json:"region"`
	AWSParam                              *AWSKeyParamJSON     `json:"aws_param"`
	ExternalAccounts                      []string             `json:"external_accounts"`
	KeyAdmins                             []string             `json:"key_admins"`
	KeyAdminRoles                         []string             `json:"key_admins_roles"`
	KeyUsers                              []string             `json:"key_users"`
	KeyUserRoles                          []string             `json:"key_users_roles"`
	PolicyTemplate                        string               `json:"policytemplate"`
	JobConfigID                           string               `tfsdk:"job_config_id"`
	AutoRotateDisableEncrypt              bool                 `tfsdk:"auto_rotate_disable_encrypt"`
	AutoRotateDisableEncryptOnAllAccounts bool                 `tfsdk:"auto_rotate_disable_encrypt_on_all_accounts"`
	AutoRotateDomainID                    string               `tfsdk:"auto_rotate_domain_id"`
	AutoRotateExternalCMDomainID          string               `tfsdk:"auto_rotate_external_cm_domain_id"`
	AutoRotateKeySource                   string               `tfsdk:"auto_rotate_key_source"`
	AutoRotatePartitionID                 string               `tfsdk:"auto_rotate_partition_id"`
	KeyExpiration                         bool                 `tfsdk:"key_expiration"`
	SourceKeyIdentifier                   string               `tfsdk:"source_key_identifier"`
	SourceKeyTier                         string               `tfsdk:"source_key_tier"`
	ValidTo                               string               `tfsdk:"valid_to"`
	DisableEncrypt                        bool                 `tfsdk:"disable_encrypt"`
	DisableEncryptOnAllAccounts           bool                 `tfsdk:"disable_encrypt_on_all_accounts"`
	RetainAlias                           bool                 `tfsdk:"retain_alias"`
	SourceKeyID                           string               `tfsdk:"source_key_id"`
	Days                                  int64                `tfsdk:"days"`
	Tags                                  []AWSKeyParamTagJSON `tfsdk:"tags"`
	DeleteTags                            []string             `tfsdk:"delete_tags"`
	Alias                                 string               `tfsdk:"alias"`
	RotationPeriodInDays                  int64                `tfsdk:"rotation_period_in_days"`
}
