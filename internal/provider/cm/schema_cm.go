package cm

import "github.com/hashicorp/terraform-plugin-framework/types"

type LocalCAsListModelJSON struct {
	ID           string `json:"id"`
	URI          string `json:"uri"`
	Account      string `json:"account"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
	Name         string `json:"name"`
	State        string `json:"state"`
	Cert         string `json:"cert"`
	SerialNumber string `json:"serialNumber"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
}

type CMCertificateAuthoritiesListModelTFSDK struct {
	ID           types.String `tfsdk:"id"`
	URI          types.String `tfsdk:"uri"`
	Name         types.String `tfsdk:"name"`
	State        types.String `tfsdk:"state"`
	Cert         types.String `tfsdk:"cert"`
	SerialNumber types.String `tfsdk:"serial_number"`
	Subject      types.String `tfsdk:"subject"`
	Issuer       types.String `tfsdk:"issuer"`
}

type CMGroupJSON struct {
	Name           string                 `json:"name"`
	AppMetadata    map[string]interface{} `json:"app_metadata"`
	ClientMetadata map[string]interface{} `json:"client_metadata"`
	Description    string                 `json:"description"`
	UserMetadata   map[string]interface{} `json:"user_metadata"`
}

type CMGroupsListModelTFSDK struct {
	Name types.String `tfsdk:"name"`
}

type CMGroupsDataSourceModelTFSDK struct {
	Filters types.Map                `tfsdk:"filters"`
	Groups  []CMGroupsListModelTFSDK `tfsdk:"groups"`
}

type CMGroupTFSDK struct {
	Name           types.String `tfsdk:"name"`
	AppMetadata    types.Map    `tfsdk:"app_metadata"`
	ClientMetadata types.Map    `tfsdk:"client_metadata"`
	Description    types.String `tfsdk:"description"`
	UserMetadata   types.Map    `tfsdk:"user_metadata"`
}

type CMKeysListTFSDK struct {
	ID               types.String `tfsdk:"id"`
	URI              types.String `tfsdk:"uri"`
	Account          types.String `tfsdk:"account"`
	Application      types.String `tfsdk:"application"`
	DevAccount       types.String `tfsdk:"dev_account"`
	CreatedAt        types.String `tfsdk:"created_at"`
	Name             types.String `tfsdk:"name"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	UsageMask        types.Int64  `tfsdk:"usage_mask"`
	Version          types.Int64  `tfsdk:"version"`
	Algorithm        types.String `tfsdk:"algorithm"`
	Size             types.Int64  `tfsdk:"size"`
	Format           types.String `tfsdk:"format"`
	Unexportable     types.Bool   `tfsdk:"unexportable"`
	Undeletable      types.Bool   `tfsdk:"undeletable"`
	ObjectType       types.String `tfsdk:"object_type"`
	ActivationDate   types.String `tfsdk:"activation_date"`
	DeactivationDate types.String `tfsdk:"deactivation_date"`
	ArchiveDate      types.String `tfsdk:"archive_date"`
	DestroyDate      types.String `tfsdk:"destroy_date"`
	RevocationReason types.String `tfsdk:"revocation_reason"`
	State            types.String `tfsdk:"state"`
	UUID             types.String `tfsdk:"uuid"`
	Description      types.String `tfsdk:"description"`
}

type HKDFParametersTFSDK struct {
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	IKMKeyName    types.String `tfsdk:"ikm_key_name"`
	Info          types.String `tfsdk:"info"`
	Salt          types.String `tfsdk:"salt"`
}

type KeyMetadataPermissionsTFSDK struct {
	DecryptWithKey    []types.String `tfsdk:"decrypt_with_key"`
	EncryptWithKey    []types.String `tfsdk:"encrypt_with_key"`
	ExportKey         []types.String `tfsdk:"export_key"`
	MACVerifyWithKey  []types.String `tfsdk:"mac_verify_with_key"`
	MACWithKey        []types.String `tfsdk:"mac_with_key"`
	ReadKey           []types.String `tfsdk:"read_key"`
	SignVerifyWithKey []types.String `tfsdk:"sign_verify_with_key"`
	SignWithKey       []types.String `tfsdk:"sign_with_key"`
	UseKey            []types.String `tfsdk:"use_key"`
}

type KeyMetadataCTETFSDK struct {
	PersistentOnClient types.Bool   `tfsdk:"persistent_on_client"`
	EncryptionMode     types.String `tfsdk:"encryption_mode"`
	CTEVersioned       types.Bool   `tfsdk:"cte_versioned"`
}

type KeyMetadataTFSDK struct {
	OwnerId     types.String                 `tfsdk:"owner_id"`
	Permissions *KeyMetadataPermissionsTFSDK `tfsdk:"permissions"`
	CTE         *KeyMetadataCTETFSDK         `tfsdk:"cte"`
}

type KeyAliasTFSDK struct {
	Alias types.String `tfsdk:"alias"`
	Index types.Int64  `tfsdk:"index"`
	Type  types.String `tfsdk:"type"`
}

type PublicKeyParametersTFSDK struct {
	ActivationDate   types.String    `tfsdk:"activation_date"`
	Aliases          []KeyAliasTFSDK `tfsdk:"aliases"`
	ArchiveDate      types.String    `tfsdk:"archive_date"`
	DeactivationDate types.String    `tfsdk:"deactivation_date"`
	Name             types.String    `tfsdk:"name"`
	State            types.String    `tfsdk:"state"`
	UnDeletable      types.Bool      `tfsdk:"undeletable"`
	UnExportable     types.Bool      `tfsdk:"unexportable"`
	UsageMask        types.Int64     `tfsdk:"usage_mask"`
}

type WrapHKDFTFSDK struct {
	HashAlgorithm types.String `tfsdk:"hash_algorithm"`
	Info          types.String `tfsdk:"info"`
	OKMLen        types.Int64  `tfsdk:"okm_len"`
	Salt          types.String `tfsdk:"salt"`
}

type WrapPBETFSDK struct {
	DKLen                  types.Int64  `tfsdk:"dklen"`
	HashAlgorithm          types.String `tfsdk:"hash_algorithm"`
	Iteration              types.Int64  `tfsdk:"iteration"`
	Password               types.String `tfsdk:"password"`
	PasswordIdentifier     types.String `tfsdk:"password_identifier"`
	PasswordIdentifierType types.String `tfsdk:"password_identifier_type"`
	Purpose                types.String `tfsdk:"purpose"`
	Salt                   types.String `tfsdk:"salt"`
}

type WrapRSAAESTFSDK struct {
	AESKeySize types.Int64  `tfsdk:"aes_key_size"`
	Padding    types.String `tfsdk:"padding"`
}

type CMKeyTFSDK struct {
	ID                       types.String              `tfsdk:"id"`
	ActivationDate           types.String              `tfsdk:"activation_date"`
	Algorithm                types.String              `tfsdk:"algorithm"`
	ArchiveDate              types.String              `tfsdk:"archive_date"`
	AssignSelfAsOwner        types.Bool                `tfsdk:"assign_self_as_owner"`
	CertType                 types.String              `tfsdk:"cert_type"`
	CompromiseDate           types.String              `tfsdk:"compromise_date"`
	CompromiseOccurrenceDate types.String              `tfsdk:"compromise_occurrence_date"`
	Curveid                  types.String              `tfsdk:"curveid"`
	DeactivationDate         types.String              `tfsdk:"deactivation_date"`
	DefaultIV                types.String              `tfsdk:"default_iv"`
	Description              types.String              `tfsdk:"description"`
	DestroyDate              types.String              `tfsdk:"destroy_date"`
	EmptyMaterial            types.Bool                `tfsdk:"empty_material"`
	Encoding                 types.String              `tfsdk:"encoding"`
	Format                   types.String              `tfsdk:"format"`
	GenerateKeyId            types.Bool                `tfsdk:"generate_key_id"`
	HKDFCreateParameters     *HKDFParametersTFSDK      `tfsdk:"hkdf_create_parameters"`
	IDSize                   types.Int64               `tfsdk:"id_size"`
	KeyId                    types.String              `tfsdk:"key_id"`
	MacSignBytes             types.String              `tfsdk:"mac_sign_bytes"`
	MacSignKeyIdentifier     types.String              `tfsdk:"mac_sign_key_identifier"`
	MacSignKeyIdentifierType types.String              `tfsdk:"mac_sign_key_identifier_type"`
	Material                 types.String              `tfsdk:"material"`
	MUID                     types.String              `tfsdk:"muid"`
	ObjectType               types.String              `tfsdk:"object_type"`
	Name                     types.String              `tfsdk:"name"`
	Metadata                 *KeyMetadataTFSDK         `tfsdk:"meta"`
	Padded                   types.Bool                `tfsdk:"padded"`
	Password                 types.String              `tfsdk:"password"`
	ProcessStartDate         types.String              `tfsdk:"process_start_date"`
	ProtectStopDate          types.String              `tfsdk:"protect_stop_date"`
	RevocationReason         types.String              `tfsdk:"revocation_reason"`
	RevocationMessage        types.String              `tfsdk:"revocation_message"`
	RotationFrequencyDays    types.String              `tfsdk:"rotation_frequency_days"`
	SecretDataEncoding       types.String              `tfsdk:"secret_data_encoding"`
	SecretDataLink           types.String              `tfsdk:"secret_data_link"`
	SigningAlgo              types.String              `tfsdk:"signing_algo"`
	Size                     types.Int64               `tfsdk:"size"`
	UnExportable             types.Bool                `tfsdk:"unexportable"`
	UnDeletable              types.Bool                `tfsdk:"undeletable"`
	State                    types.String              `tfsdk:"state"`
	TemplateID               types.String              `tfsdk:"template_id"`
	UsageMask                types.Int64               `tfsdk:"usage_mask"`
	UUID                     types.String              `tfsdk:"uuid"`
	WrapKeyIDType            types.String              `tfsdk:"wrap_key_id_type"`
	WrapKeyName              types.String              `tfsdk:"wrap_key_name"`
	WrapPublicKey            types.String              `tfsdk:"wrap_public_key"`
	WrapPublicKeyPadding     types.String              `tfsdk:"wrap_public_key_padding"`
	WrappingEncryptionAlgo   types.String              `tfsdk:"wrapping_encryption_algo"`
	WrappingHashAlgo         types.String              `tfsdk:"wrapping_hash_algo"`
	WrappingMethod           types.String              `tfsdk:"wrapping_method"`
	XTS                      types.Bool                `tfsdk:"xts"`
	Aliases                  []*KeyAliasTFSDK          `tfsdk:"aliases"`
	PublicKeyParameters      *PublicKeyParametersTFSDK `tfsdk:"public_key_parameters"`
	HKDFWrap                 *WrapHKDFTFSDK            `tfsdk:"wrap_hkdf"`
	PBEWrap                  *WrapPBETFSDK             `tfsdk:"wrap_pbe"`
	RSAAESWrap               *WrapRSAAESTFSDK          `tfsdk:"wrap_rsaaes"`
	Labels                   types.Map                 `tfsdk:"labels"`
	AllVersions              types.Bool                `tfsdk:"all_versions"`
}

type HKDFParametersJSON struct {
	HashAlgorithm string `json:"hashAlgorithm"`
	IKMKeyName    string `json:"ikmKeyName"`
	Info          string `json:"info"`
	Salt          string `json:"salt"`
}

type KeyMetadataPermissionsJSON struct {
	DecryptWithKey    []string `json:"DecryptWithKey"`
	EncryptWithKey    []string `json:"EncryptWithKey"`
	ExportKey         []string `json:"ExportKey"`
	MACVerifyWithKey  []string `json:"MACVerifyWithKey"`
	MACWithKey        []string `json:"MACWithKey"`
	ReadKey           []string `json:"ReadKey"`
	SignVerifyWithKey []string `json:"SignVerifyWithKey"`
	SignWithKey       []string `json:"SignWithKey"`
	UseKey            []string `json:"UseKey"`
}

type KeyMetadataCTEJSON struct {
	PersistentOnClient bool   `json:"persistent_on_client"`
	EncryptionMode     string `json:"encryption_mode"`
	CTEVersioned       bool   `json:"cte_versioned"`
}

type KeyMetadataJSON struct {
	OwnerId     string                      `json:"owner_id"`
	Permissions *KeyMetadataPermissionsJSON `json:"permissions"`
	CTE         *KeyMetadataCTEJSON         `json:"cte"`
}

type KeyAliasJSON struct {
	Alias string `json:"alias"`
	Index int64  `json:"index"`
	Type  string `json:"type"`
}

type PublicKeyParametersJSON struct {
	ActivationDate   string         `json:"activationDate,omitempty"`
	Aliases          []KeyAliasJSON `json:"aliases"`
	ArchiveDate      string         `json:"archiveDate,omitempty"`
	DeactivationDate string         `json:"deactivationDate,omitempty"`
	Name             string         `json:"name"`
	State            string         `json:"state"`
	UnDeletable      bool           `json:"undeletable"`
	UnExportable     bool           `json:"unexportable"`
	UsageMask        int64          `json:"usageMask"`
}

type WrapHKDFJSON struct {
	HashAlgorithm string `json:"hashAlgorithm"`
	Info          string `json:"info"`
	OKMLen        int64  `json:"okmLen"`
	Salt          string `json:"salt"`
}

type WrapPBEJSON struct {
	DKLen                  int64  `json:"dklen"`
	HashAlgorithm          string `json:"hashAlgorithm"`
	Iteration              int64  `json:"iteration"`
	Password               string `json:"password"`
	PasswordIdentifier     string `json:"passwordIdentifier"`
	PasswordIdentifierType string `json:"passwordIdentifierType"`
	Purpose                string `json:"purpose"`
	Salt                   string `json:"salt"`
}

type WrapRSAAESJSON struct {
	AESKeySize int64  `json:"aesKeySize"`
	Padding    string `json:"padding"`
}

type CMKeyJSON struct {
	ID                       string                   `json:"id"`
	ActivationDate           string                   `json:"activationDate,omitempty"`
	Algorithm                string                   `json:"algorithm,omitempty"`
	ArchiveDate              string                   `json:"archiveDate,omitempty"`
	AssignSelfAsOwner        bool                     `json:"assignSelfAsOwner,omitempty"`
	CertType                 string                   `json:"certType,omitempty"`
	CompromiseDate           string                   `json:"compromiseDate,omitempty"`
	CompromiseOccurrenceDate string                   `json:"compromiseOccurrenceDate,omitempty"`
	Curveid                  string                   `json:"curveid,omitempty"`
	DeactivationDate         string                   `json:"deactivationDate,omitempty"`
	DefaultIV                string                   `json:"defaultIV,omitempty"`
	Description              string                   `json:"description,omitempty"`
	DestroyDate              string                   `json:"destroyDate,omitempty"`
	EmptyMaterial            bool                     `json:"emptyMaterial,omitempty"`
	Encoding                 string                   `json:"encoding,omitempty"`
	Format                   string                   `json:"format,omitempty"`
	GenerateKeyId            bool                     `json:"generateKeyId,omitempty"`
	HKDFCreateParameters     *HKDFParametersJSON      `json:"hkdfCreateParameters,omitempty"`
	IDSize                   int64                    `json:"idSize,omitempty"`
	KeyId                    string                   `json:"keyId,omitempty"`
	MacSignBytes             string                   `json:"macSignBytes,omitempty"`
	MacSignKeyIdentifier     string                   `json:"macSignKeyIdentifier,omitempty"`
	MacSignKeyIdentifierType string                   `json:"macSignKeyIdentifierType,omitempty"`
	Material                 string                   `json:"material,omitempty"`
	MUID                     string                   `json:"muid,omitempty"`
	ObjectType               string                   `json:"objectType,omitempty"`
	Name                     string                   `json:"name,omitempty"`
	Metadata                 *KeyMetadataJSON         `json:"meta,omitempty"`
	Padded                   bool                     `json:"padded,omitempty"`
	Password                 string                   `json:"password,omitempty"`
	ProcessStartDate         string                   `json:"processStartDate,omitempty"`
	ProtectStopDate          string                   `json:"protectStopDate,omitempty"`
	RevocationReason         string                   `json:"revocationMessage,omitempty"`
	RevocationMessage        string                   `json:"revocationReason,omitempty"`
	RotationFrequencyDays    string                   `json:"rotationFrequencyDays,omitempty"`
	SecretDataEncoding       string                   `json:"secretDataEncoding,omitempty"`
	SecretDataLink           string                   `json:"secretDataLink,omitempty"`
	SigningAlgo              string                   `json:"signingAlgo,omitempty"`
	Size                     int64                    `json:"size,omitempty"`
	UnExportable             bool                     `json:"unexportable,omitempty"`
	UnDeletable              bool                     `json:"undeletable,omitempty"`
	State                    string                   `json:"state,omitempty"`
	TemplateID               string                   `json:"templateId,omitempty"`
	UsageMask                int64                    `json:"usageMask,omitempty"`
	UUID                     string                   `json:"uuid,omitempty"`
	WrapKeyIDType            string                   `json:"wrapKeyIDType,omitempty"`
	WrapKeyName              string                   `json:"wrapKeyName,omitempty"`
	WrapPublicKey            string                   `json:"wrapPublicKey,omitempty"`
	WrapPublicKeyPadding     string                   `json:"wrapPublicKeyPadding,omitempty"`
	WrappingEncryptionAlgo   string                   `json:"wrappingEncryptionAlgo,omitempty"`
	WrappingHashAlgo         string                   `json:"wrappingHashAlgo,omitempty"`
	WrappingMethod           string                   `json:"wrappingMethod,omitempty"`
	XTS                      bool                     `json:"xts,omitempty"`
	Aliases                  []KeyAliasJSON           `json:"aliases,omitempty"`
	PublicKeyParameters      *PublicKeyParametersJSON `json:"publicKeyParameters,omitempty"`
	HKDFWrap                 *WrapHKDFJSON            `json:"wrapHKDF,omitempty"`
	PBEWrap                  *WrapPBEJSON             `json:"wrapPBE,omitempty"`
	RSAAESWrap               *WrapRSAAESJSON          `json:"wrapRSAAES,omitempty"`
	AllVersions              bool                     `json:"allVersions,omitempty"`
	Labels                   map[string]interface{}   `json:"labels,omitempty"`
}

type CMRegTokensListTFSDK struct {
	ID                types.String `tfsdk:"id"`
	URI               types.String `tfsdk:"uri"`
	Account           types.String `tfsdk:"account"`
	Application       types.String `tfsdk:"application"`
	DevAccount        types.String `tfsdk:"dev_account"`
	CreatedAt         types.String `tfsdk:"created_at"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
	Token             types.String `tfsdk:"token"`
	ValidUntil        types.String `tfsdk:"valid_until"`
	MaxClients        types.Int64  `tfsdk:"max_clients"`
	ClientsRegistered types.Int64  `tfsdk:"clients_registered"`
	CAID              types.String `tfsdk:"ca_id"`
	NamePrefix        types.String `tfsdk:"name_prefix"`
}

type CMRegTokenTFSDK struct {
	ID                        types.String `tfsdk:"id"`
	Token                     types.String `tfsdk:"token"`
	CAID                      types.String `tfsdk:"ca_id"`
	CertDuration              types.Int64  `tfsdk:"cert_duration"`
	ClientManagementProfileID types.String `tfsdk:"client_management_profile_id"`
	Label                     types.Map    `tfsdk:"label"`
	Labels                    types.Map    `tfsdk:"labels"`
	Lifetime                  types.String `tfsdk:"lifetime"`
	MaxClients                types.Int64  `tfsdk:"max_clients"`
	NamePrefix                types.String `tfsdk:"name_prefix"`
}

type CMRegTokenJSON struct {
	ID                        string                 `json:"id"`
	Token                     string                 `json:"token"`
	CAID                      string                 `json:"ca_id"`
	CertDuration              int64                  `json:"cert_duration"`
	ClientManagementProfileID string                 `json:"client_management_profile_id"`
	Label                     map[string]interface{} `json:"label"`
	Labels                    map[string]interface{} `json:"labels"`
	Lifetime                  string                 `json:"lifetime"`
	MaxClients                int64                  `json:"max_clients"`
	NamePrefix                string                 `json:"name_prefix"`
}

type CMUserTFSDK struct {
	UserID                 types.String `tfsdk:"user_id"`
	Name                   types.String `tfsdk:"full_name"`
	UserName               types.String `tfsdk:"username"`
	Nickname               types.String `tfsdk:"nickname"`
	Email                  types.String `tfsdk:"email"`
	Password               types.String `tfsdk:"password"`
	IsDomainUser           types.Bool   `tfsdk:"is_domain_user"`
	PreventUILogin         types.Bool   `tfsdk:"prevent_ui_login"`
	PasswordChangeRequired types.Bool   `tfsdk:"password_change_required"`
}

type UserLoginFlagsJSON struct {
	PreventUILogin bool `json:"prevent_ui_login"`
}

type CMUserJSON struct {
	UserID                 string             `json:"user_id"`
	Name                   string             `json:"full_name"`
	UserName               string             `json:"username"`
	Nickname               string             `json:"nickname"`
	Email                  string             `json:"email"`
	Password               string             `json:"password"`
	IsDomainUser           bool               `json:"is_domain_user"`
	LoginFlags             UserLoginFlagsJSON `json:"login_flags"`
	PasswordChangeRequired bool               `json:"password_change_required"`
}

type CMSSHKeyTFSDK struct {
	Key types.String `tfsdk:"key"`
}

type CMSSHKeyJSON struct {
	Key string `json:"key"`
}

type CMPwdChangeTFSDK struct {
	Username    types.String `tfsdk:"username"`
	Password    types.String `tfsdk:"password"`
	NewPassword types.String `tfsdk:"new_password"`
}

type CMPwdChangeJSON struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
}

type CMDomainTFSDK struct {
	ID                  types.String   `tfsdk:"id"`
	Name                types.String   `tfsdk:"name"`
	Admins              []types.String `tfsdk:"admins"`
	AllowUserManagement types.Bool     `tfsdk:"allow_user_management"`
	HSMConnectionId     types.String   `tfsdk:"hsm_connection_id"`
	HSMKEKLabel         types.String   `tfsdk:"hsm_kek_label"`
	Meta                types.Map      `tfsdk:"meta"`
	ParentCAId          types.String   `tfsdk:"parent_ca_id"`
	URI                 types.String   `tfsdk:"uri"`
	Account             types.String   `tfsdk:"account"`
	Application         types.String   `tfsdk:"application"`
	DevAccount          types.String   `tfsdk:"dev_account"`
	CreatedAt           types.String   `tfsdk:"created_at"`
	UpdatedAt           types.String   `tfsdk:"updated_at"`
}

type CMDomainJSON struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Admins              []string               `json:"admins"`
	AllowUserManagement bool                   `json:"allow_user_management"`
	HSMConnectionId     string                 `json:"hsm_connection_id"`
	HSMKEKLabel         string                 `json:"hsm_kek_label"`
	Meta                map[string]interface{} `json:"meta"`
	ParentCAId          string                 `json:"parent_ca_id"`
	URI                 string                 `json:"uri"`
	Account             string                 `json:"account"`
	Application         string                 `json:"application"`
	DevAccount          string                 `json:"devAccount"`
	CreatedAt           string                 `json:"createdAt"`
	UpdatedAt           string                 `json:"updatedAt"`
}

type CMInterfaceMetadataNAETFSDK struct {
	MaskSystemGroups types.Bool `tfsdk:"mask_system_groups"`
}
type CMInterfaceMetadataTFSDK struct {
	NAE *CMInterfaceMetadataNAETFSDK `tfsdk:"nae"`
}
type CMInterfacTrustedCAsTFSDK struct {
	External []types.String `tfsdk:"external"`
	Local    []types.String `tfsdk:"local"`
}
type CMInterfacCertificateTFSDK struct {
	CertChain types.String `tfsdk:"certificate_chain"`
	Generate  types.Bool   `tfsdk:"generate"`
	Format    types.String `tfsdk:"format"`
	Password  types.String `tfsdk:"password"`
}
type NamesParamsTFSDK struct {
	C  types.String `tfsdk:"C"`
	L  types.String `tfsdk:"L"`
	O  types.String `tfsdk:"O"`
	OU types.String `tfsdk:"OU"`
	ST types.String `tfsdk:"ST"`
}
type CMInterfaceLocalAutogenAttrTFSDK struct {
	CN          types.String       `tfsdk:"cn"`
	DNSNames    []types.String     `tfsdk:"dns_names"`
	Emails      []types.String     `tfsdk:"email_addresses"`
	IPAddresses []types.String     `tfsdk:"ip_addresses"`
	Names       []NamesParamsTFSDK `tfsdk:"names"`
	UID         types.String       `tfsdk:"uid"`
}
type TLSCiphersTFSDK struct {
	CipherSuite types.String `tfsdk:"cipher_suite"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}
type CMInterfaceTFSDK struct {
	ID                      types.String                      `tfsdk:"id"`
	Port                    types.Int64                       `tfsdk:"port"`
	AllowUnregistered       types.Bool                        `tfsdk:"allow_unregistered"`
	AutogenCAId             types.String                      `tfsdk:"auto_gen_ca_id"`
	AutogenDaysBeforeExpiry types.Int64                       `tfsdk:"auto_gen_days_before_expiry"`
	AutoRegistration        types.Bool                        `tfsdk:"auto_registration"`
	CertUserField           types.String                      `tfsdk:"cert_user_field"`
	CustomUIDSize           types.Int64                       `tfsdk:"custom_uid_size"`
	CustomUIDv2             types.Bool                        `tfsdk:"custom_uid_v2"`
	DefaultConnection       types.String                      `tfsdk:"default_connection"`
	InterfaceType           types.String                      `tfsdk:"interface_type"`
	KMIPEnableHardDelete    types.Int64                       `tfsdk:"kmip_enable_hard_delete"`
	MaximumTLSVersion       types.String                      `tfsdk:"maximum_tls_version"`
	Meta                    *CMInterfaceMetadataTFSDK         `tfsdk:"meta"`
	MinimumTLSVersion       types.String                      `tfsdk:"minimum_tls_version"`
	Mode                    types.String                      `tfsdk:"mode"`
	Name                    types.String                      `tfsdk:"name"`
	NetworkInterface        types.String                      `tfsdk:"network_interface"`
	RegToken                types.String                      `tfsdk:"registration_token"`
	TrustedCAs              *CMInterfacTrustedCAsTFSDK        `tfsdk:"trusted_cas"`
	Certificate             *CMInterfacCertificateTFSDK       `tfsdk:"certificate"`
	LocalAutogenAttributes  *CMInterfaceLocalAutogenAttrTFSDK `tfsdk:"local_auto_gen_attributes"`
	TLSCiphers              []TLSCiphersTFSDK                 `tfsdk:"tls_ciphers"`
	CreatedAt               types.String                      `tfsdk:"created_at"`
	UpdatedAt               types.String                      `tfsdk:"updated_at"`
}
type CMInterfaceMetadataNAEJSON struct {
	MaskSystemGroups bool `json:"mask_system_groups"`
}
type CMInterfaceMetadataJSON struct {
	NAE CMInterfaceMetadataNAEJSON `json:"nae"`
}
type CMInterfacTrustedCAsJSON struct {
	External []string `json:"external"`
	Local    []string `json:"local"`
}
type CMInterfacCertificateJSON struct {
	CertChain string `json:"certificate_chain"`
	Generate  bool   `json:"generate"`
	Format    string `json:"format"`
	Password  string `json:"password"`
}
type NamesParamsJSON struct {
	C  string `json:"C"`
	L  string `json:"L"`
	O  string `json:"O"`
	OU string `json:"OU"`
	ST string `json:"ST"`
}
type CMInterfaceLocalAutogenAttrJSON struct {
	CN          string            `json:"cn"`
	DNSNames    []string          `json:"dns_names"`
	Emails      []string          `json:"email_addresses"`
	IPAddresses []string          `json:"ip_addresses"`
	Names       []NamesParamsJSON `json:"names"`
	UID         string            `json:"uid"`
}
type TLSCiphersJSON struct {
	CipherSuite string `json:"cipher_suite"`
	Enabled     bool   `json:"enabled"`
}
type CMInterfaceJSON struct {
	ID                      string                          `json:"id"`
	Port                    int64                           `json:"port"`
	AllowUnregistered       bool                            `json:"allow_unregistered"`
	AutogenCAId             string                          `json:"auto_gen_ca_id"`
	AutogenDaysBeforeExpiry int64                           `json:"auto_gen_days_before_expiry"`
	AutoRegistration        bool                            `json:"auto_registration"`
	CertUserField           string                          `json:"cert_user_field"`
	CustomUIDSize           int64                           `json:"custom_uid_size"`
	CustomUIDv2             bool                            `json:"custom_uid_v2"`
	DefaultConnection       string                          `json:"default_connection"`
	InterfaceType           string                          `json:"interface_type"`
	KMIPEnableHardDelete    int64                           `json:"kmip_enable_hard_delete"`
	MaximumTLSVersion       string                          `json:"maximum_tls_version"`
	Meta                    CMInterfaceMetadataJSON         `json:"meta"`
	MinimumTLSVersion       string                          `json:"minimum_tls_version"`
	Mode                    string                          `json:"mode"`
	Name                    string                          `json:"name"`
	NetworkInterface        string                          `json:"network_interface"`
	RegToken                string                          `json:"registration_token"`
	TrustedCAs              CMInterfacTrustedCAsJSON        `json:"trusted_cas"`
	Certificate             CMInterfacCertificateJSON       `json:"certificate"`
	LocalAutogenAttributes  CMInterfaceLocalAutogenAttrJSON `json:"local_auto_gen_attributes"`
	TLSCiphers              []TLSCiphersJSON                `json:"tls_ciphers"`
	CreatedAt               string                          `json:"createdAt"`
	UpdatedAt               string                          `json:"updatedAt"`
}

type CMLicenseTFSDK struct {
	ID                    types.String `tfsdk:"id"`
	License               types.String `tfsdk:"license"`
	BindType              types.String `tfsdk:"bind_type"`
	Hash                  types.String `tfsdk:"hash"`
	Type                  types.String `tfsdk:"type"`
	State                 types.String `tfsdk:"state"`
	Start                 types.String `tfsdk:"start"`
	Expiration            types.String `tfsdk:"expiration"`
	Version               types.String `tfsdk:"version"`
	LicenseCount          types.Int64  `tfsdk:"license_count"`
	TrialSecondsRemaining types.String `tfsdk:"trial_seconds_remaining"`
}
type CMLicenseJSON struct {
	ID                    string `json:"id"`
	License               string `json:"license"`
	BindType              string `json:"bind_type"`
	Hash                  string `json:"hash"`
	Type                  string `json:"type"`
	State                 string `json:"state"`
	Start                 string `json:"start"`
	Expiration            string `json:"expiration"`
	Version               string `json:"version"`
	LicenseCount          int64  `json:"license_count"`
	TrialSecondsRemaining string `json:"trial_seconds_remaining"`
}

type CMNTPTFSDK struct {
	ID      types.String `tfsdk:"id"`
	Host    types.String `tfsdk:"host"`
	Key     types.String `tfsdk:"key"`
	KeyType types.String `tfsdk:"key_type"`
}
type CMNTPJSON struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
}
