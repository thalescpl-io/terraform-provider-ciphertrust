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
	OwnerId     types.String                `tfsdk:"owner_id"`
	Permissions KeyMetadataPermissionsTFSDK `tfsdk:"permissions"`
	CTE         KeyMetadataCTETFSDK         `tfsdk:"cte"`
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

type CMScpConnectionListModelTFDSK struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Products    []types.String `tfsdk:"products"`
	Description types.String   `tfsdk:"description"`
	Host        types.String   `tfsdk:"host"`
	Port        types.Int64    `tfsdk:"port"`
	Username    types.String   `tfsdk:"username"`
	AuthMethod  types.String   `tfsdk:"auth_method"`
	PathTo      types.String   `tfsdk:"path_to"`
	Protocol    types.String   `tfsdk:"protocol"`
}

type CMScpConnectionTFDSK struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Products    []types.String `tfsdk:"products"`
	Meta        types.Map      `tfsdk:"meta"`
	Description types.String   `tfsdk:"description"`
	Labels      types.Map      `tfsdk:"labels"`
	Host        types.String   `tfsdk:"host"`
	Port        types.Int64    `tfsdk:"port"`
	Username    types.String   `tfsdk:"username"`
	AuthMethod  types.String   `tfsdk:"auth_method"`
	PathTo      types.String   `tfsdk:"path_to"`
	Protocol    types.String   `tfsdk:"protocol"`
	Password    types.String   `tfsdk:"password"`
	PublicKey   types.String   `tfsdk:"public_key"`
}

type CMScpConnectionJSON struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Products    []string               `json:"products"`
	Meta        interface{}            `json:"meta"`
	Description string                 `json:"description"`
	Labels      map[string]interface{} `json:"labels"`
	Host        string                 `json:"host"`
	Port        int64                  `json:"port"`
	Username    string                 `json:"username"`
	AuthMethod  string                 `json:"auth_method"`
	PathTo      string                 `json:"path_to"`
	Protocol    string                 `json:"protocol"`
	Password    string                 `json:"password"`
	PublicKey   string                 `json:"public_key"`
}
