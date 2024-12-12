package connections

import "github.com/hashicorp/terraform-plugin-framework/types"

type IAMRoleAnywhereTFSDK struct {
	AnywhereRoleARN types.String `tfsdk:"anywhere_role_arn"`
	Certificate     types.String `tfsdk:"certificate"`
	ProfileARN      types.String `tfsdk:"profile_arn"`
	TrustAnchorARN  types.String `tfsdk:"trust_anchor_arn"`
	PrivateKey      types.String `tfsdk:"private_key"`
}

type AWSConnectionModelTFSDK struct {
	ID                      types.String         `tfsdk:"id"`
	Name                    types.String         `tfsdk:"name"`
	Description             types.String         `tfsdk:"description"`
	AccessKeyID             types.String         `tfsdk:"access_key_id"`
	AssumeRoleARN           types.String         `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID    types.String         `tfsdk:"assume_role_external_id"`
	AWSRegion               types.String         `tfsdk:"aws_region"`
	AWSSTSRegionalEndpoints types.String         `tfsdk:"aws_sts_regional_endpoints"`
	CloudName               types.String         `tfsdk:"cloud_name"`
	IsRoleAnywhere          types.Bool           `tfsdk:"is_role_anywhere"`
	IAMRoleAnywhere         IAMRoleAnywhereTFSDK `tfsdk:"iam_role_anywhere"`
	Labels                  types.Map            `tfsdk:"labels"`
	Meta                    types.Map            `tfsdk:"meta"`
	Products                []types.String       `tfsdk:"products"`
	SecretAccessKey         types.String         `tfsdk:"secret_access_key"`
}

type IAMRoleAnywhereJSON struct {
	AnywhereRoleARN string `json:"anywhere_role_arn"`
	Certificate     string `json:"certificate"`
	ProfileARN      string `json:"profile_arn"`
	TrustAnchorARN  string `json:"trust_anchor_arn"`
	PrivateKey      string `json:"private_key"`
}

type AWSConnectionModelJSON struct {
	ID                      string                 `json:"id"`
	Name                    string                 `json:"name"`
	Description             string                 `json:"description"`
	AccessKeyID             string                 `json:"access_key_id"`
	AssumeRoleARN           string                 `json:"assume_role_arn"`
	AssumeRoleExternalID    string                 `json:"assume_role_external_id"`
	AWSRegion               string                 `json:"aws_region"`
	AWSSTSRegionalEndpoints string                 `json:"aws_sts_regional_endpoints"`
	CloudName               string                 `json:"cloud_name"`
	IsRoleAnywhere          bool                   `json:"is_role_anywhere"`
	IAMRoleAnywhere         *IAMRoleAnywhereJSON   `json:"iam_role_anywhere"`
	Labels                  map[string]interface{} `json:"labels"`
	Meta                    map[string]interface{} `json:"meta"`
	Products                []string               `json:"products"`
	SecretAccessKey         string                 `json:"secret_access_key"`
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

type CMCreateConnectionResponseCommonTFSDK struct {
	URI                 types.String `tfsdk:"uri"`
	Account             types.String `tfsdk:"account"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
	Service             types.String `tfsdk:"service"`
	Category            types.String `tfsdk:"category"`
	ResourceURL         types.String `tfsdk:"resource_url"`
	LastConnectionOK    types.Bool   `tfsdk:"last_connection_ok"`
	LastConnectionError types.String `tfsdk:"last_connection_error"`
	LastConnectionAt    types.String `tfsdk:"last_connection_at"`
}

type CMCreateConnectionResponseCommon struct {
	URI                 string `json:"uri"`
	Account             string `json:"account"`
	CreatedAt           string `json:"createdAt"`
	UpdatedAt           string `json:"updatedAt"`
	Service             string `json:"service"`
	Category            string `json:"category"`
	ResourceURL         string `json:"resource_url"`
	LastConnectionOK    bool   `json:"last_connection_ok"`
	LastConnectionError string `json:"last_connection_error"`
	LastConnectionAt    string `json:"last_connection_at"`
}

type GCPConnectionTFSDK struct {
	CMCreateConnectionResponseCommonTFSDK
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Products    []types.String `tfsdk:"products"`
	Meta        types.Map      `tfsdk:"meta"`
	Description types.String   `tfsdk:"description"`
	Labels      types.Map      `tfsdk:"labels"`
	CloudName   types.String   `tfsdk:"cloud_name"`
	KeyFile     types.String   `tfsdk:"key_file"`
}

type GCPConnectionJSON struct {
	CMCreateConnectionResponseCommon
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Products    []string               `json:"products"`
	Meta        interface{}            `json:"meta"`
	Description string                 `json:"description"`
	Labels      map[string]interface{} `json:"labels"`
	CloudName   string                 `json:"cloud_name"`
	KeyFile     string                 `json:"key_file"`
}
