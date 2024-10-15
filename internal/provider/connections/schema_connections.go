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
