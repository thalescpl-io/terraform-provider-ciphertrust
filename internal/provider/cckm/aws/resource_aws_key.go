package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	common "github.com/thalescpl-io/terraform-provider-ciphertrust/internal/provider/common"
)

var (
	_ resource.Resource              = &resourceAWSKey{}
	_ resource.ResourceWithConfigure = &resourceAWSKey{}
)

func NewResourceAWSKey() resource.Resource {
	return &resourceAWSKey{}
}

type resourceAWSKey struct {
	client *common.Client
}

func (r *resourceAWSKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key"
}

// Schema defines the schema for the resource.
func (r *resourceAWSKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"kms": schema.StringAttribute{
				Required:    true,
				Description: "Name or ID of the KMS to be used to create the key.",
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "Name of the available regions.",
			},
			"aws_param": schema.ListNestedAttribute{
				Required:    true,
				Description: "AWS key parameters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"alias": schema.StringAttribute{
							Optional:    true,
							Description: "Alias for the KMS key.",
						},
						"bypass_policy_lockout_safety_check": schema.BoolAttribute{
							Optional:    true,
							Description: "Whether to bypass the key policy lockout safety check.",
						},
						"customer_master_key_spec": schema.StringAttribute{
							Optional:    true,
							Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"SYMMETRIC_DEFAULT",
									"RSA_2048",
									"RSA_3072",
									"RSA_4096",
									"ECC_NIST_P256",
									"ECC_NIST_P384",
									"ECC_NIST_P521",
									"ECC_SECG_P256K1",
									"HMAC_224",
									"HMAC_256",
									"HMAC_384",
									"HMAC_512"}...),
							},
						},
						"description": schema.StringAttribute{
							Optional:    true,
							Description: "Description of the key.",
						},
						"key_usage": schema.StringAttribute{
							Optional:    true,
							Description: "Intended use of the KMS key.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"ENCRYPT_DECRYPT",
									"SIGN_VERIFY",
									"GENERATE_VERIFY_MAC"}...),
							},
						},
						"multi_region": schema.BoolAttribute{
							Optional:    true,
							Description: "Create a multi region primary key.",
						},
						"origin": schema.StringAttribute{
							Optional:    true,
							Description: "Source of the KMS key's key material. The origin cannot be changed after the KMS key is created.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"AWS_KMS",
									"EXTERNAL"}...),
							},
						},
						"policy": schema.MapAttribute{
							ElementType: types.StringType,
							Optional:    true,
							Description: "Key policy to attach to the KMS key. Policy is mutually exclusive to all other policy parameters. If no policy parameters are specified the default policy is used.",
						},
						"tags": schema.ListNestedAttribute{
							Optional:    true,
							Description: "",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"tag_key": schema.StringAttribute{
										Required:    true,
										Description: "key for the tag.",
									},
									"tag_value": schema.StringAttribute{
										Required:    true,
										Description: "value corresponding to key of the tag.",
									},
								},
							},
						},
					},
				},
			},
			"external_accounts": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "AWS accounts that can use this key. External accounts are mutually exclusive to policy and policy template. If no policy parameters are specified the default policy is used.",
			},
			"key_admins": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IAM users who can administer this key using the KMS API. Key admins are mutually exclusive to policy and policy template. If no policy parameters are specified the default policy is used.",
			},
			"key_admins_roles": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IAM roles that can administer this key using the KMS API. Key admins are mutually exclusive to policy and policy template. If no policy parameters are specified the default policy is used.",
			},
			"key_users": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IAM users who can use the KMS key in cryptographic operations. Key users are mutually exclusive to policy and policy template. If no policy parameters are specified the default policy is used.",
			},
			"key_users_roles": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "IAM roles that can use the KMS key in cryptographic operations. Key users are mutually exclusive to policy and policy template. If no policy parameters are specified the default policy is used.",
			},
			"policytemplate": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the policy template to apply. Policy template is mutually exclusive to all other policy parameters. If no policy parameters are specified the default policy is used.",
			},
			// Update related parameters
			"update_op_type": schema.StringAttribute{
				Optional:    true,
				Description: "Update operation to be performed for the AWS key",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"enable-rotation-job",
						"disable-rotation-job",
						"import-material",
						"delete-material",
						"rotate",
						"rotate-material",
						"schedule-deletion",
						"policy",
						"update-description",
						"enable",
						"diable",
						"add-tags",
						"remove-tags",
						"add-alias",
						"delete-alias",
						"cancel-deletion",
						"enable-auto-rotation",
						"disable-auto-rotation"}...),
				},
			},
			// params for enable-rotation-job
			"job_config_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the scheduler configuration job that will schedule the key rotation.",
			},
			"auto_rotate_disable_encrypt": schema.BoolAttribute{
				Optional:    true,
				Description: "Disable encryption on the old key. Parameters auto_rotate_disable_encrypt and auto_rotate_disable_encrypt_on_all_accounts are mutually exclusive. Specify either auto_rotate_disable_encrypt or auto_rotate_disable_encrypt_on_all_accounts.",
			},
			"auto_rotate_disable_encrypt_on_all_accounts": schema.BoolAttribute{
				Optional:    true,
				Description: "Disable encryption permissions on the old key for all the accounts. Parameters auto_rotate_disable_encrypt and auto_rotate_disable_encrypt_on_all_accounts are mutually exclusive. Specify either auto_rotate_disable_encrypt or auto_rotate_disable_encrypt_on_all_accounts.",
			},
			"auto_rotate_domain_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the domain in which the DSM key will be created.",
			},
			"auto_rotate_external_cm_domain_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the external-cm domain in which the external-cm key will be created.",
			},
			"auto_rotate_key_source": schema.StringAttribute{
				Optional:    true,
				Description: "Key source from where the key will be uploaded.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"local",
						"dsm",
						"hsm-luna",
						"external-cm"}...),
				},
			},
			"auto_rotate_partition_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the partition in which hsm-luna key will be created.",
			},
			// Params for import-material
			"key_expiration": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to disable encryption on key which is getting rotated.",
			},
			"source_key_identifier": schema.StringAttribute{
				Optional:    true,
				Description: "source_key_identifier is the mandatory parameter. (Optional only if source_key_tier is local and key is 256 bits AES key). If key material is re-imported, AWS allows re-importing the same key material only, therefore it is mandatory to provide source key identifier of the same source key which was imported previously.",
			},
			"source_key_tier": schema.StringAttribute{
				Optional:    true,
				Description: "Source key tier. Options are local, external-cm, dsm and hsm-luna. Default is local.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"local",
						"dsm",
						"hsm-luna",
						"external-cm"}...),
				},
			},
			"valid_to": schema.StringAttribute{
				Optional:    true,
				Description: "Key expiration time of new roated key, must be formatted as per RFC3339.",
			},
			// Params for rotate
			"disable_encrypt": schema.BoolAttribute{
				Optional:    true,
				Description: "Indicates whether to disable encryption permissions on the old key (after key rotation). Parameters disable_encrypt and disable_encrypt_on_all_accounts are mutually exclusive. Specify either disable_encrypt or disable_encrypt_on_all_accounts.",
			},
			"disable_encrypt_on_all_accounts": schema.BoolAttribute{
				Optional:    true,
				Description: "Indicates whether to disable encryption permissions on the old key for all the accounts (after key rotation). Parameters disable_encrypt and disable_encrypt_on_all_accounts are mutually exclusive. Specify either disable_encrypt or disable_encrypt_on_all_accounts.",
			},
			"retain_alias": schema.BoolAttribute{
				Optional:    true,
				Description: "Indicates whether to retain the alias with the timestamp on the archived key after key rotation.",
			},
			"source_key_id": schema.StringAttribute{
				Optional:    true,
				Description: "If source_key_tier is dsm or hsm-luna or 'external-cm`, this parameter is the key identifier of the key to be uploaded. source_key_id is a mandatory parameter in the case of dsm, external-cm and hsm-luna. If source_key_tier is local, this parameter is the key identifier of the CipherTrust Manager key to be uploaded. By default, a new CipherTrust Manager key is generated automatically.",
			},
			// Params for schedule-deletion
			"days": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of days after which the key will be deleted.",
			},
			// Params for add-tags
			"tags": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Tags to be added to the AWS key.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"tag_key": schema.StringAttribute{
							Required:    true,
							Description: "key for the tag.",
						},
						"tag_value": schema.StringAttribute{
							Required:    true,
							Description: "value corresponding to key of the tag.",
						},
					},
				},
			},
			// Params for remove-tags
			"delete_tags": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Tags to be removed from the AWS key.",
			},
			// Params for add-alias
			"alias": schema.StringAttribute{
				Optional:    true,
				Description: "Alias to be added to the AWS key.",
			},
			// Params for enable-auto-rotation
			"rotation_period_in_days": schema.Int64Attribute{
				Optional:    true,
				Description: "Specify the rotation period in days.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceAWSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_key.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan AWSKeyTFSDK
	var payload AWSKeyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.KMS.ValueString() != "" && plan.KMS.ValueString() != types.StringNull().ValueString() {
		payload.KMS = plan.KMS.ValueString()
	}
	if plan.Region.ValueString() != "" && plan.Region.ValueString() != types.StringNull().ValueString() {
		payload.Region = plan.Region.ValueString()
	}
	if plan.PolicyTemplate.ValueString() != "" && plan.PolicyTemplate.ValueString() != types.StringNull().ValueString() {
		payload.PolicyTemplate = plan.PolicyTemplate.ValueString()
	}

	var externalAccounts []string
	for _, externalAccount := range plan.ExternalAccounts {
		externalAccounts = append(externalAccounts, externalAccount.ValueString())
	}
	payload.ExternalAccounts = externalAccounts

	var keyAdmins []string
	for _, keyAdmin := range plan.KeyAdmins {
		keyAdmins = append(keyAdmins, keyAdmin.ValueString())
	}
	payload.KeyAdmins = keyAdmins

	var keyAdminRoles []string
	for _, keyAdminRole := range plan.KeyAdminRoles {
		keyAdminRoles = append(keyAdminRoles, keyAdminRole.ValueString())
	}
	payload.KeyAdminRoles = keyAdminRoles

	var keyUsers []string
	for _, keyUser := range plan.KeyUsers {
		keyUsers = append(keyUsers, keyUser.ValueString())
	}
	payload.KeyUsers = keyUsers

	var keyUserRoles []string
	for _, keyUserRole := range plan.KeyUserRoles {
		keyUserRoles = append(keyUserRoles, keyUserRole.ValueString())
	}
	payload.KeyUserRoles = keyUserRoles

	// Add aws_param to the payload if set
	var awsParam AWSKeyParamJSON
	if (!reflect.DeepEqual(AWSKeyParamTFSDK{}, plan.AWSParam)) {
		tflog.Debug(ctx, "aws_param should not be empty at this point")
		if plan.AWSParam.Alias.ValueString() != "" && plan.AWSParam.Alias.ValueString() != types.StringNull().ValueString() {
			awsParam.Alias = plan.AWSParam.Alias.ValueString()
		}
		if plan.AWSParam.BypassPolicyLockoutSafetyCheck.ValueBool() != types.BoolNull().ValueBool() {
			awsParam.BypassPolicyLockoutSafetyCheck = plan.AWSParam.BypassPolicyLockoutSafetyCheck.ValueBool()
		}
		if plan.AWSParam.CustomerMasterKeySpec.ValueString() != "" && plan.AWSParam.CustomerMasterKeySpec.ValueString() != types.StringNull().ValueString() {
			awsParam.CustomerMasterKeySpec = plan.AWSParam.CustomerMasterKeySpec.ValueString()
		}
		if plan.AWSParam.Description.ValueString() != "" && plan.AWSParam.Description.ValueString() != types.StringNull().ValueString() {
			awsParam.Description = plan.AWSParam.Description.ValueString()
		}
		if plan.AWSParam.KeyUsage.ValueString() != "" && plan.AWSParam.KeyUsage.ValueString() != types.StringNull().ValueString() {
			awsParam.KeyUsage = plan.AWSParam.KeyUsage.ValueString()
		}
		if plan.AWSParam.MultiRegion.ValueBool() != types.BoolNull().ValueBool() {
			awsParam.MultiRegion = plan.AWSParam.MultiRegion.ValueBool()
		}
		policyPayload := make(map[string]interface{})
		for k, v := range plan.AWSParam.Policy.Elements() {
			policyPayload[k] = v.(types.String).ValueString()
		}
		payload.AWSParam.Policy = policyPayload

		var tags []AWSKeyParamTagJSON
		for _, tagInput := range plan.AWSParam.Tags {
			var tag AWSKeyParamTagJSON
			if tagInput.TagKey.ValueString() != "" && tagInput.TagKey.ValueString() != types.StringNull().ValueString() {
				tag.TagKey = tagInput.TagKey.ValueString()
			}
			if tagInput.TagValue.ValueString() != "" && tagInput.TagValue.ValueString() != types.StringNull().ValueString() {
				tag.TagValue = tagInput.TagValue.ValueString()
			}
			tags = append(tags, tag)
		}
		payload.AWSParam.Tags = tags

		payload.AWSParam = &awsParam
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_KEY_MANAGEMENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating key on CipherTrust Manager: ",
			"Could not create key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_key.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceAWSKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceAWSKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan AWSKeyTFSDK
	var payload AWSKeyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.UpdateOpType.ValueString() != "" && plan.UpdateOpType.ValueString() != types.StringNull().ValueString() {
		if plan.UpdateOpType.ValueString() == "enable-rotation-job" {

		} else if plan.UpdateOpType.ValueString() == "disable-rotation-job" {

		} else if plan.UpdateOpType.ValueString() == "import-material" {

		} else if plan.UpdateOpType.ValueString() == "delete-material" {

		} else if plan.UpdateOpType.ValueString() == "rotate" {

		} else if plan.UpdateOpType.ValueString() == "rotate-material" {

		} else if plan.UpdateOpType.ValueString() == "schedule-deletion" {

		} else if plan.UpdateOpType.ValueString() == "policy" {

		} else if plan.UpdateOpType.ValueString() == "update-description" {

		} else if plan.UpdateOpType.ValueString() == "enable" {

		} else if plan.UpdateOpType.ValueString() == "diable" {

		} else if plan.UpdateOpType.ValueString() == "add-tags" {

		} else if plan.UpdateOpType.ValueString() == "remove-tags" {

		} else if plan.UpdateOpType.ValueString() == "add-alias" {

		} else if plan.UpdateOpType.ValueString() == "delete-alias" {

		} else if plan.UpdateOpType.ValueString() == "cancel-deletion" {

		} else if plan.UpdateOpType.ValueString() == "enable-auto-rotation" {

		} else if plan.UpdateOpType.ValueString() == "disable-auto-rotation" {

		} else {

		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_KEY_MANAGEMENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating key on CipherTrust Manager: ",
			"Could not upodate key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceAWSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AWSKeyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	output, err := r.client.DeleteByID(ctx, state.ID.ValueString(), common.URL_KEY_MANAGEMENT)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_key.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Key",
			"Could not delete key, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceAWSKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
