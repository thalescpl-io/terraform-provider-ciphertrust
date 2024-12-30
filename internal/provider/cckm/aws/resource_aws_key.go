package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	// "reflect"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
			"region": schema.StringAttribute{
				Required:    true,
				Description: "AWS region in which to create or replicate a key.",
			},
			"alias": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Alias(es) of the key. To allow for key rotation changing or removing original aliases, all aliases already assigned to another key will be ignored.",
			},
			"auto_rotate": schema.BoolAttribute{
				Required:    true,
				Description: "Enable AWS autorotation on the key. Default is false.",
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
				Description: "Description of the AWS key.",
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable or disable the key. Default is true.",
			},
			"enable_rotation": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Enable the key for scheduled rotation job.",
				Attributes: map[string]schema.Attribute{
					"job_config_id": schema.StringAttribute{
						Required:    true,
						Description: "ID of the scheduler configuration job that will schedule the key rotation.",
					},
					"key_source": schema.StringAttribute{
						Required:    true,
						Description: "Key source from where the key will be uploaded.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"local",
								"dsm",
								"hsm-luna",
								"external-cm"}...),
						},
					},
					"disable_encrypt": schema.BoolAttribute{
						Optional:    true,
						Description: "Disable encryption on the old key.",
					},
					"disable_encrypt_on_all_accounts": schema.BoolAttribute{
						Optional:    true,
						Description: "Disable encryption permissions on the old key for all the accounts. Parameters auto_rotate_disable_encrypt and auto_rotate_disable_encrypt_on_all_accounts are mutually exclusive. Specify either auto_rotate_disable_encrypt or auto_rotate_disable_encrypt_on_all_accounts.",
					},
					"dsm_domain_id": schema.StringAttribute{
						Optional:    true,
						Description: "DSM domain ID, required if key_source is dsm.",
					},
					"hsm_partition_id": schema.StringAttribute{
						Optional:    true,
						Description: "HSM Luna partition ID, required if key_source is hsm-luna.",
					},
					"external_cm_domain_id": schema.StringAttribute{
						Optional:    true,
						Description: "ID of the external-cm domain in which the external-cm key will be created, required is the key_source is external-cm",
					},
				},
			},
			"import_key_material": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Key import details.",
				Attributes: map[string]schema.Attribute{
					"source_key_name": schema.StringAttribute{
						Required:    true,
						Description: "Name of the key created for key material.",
					},
					"dsm_domain_id": schema.StringAttribute{
						Optional:    true,
						Description: "Domain for the DSM key. Required if source_key_tier is dsm.",
					},
					"hsm_partition_id": schema.StringAttribute{
						Optional:    true,
						Description: "Partition for the HSM Luna key. Required if source_key_tier is hsm-luna.",
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
					"key_expiration": schema.BoolAttribute{
						Optional:    true,
						Description: "Enable key material expiration.",
					},
					"valid_to": schema.StringAttribute{
						Optional:    true,
						Description: "Date of key material expiry in UTC time in RFC3339 format. For example, 2022-07-03T14:24:00Z.",
					},
				},
			},
			"key_policy": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Key policy to attach to the AWS key. Policy and key administrators, key_users, and AWS accounts are mutually exclusive. Specify either the policy or any one user at a time. If no parameters are specified, the default policy is used.",
				Attributes: map[string]schema.Attribute{
					"external_accounts": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Other AWS accounts that can access to the key.",
					},
					"key_admins": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Key administrators - users.",
					},
					"key_admins_roles": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Key administrators - roles.",
					},
					"key_users": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Key users - users.",
					},
					"key_users_roles": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Key users - roles.",
					},
					"policy": schema.StringAttribute{
						Optional:    true,
						Description: "AWS key policy json.",
					},
					"policytemplate": schema.StringAttribute{
						Optional:    true,
						Description: "CipherTrust policy template ID",
					},
				},
			},
			"key_usage": schema.StringAttribute{
				Optional:    true,
				Description: "Specifies the intended use of the key. RSA key options: ENCRYPT_DECRYPT, SIGN_VERIFY. Default is ENCRYPT_DECRYPT. EC key options: SIGN_VERIFY. Default is SIGN_VERIFY. Symmetric key options: ENCRYPT_DECRYPT. Default is ENCRYPT_DECRYPT.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"ENCRYPT_DECRYPT",
						"SIGN_VERIFY",
						"GENERATE_VERIFY_MAC"}...),
				},
			},
			"kms": schema.StringAttribute{
				Required:    true,
				Description: "Name or ID of the KMS to be used to create the key. Required unless replicating a multi-user key.",
			},
			"multi_region": schema.BoolAttribute{
				Optional:    true,
				Description: "Creates or identifies a multi-region key.",
			},
			"origin": schema.StringAttribute{
				Optional:    true,
				Description: "Source of the CMK's key material. Options: AWS_KMS, EXTERNAL. AWS_KMS will create a native AWS key and is the default for AWS native key creation. EXTERNAL will create an external AWS key and is the default for import operations. This parameter is not required for upload operations.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"AWS_KMS",
						"EXTERNAL"}...),
				},
			},
			"primary_region": schema.StringAttribute{
				Optional:    true,
				Description: "Update the primary region of a multi-region key. Can only be set for a primary key.",
			},
			"replicate_key": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Key replication details.",
				Attributes: map[string]schema.Attribute{
					"key_id": schema.StringAttribute{
						Optional:    true,
						Description: "CipherTrust key ID of the key to replicate.",
					},
					"import_key_material": schema.BoolAttribute{
						Optional:    true,
						Description: "Import key material to a replicated external key.",
					},
					"key_expiration": schema.BoolAttribute{
						Optional:    true,
						Description: "Enable key expiration of the replicated key. Only applies to external keys.",
					},
					"make_primary": schema.BoolAttribute{
						Optional:    true,
						Description: "Update the primary key region to the replicated key's region following replication.",
					},
					"valid_to": schema.StringAttribute{
						Optional:    true,
						Description: "Date the key material of the replicated key expires. Only applies to external keys. Set as UTC time in RFC3339 format. For example, 2022-07-03T14:24:00Z.",
					},
				},
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional:    true,
				Description: "Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is 7.",
			},
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
			"upload_key": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Key upload details.",
				Attributes: map[string]schema.Attribute{
					"source_key_identifier": schema.StringAttribute{
						Optional:    true,
						Description: "DSM or CipherTrust key ID to upload to AWS.",
					},
					"key_expiration": schema.BoolAttribute{
						Optional:    true,
						Description: "Enable key expiration.",
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
						Description: "Date of key expiry in UTC time in RFC3339 format. For example, 2022-07-03T14:24:00Z.",
					},
				},
			},
			//Read-Only Params
			"arn": schema.StringAttribute{
				Computed:    true,
				Description: "The Amazon Resource Name (ARN) of the key.",
			},
			"aws_account_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS account ID.",
			},
			"aws_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS key ID.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "AWS cloud.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was created.",
			},
			"deletion_date": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key is scheduled for deletion.",
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True if the key is enabled.",
			},
			"encryption_algorithms": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Encryption algorithms of an asymmetric key",
			},
			"expiration_model": schema.StringAttribute{
				Computed:    true,
				Description: "Expiration model.",
			},
			"external_accounts": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Other AWS accounts that have access to this key.",
			},
			"key_admins": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Key ID.",
			},
			"key_manager": schema.StringAttribute{
				Computed:    true,
				Description: "Key manager.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "Key material origin.",
			},
			"key_rotation_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True if rotation is enabled in AWS for this key.",
			},
			"key_source": schema.StringAttribute{
				Computed:    true,
				Description: "Source of the key.",
			},
			"key_state": schema.StringAttribute{
				Computed:    true,
				Description: "Key state.",
			},
			"key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Key type.",
			},
			"key_users": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"kms_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the kms",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
			},
			"local_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust key identifier of the external key.",
			},
			"local_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust key name of the external key.",
			},
			"multi_region_key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Indicates if the key is the primary key or a replica key..",
			},
			"multi_region_primary_key": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Multi-region primary key details.",
			},
			//multi_region_replica_keys
			"policy": schema.StringAttribute{
				Computed:    true,
				Description: "AWS key policy.",
			},
			"policy_template_tag": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "AWS key tag for an associated policy template.",
			},
			"replica_policy": schema.StringAttribute{
				Computed:    true,
				Description: "Replication policy.",
			},
			"rotated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time when this key was rotated by a scheduled rotation job.",
			},
			"rotated_from": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID from of the key this key has been rotated from by a scheduled rotation job.",
			},
			"rotated_to": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID which this key has been rotated too by a scheduled rotation job.",
			},
			"rotation_status": schema.StringAttribute{
				Computed:    true,
				Description: "Rotation status of the key.",
			},
			"synced_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was synchronized.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was last updated.",
			},
			"valid_to": schema.StringAttribute{
				Computed:    true,
				Description: "Date of key material expiry.",
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
	// if plan.PolicyTemplate.ValueString() != "" && plan.PolicyTemplate.ValueString() != types.StringNull().ValueString() {
	// 	payload.PolicyTemplate = plan.PolicyTemplate.ValueString()
	// }

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
	// for _, keyAdminRole := range plan.KeyAdminRoles {
	// 	keyAdminRoles = append(keyAdminRoles, keyAdminRole.ValueString())
	// }
	payload.KeyAdminRoles = keyAdminRoles

	var keyUsers []string
	for _, keyUser := range plan.KeyUsers {
		keyUsers = append(keyUsers, keyUser.ValueString())
	}
	payload.KeyUsers = keyUsers

	var keyUserRoles []string
	// for _, keyUserRole := range plan.KeyUserRoles {
	// 	keyUserRoles = append(keyUserRoles, keyUserRole.ValueString())
	// }
	payload.KeyUserRoles = keyUserRoles

	// Add aws_param to the payload if set
	// var awsParam AWSKeyParamJSON
	// if !reflect.DeepEqual((*AWSKeyParamTFSDK)(nil), plan.AWSParam) {
	// 	tflog.Debug(ctx, "aws_param should not be empty at this point")
	// 	if plan.AWSParam.Alias.ValueString() != "" && plan.AWSParam.Alias.ValueString() != types.StringNull().ValueString() {
	// 		awsParam.Alias = plan.AWSParam.Alias.ValueString()
	// 	}
	// 	if plan.AWSParam.BypassPolicyLockoutSafetyCheck.ValueBool() != types.BoolNull().ValueBool() {
	// 		awsParam.BypassPolicyLockoutSafetyCheck = plan.AWSParam.BypassPolicyLockoutSafetyCheck.ValueBool()
	// 	}
	// 	if plan.AWSParam.CustomerMasterKeySpec.ValueString() != "" && plan.AWSParam.CustomerMasterKeySpec.ValueString() != types.StringNull().ValueString() {
	// 		awsParam.CustomerMasterKeySpec = plan.AWSParam.CustomerMasterKeySpec.ValueString()
	// 	}
	// 	if plan.AWSParam.Description.ValueString() != "" && plan.AWSParam.Description.ValueString() != types.StringNull().ValueString() {
	// 		awsParam.Description = plan.AWSParam.Description.ValueString()
	// 	}
	// 	if plan.AWSParam.KeyUsage.ValueString() != "" && plan.AWSParam.KeyUsage.ValueString() != types.StringNull().ValueString() {
	// 		awsParam.KeyUsage = plan.AWSParam.KeyUsage.ValueString()
	// 	}
	// 	if plan.AWSParam.MultiRegion.ValueBool() != types.BoolNull().ValueBool() {
	// 		awsParam.MultiRegion = plan.AWSParam.MultiRegion.ValueBool()
	// 	}
	// 	policyPayload := make(map[string]interface{})
	// 	for k, v := range plan.AWSParam.Policy.Elements() {
	// 		policyPayload[k] = v.(types.String).ValueString()
	// 	}
	// 	payload.AWSParam.Policy = policyPayload

	// 	var tags []AWSKeyParamTagJSON
	// 	for _, tagInput := range plan.AWSParam.Tags {
	// 		var tag AWSKeyParamTagJSON
	// 		if tagInput.TagKey.ValueString() != "" && tagInput.TagKey.ValueString() != types.StringNull().ValueString() {
	// 			tag.TagKey = tagInput.TagKey.ValueString()
	// 		}
	// 		if tagInput.TagValue.ValueString() != "" && tagInput.TagValue.ValueString() != types.StringNull().ValueString() {
	// 			tag.TagValue = tagInput.TagValue.ValueString()
	// 		}
	// 		tags = append(tags, tag)
	// 	}
	// 	payload.AWSParam.Tags = tags

	// 	payload.AWSParam = &awsParam
	// }

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
	var plan, state AWSKeyTFSDK
	var payload AWSKeyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.EnableKey.ValueBool() != types.BoolNull().ValueBool() {
		EnableDisableKey(r, ctx, &plan, &state, &resp.Diagnostics)
	}

	// if plan.UpdateOpType.ValueString() != "" && plan.UpdateOpType.ValueString() != types.StringNull().ValueString() {
	// 	if plan.UpdateOpType.ValueString() == "enable-rotation-job" {

	// 	} else if plan.UpdateOpType.ValueString() == "disable-rotation-job" {

	// 	} else if plan.UpdateOpType.ValueString() == "import-material" {

	// 	} else if plan.UpdateOpType.ValueString() == "delete-material" {

	// 	} else if plan.UpdateOpType.ValueString() == "rotate" {

	// 	} else if plan.UpdateOpType.ValueString() == "rotate-material" {

	// 	} else if plan.UpdateOpType.ValueString() == "schedule-deletion" {

	// 	} else if plan.UpdateOpType.ValueString() == "policy" {

	// 	} else if plan.UpdateOpType.ValueString() == "update-description" {

	// 	} else if plan.UpdateOpType.ValueString() == "enable" {

	// 	} else if plan.UpdateOpType.ValueString() == "diable" {

	// 	} else if plan.UpdateOpType.ValueString() == "add-tags" {

	// 	} else if plan.UpdateOpType.ValueString() == "remove-tags" {

	// 	} else if plan.UpdateOpType.ValueString() == "add-alias" {

	// 	} else if plan.UpdateOpType.ValueString() == "delete-alias" {

	// 	} else if plan.UpdateOpType.ValueString() == "cancel-deletion" {

	// 	} else if plan.UpdateOpType.ValueString() == "enable-auto-rotation" {

	// 	} else if plan.UpdateOpType.ValueString() == "disable-auto-rotation" {

	// 	} else {

	// 	}
	// }

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

func EnableKeyRotation(r *resourceAWSKey, ctx context.Context, plan *AWSKeyTFSDK, state *AWSKeyTFSDK, diag *diag.Diagnostics) {
}

func EnableDisableKey(r *resourceAWSKey, ctx context.Context, plan *AWSKeyTFSDK, state *AWSKeyTFSDK, diag *diag.Diagnostics) {
	if plan.EnableKey.ValueBool() == true {
		var payload []byte
		_, err := r.client.UpdateDataFullURL(
			ctx,
			plan.ID.ValueString(),
			common.URL_AWS_KEY+"/"+plan.ID.ValueString()+"/enable",
			payload,
			"id")
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_key.go -> block]["+plan.ID.ValueString()+"]")
			diag.AddError(
				"Error enabling AWS Key: ",
				"Could not enable AWS Key, unexpected error: "+err.Error(),
			)
			return
		}
	} else if plan.EnableKey.ValueBool() == false {
		var payload []byte
		_, err := r.client.UpdateDataFullURL(
			ctx,
			plan.ID.ValueString(),
			common.URL_AWS_KEY+"/"+plan.ID.ValueString()+"/disable",
			payload,
			"id")
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_key.go -> block]["+plan.ID.ValueString()+"]")
			diag.AddError(
				"Error disabling AWS Key: ",
				"Could not disable AWS Key, unexpected error: "+err.Error(),
			)
			return
		}
	} else {
		diag.AddError(
			"Invalid Value",
			"enable_key shall be true or false at this point",
		)
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
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_KEY_MANAGEMENT, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
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
