package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/thalescpl-io/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/tidwall/gjson"
)

var (
	azureStackConnectionTypeDescription = `Azure stack connection type

	Options:
	
		AAD
		ADFS
`
	cloudNameDescription = `Name of the cloud.

	Options:
	
		AzureCloud
		AzureChinaCloud
		AzureUSGovernment
		AzureStack
`
)

func NewResourceCMAzureConnection() resource.Resource {
	return &resourceCMAzureConnection{}
}

type resourceCMAzureConnection struct {
	client *common.Client
}

func (r *resourceCMAzureConnection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_connection"
}

// Schema defines the schema for the resource.
func (r *resourceCMAzureConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"client_id": schema.StringAttribute{
				Required:    true,
				Description: "Unique Identifier (client ID) for the Azure application.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique connection name.",
			},
			"tenant_id": schema.StringAttribute{
				Required:    true,
				Description: "Tenant ID of the Azure application.",
			},
			"active_directory_endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Azure stack active directory authority URL",
			},
			"azure_stack_connection_type": schema.StringAttribute{
				Optional:    true,
				Description: azureStackConnectionTypeDescription,
			},
			"azure_stack_server_cert": schema.StringAttribute{
				Optional:    true,
				Description: "Azure stack server certificate",
			},
			"cert_duration": schema.Int64Attribute{
				Optional:    true,
				Description: "Duration in days for which the azure certificate is valid, default (730 i.e. 2 Years).",
			},
			"certificate": schema.StringAttribute{
				Optional:    true,
				Description: "User has the option to upload external certificate for Azure Cloud connection. This option cannot be used with option is_certificate_used and client_secret.User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. User can also update the new external certificate in the existing connection in Update (PATCH) API call. Any unused certificate will automatically deleted in 24 hours.",
			},
			"client_secret": schema.StringAttribute{
				Optional:    true,
				Description: "Secret key for the Azure application. Required in Azure Stack connection.",
			},
			"cloud_name": schema.StringAttribute{
				Optional:    true,
				Description: cloudNameDescription,
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description about the connection.",
			},
			"external_certificate_used": schema.BoolAttribute{
				Optional:    true,
				Description: "true if the certificate associated with the connection is generated externally, false otherwise.",
			},
			"is_certificate_used": schema.BoolAttribute{
				Optional:    true,
				Description: "User has the option to choose the Certificate Authentication method instead of Client Secret for Azure Cloud connection. In order to use the Certificate, set it to true. Once the connection is created, in the response user will get a certificate. By default, the certificate is valid for 2 Years. User can update the certificate in the existing connection by setting it to true in Update (PATCH) API call.",
			},
			"key_vault_dns_suffix": schema.StringAttribute{
				Optional:    true,
				Description: "Azure stack key vault dns suffix",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: labelsDescription,
			},
			"management_url": schema.StringAttribute{
				Optional:    true,
				Description: "Azure stack management URL",
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional end-user or service data stored with the connection.",
			},
			"products": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: productsDescription,
			},
			"resource_manager_url": schema.StringAttribute{
				Optional:    true,
				Description: "Azure stack resource manager URL.",
			},
			"vault_resource_url": schema.StringAttribute{
				Optional:    true,
				Description: "Azure stack vault service resource URL.",
			},
			//common response parameters (optional)
			"uri":                   schema.StringAttribute{Computed: true, Optional: true},
			"account":               schema.StringAttribute{Computed: true, Optional: true},
			"created_at":            schema.StringAttribute{Computed: true, Optional: true},
			"updated_at":            schema.StringAttribute{Computed: true, Optional: true},
			"service":               schema.StringAttribute{Computed: true, Optional: true},
			"category":              schema.StringAttribute{Computed: true, Optional: true},
			"resource_url":          schema.StringAttribute{Computed: true, Optional: true},
			"last_connection_ok":    schema.BoolAttribute{Computed: true, Optional: true},
			"last_connection_error": schema.StringAttribute{Computed: true, Optional: true},
			"last_connection_at":    schema.StringAttribute{Computed: true, Optional: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMAzureConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMAzureConnectionTFSDK
	var payload CMAzureConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ClientID.ValueString() != "" && plan.ClientID.ValueString() != types.StringNull().ValueString() {
		payload.ClientID = plan.ClientID.ValueString()
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	if plan.TenantID.ValueString() != "" && plan.TenantID.ValueString() != types.StringNull().ValueString() {
		payload.TenantID = plan.TenantID.ValueString()
	}

	if plan.ActiveDirectoryEndpoint.ValueString() != "" && plan.ActiveDirectoryEndpoint.ValueString() != types.StringNull().ValueString() {
		payload.ActiveDirectoryEndpoint = plan.ActiveDirectoryEndpoint.ValueString()
	}

	if plan.AzureStackConnectionType.ValueString() != "" && plan.AzureStackConnectionType.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackConnectionType = plan.AzureStackConnectionType.ValueString()
	}

	if plan.AzureStackServerCert.ValueString() != "" && plan.AzureStackServerCert.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackServerCert = plan.AzureStackServerCert.ValueString()
	}

	if plan.CertDuration.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}

	if plan.Certificate.ValueString() != "" && plan.Certificate.ValueString() != types.StringNull().ValueString() {
		payload.Certificate = plan.Certificate.ValueString()
	}

	if plan.ClientSecret.ValueString() != "" && plan.ClientSecret.ValueString() != types.StringNull().ValueString() {
		payload.ClientSecret = plan.ClientSecret.ValueString()
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.ExternalCertificateUsed.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExternalCertificateUsed = plan.ExternalCertificateUsed.ValueBool()
	}

	if plan.IsCertificateUsed.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsCertificateUsed = plan.IsCertificateUsed.ValueBool()
	}

	if plan.KeyVaultDNSSuffix.ValueString() != "" && plan.KeyVaultDNSSuffix.ValueString() != types.StringNull().ValueString() {
		payload.KeyVaultDNSSuffix = plan.KeyVaultDNSSuffix.ValueString()
	}

	azureLabelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		azureLabelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = azureLabelsPayload

	if plan.ManagementURL.ValueString() != "" && plan.ManagementURL.ValueString() != types.StringNull().ValueString() {
		payload.ManagementURL = plan.ManagementURL.ValueString()
	}

	azureMetadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		azureMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = azureMetadataPayload

	var azureProducts []string
	for _, product := range plan.Products {
		azureProducts = append(azureProducts, product.ValueString())
	}
	payload.Products = azureProducts

	if plan.ResourceManagerURL.ValueString() != "" && plan.ResourceManagerURL.ValueString() != types.StringNull().ValueString() {
		payload.ResourceManagerURL = plan.ResourceManagerURL.ValueString()
	}

	if plan.VaultResourceURL.ValueString() != "" && plan.VaultResourceURL.ValueString() != types.StringNull().ValueString() {
		payload.VaultResourceURL = plan.VaultResourceURL.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Azure connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AZURE_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Azure Connection on CipherTrust Manager: ",
			"Could not create azure connection, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.Category = types.StringValue(gjson.Get(response, "category").String())
	plan.Service = types.StringValue(gjson.Get(response, "service").String())
	plan.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())
	plan.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	plan.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	plan.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())

	tflog.Debug(ctx, fmt.Sprintf("Response: %s", response))

	tflog.Debug(ctx, "[resource_azure_connection.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMAzureConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMAzureConnectionTFSDK
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AZURE_CONNECTION)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Azure Connection on CipherTrust Manager: ",
			"Could not read azure connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Read]["+id+"]")
	return
}

func (r *resourceCMAzureConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Update]["+id+"]")
	var plan CMAzureConnectionTFSDK
	var payload CMAzureConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ActiveDirectoryEndpoint.ValueString() != "" && plan.ActiveDirectoryEndpoint.ValueString() != types.StringNull().ValueString() {
		payload.ActiveDirectoryEndpoint = plan.ActiveDirectoryEndpoint.ValueString()
	}

	if plan.AzureStackConnectionType.ValueString() != "" && plan.AzureStackConnectionType.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackConnectionType = plan.AzureStackConnectionType.ValueString()
	}

	if plan.AzureStackServerCert.ValueString() != "" && plan.AzureStackServerCert.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackServerCert = plan.AzureStackServerCert.ValueString()
	}

	if plan.CertDuration.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}

	if plan.Certificate.ValueString() != "" && plan.Certificate.ValueString() != types.StringNull().ValueString() {
		payload.Certificate = plan.Certificate.ValueString()
	}

	if plan.ClientID.ValueString() != "" && plan.ClientID.ValueString() != types.StringNull().ValueString() {
		payload.ClientID = plan.ClientID.ValueString()
	}

	if plan.ClientSecret.ValueString() != "" && plan.ClientSecret.ValueString() != types.StringNull().ValueString() {
		payload.ClientSecret = plan.ClientSecret.ValueString()
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.ExternalCertificateUsed.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExternalCertificateUsed = plan.ExternalCertificateUsed.ValueBool()
	}

	if plan.IsCertificateUsed.ValueBool() != types.BoolNull().ValueBool() {
		payload.IsCertificateUsed = plan.IsCertificateUsed.ValueBool()
	}

	if plan.KeyVaultDNSSuffix.ValueString() != "" && plan.KeyVaultDNSSuffix.ValueString() != types.StringNull().ValueString() {
		payload.KeyVaultDNSSuffix = plan.KeyVaultDNSSuffix.ValueString()
	}

	azureLabelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		azureLabelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = azureLabelsPayload

	if plan.ManagementURL.ValueString() != "" && plan.ManagementURL.ValueString() != types.StringNull().ValueString() {
		payload.ManagementURL = plan.ManagementURL.ValueString()
	}

	azureMetadataPayload := make(map[string]interface{})
	for k, v := range plan.Meta.Elements() {
		azureMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.Meta = azureMetadataPayload

	var azureProducts []string
	for _, product := range plan.Products {
		azureProducts = append(azureProducts, product.ValueString())
	}
	payload.Products = azureProducts

	if plan.ResourceManagerURL.ValueString() != "" && plan.ResourceManagerURL.ValueString() != types.StringNull().ValueString() {
		payload.ResourceManagerURL = plan.ResourceManagerURL.ValueString()
	}

	if plan.TenantID.ValueString() != "" && plan.TenantID.ValueString() != types.StringNull().ValueString() {
		payload.TenantID = plan.TenantID.ValueString()
	}
	if plan.VaultResourceURL.ValueString() != "" && plan.VaultResourceURL.ValueString() != types.StringNull().ValueString() {
		payload.VaultResourceURL = plan.VaultResourceURL.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Azure connection update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_AZURE_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating Azure Connection on CipherTrust Manager: ",
			"Could not update azure connection, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.Category = types.StringValue(gjson.Get(response, "category").String())
	plan.Service = types.StringValue(gjson.Get(response, "service").String())
	plan.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())
	plan.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	plan.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	plan.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())

	tflog.Debug(ctx, fmt.Sprintf("Response: %s", response))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCMAzureConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMAzureConnectionTFSDK
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Delete]["+state.ID.ValueString()+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AZURE_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Azure Connection",
			"Could not delete azure connection, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
}

func (d *resourceCMAzureConnection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
