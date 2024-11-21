package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	common "github.com/thalescpl-io/terraform-provider-ciphertrust/internal/provider/common"
	"strings"
)

var (
	_ datasource.DataSource              = &dataSourceScpConnection{}
	_ datasource.DataSourceWithConfigure = &dataSourceScpConnection{}
)

func NewDataSourceScpConnection() datasource.DataSource {
	return &dataSourceScpConnection{}
}

type dataSourceScpConnection struct {
	client *common.Client
}

type ScpConnectionDataSourceModel struct {
	Filters types.Map              `tfsdk:"filters"`
	Scp     []CMScpConnectionTFDSK `tfsdk:"scp"`
}

func (d *dataSourceScpConnection) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_scp_connection_list"
}

func (d *dataSourceScpConnection) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"auth_method": schema.StringAttribute{
				Computed:    true,
			},
			"host": schema.StringAttribute{
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Computed:    true,
			},
			"path_to": schema.StringAttribute{
				Computed:    true,
			},
			"username": schema.StringAttribute{
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Computed:    true,
			},
			"labels": schema.MapAttribute{
				Computed:    true,
			},
			"meta": schema.MapAttribute{
				Computed:    true,
			},
			"port": schema.Int64Attribute{
				Computed:    true,
			},
			"products": schema.ListAttribute{
				Computed:    true,
			},
			"protocol": schema.StringAttribute{
				Computed:    true,
			},
		},
	}
}

func (d *dataSourceScpConnection) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_scp_connection.go -> Read]["+id+"]")
	var state ScpConnectionDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_SCP_CONNECTION+"/?"+strings.Join(kvs, "")+"skip=0&limit=10")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_scp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read scp connection from CM",
			err.Error(),
		)
		return
	}

	scpConnections := []CMScpConnectionJSON{}

	err = json.Unmarshal([]byte(jsonStr), &scpConnections)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_scp_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read scp connection from CM",
			err.Error(),
		)
		return
	}

	for _, scp := range scpConnections {
		scpConn := CMScpConnectionListTFDSK{
			ID:          types.StringValue(scp.ID),
			Name:        types.StringValue(scp.Name),
			Products:    types.,
			Meta:        types.Map{},
			Description: types.StringValue(scp.Description),
			Labels:      types.Map{},
			Host:        types.StringValue(scp.Host),
			Port:        types.Int64{},
			Username:    types.StringValue(scp.Username),
			AuthMethod:  types.StringValue(scp.AuthMethod),
			PathTo:      types.StringValue(scp.PathTo),
			Protocol:    types.StringValue(scp.Protocol),
		}

		state.Scp = append(state.Scp, scpConn)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_groups.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceScpConnection) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
