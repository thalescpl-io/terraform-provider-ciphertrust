package cm

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/tidwall/gjson"
	"regexp"
	"time"
)

var (
	_ resource.Resource              = &resourceScheduler{}
	_ resource.ResourceWithConfigure = &resourceScheduler{}

	runAt = `Described using the cron expression format : "* * * * *" These five values indicate when the job should be executed. They are in order of minute, hour, day of month, month, and day of week. Valid values are 0-59 (minutes), 0-23 (hours), 1-31 (day of month), 1-12 or jan-dec (month), and 0-6 or sun-sat (day of week). Names are case insensitive. For use of special characters, consult the Time Specification description at the top of this page.

For example:

    To run every min: "* * * * *"
    To run on Saturday at 23:45(11:45 PM): "45 23 * * 6"
    To run on Monday at 09:00: "0 9 * * 1"
`
	filterDescription        = `A set of selection criteria to specify what resources to include in the backup. Only applicable to domain-scoped backups. By default, no filters are applied and the backup includes all keys. For example, to back up all keys with a name containing 'enc-key', set the filters to [{"resourceType": "Keys", "resourceQuery":{"name":"*enc-key*"}}].`
	resourceQueryDescription = `A JSON object containing resource attributes and attribute values to be queried. The resources returned in the query are backed up. If empty, all the resources of the specified resourceType will be backed up. For Keys, valid resourceQuery paramater values are the same as the body of the 'vault/query-keys' POST endpoint described on the Keys page. If multiple parameters of 'vault/query-keys' are provided then the result will be AND of all. To back up AES keys with a meta parameter value containing {"info":{"color":"red"}}}, use {"algorithm":"AES", "metaContains": {"info":{"color":"red"}}}. To backup specific keys using names, use {"names":["key1", "key2"]}.

For CTE policies, valid resourceQuery parameter values are the same as query parameters of the list '/v1/transparent-encryption/policies' endpoint described in the CTE > Policies section. For example, to back up LDT policies only, use {"policy_type":"LDT"}. Similarly, to back up policies with learn mode enabled, use {"never_deny": true}. For users, the valid resourceQuery parameter values are the same as query parameters of the list '/v1/usermgmt/users' endpoint as described in the “Users” page. For example, to back up all users with name "frank" and email id "frank@local", use {"name":"frank","email": "frank@local"}.

For Customer fragments, valid resourceQuery parameter values are 'ids' and 'names' of Customer fragments. To backup specific customer fragments using ids, use {"ids":["370c4373-2675-4aa1-8cc7-07a9f95a5861", "4e1b9dec-2e38-40d7-b4d6-244043200546"]}. To backup specific customer fragments using names, use {"names":["customerFragment1", "customerFragment2"]}.

Note: When providing resource_query as a JSON string, ensure proper escaping of special characters like quotes (") and use \n for line breaks if entering the JSON in multiple lines. 
For example: "{\"ids\": ["56fc2127-3a96-428e-b93b-ab169728c23c", "a6c8d8eb-1b69-42f0-97d7-4f0845fbf602"]}"
`
)

const schedulerDateRegEx = `^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$`

func NewResourceScheduler() resource.Resource {
	return &resourceScheduler{}
}

type resourceScheduler struct {
	client *common.Client
}

func (r *resourceScheduler) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scheduler"
}

// Schema defines the schema for the resource.
func (r *resourceScheduler) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the job configuration.",
			},
			"operation": schema.StringAttribute{
				Required:    true,
				Description: "The operation field specifies the type of operation to be performed. Currently, only 'database_backup' is supported. Ensure that the database_backup_params parameter is specified when using this operation.",
			},
			"run_at": schema.StringAttribute{
				Required:    true,
				Description: runAt,
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description for the job configuration.",
			},
			"run_on": schema.StringAttribute{
				Optional:    true,
				Description: "Default is 'any'. For database_backup, the default will be the current node if in a cluster.",
			},
			"disabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "By default, the job configuration starts in an active state. True disables the job configuration.",
			},
			"start_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date the job configuration becomes active. RFC3339 format. For example, 2018-10-02T14:24:37.436073Z",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(schedulerDateRegEx),
						"Must conform to the format: YYYY-MM-DDTHH:MM:SSZ (e.g., 2021-03-07T00:00:00Z).",
					),
				},
			},
			"end_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date the job configuration becomes inactive. RFC3339 format. For example, 2018-10-02T14:24:37.436073Z",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(schedulerDateRegEx),
						"Must conform to the format: YYYY-MM-DDTHH:MM:SSZ (e.g., 2021-03-07T00:00:00Z).",
					),
				},
			},

			"database_backup_params": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Database backup operation specific arguments. Should be JSON-serializable. Required only for \"database_backup\" operations. Not allowed for other operations.",
				Attributes: map[string]schema.Attribute{
					"tied_to_hsm": schema.BoolAttribute{
						Optional:    true,
						Description: "If true, the system backup can only be restored to instances that use the same HSM partition. Valid only with the system scoped backup.",
					},
					"scope": schema.StringAttribute{
						Optional:    true,
						Description: "Scope of the backup to be taken - system (default) or domain.",
					},
					"retention_count": schema.Int64Attribute{
						Optional:    true,
						Description: "Number of backups saved for this job config. Default is an unlimited quantity.",
					},
					"do_scp": schema.BoolAttribute{
						Optional:    true,
						Description: "If true, the system backup will also be transferred to the external server via SCP.",
					},
					"description": schema.StringAttribute{
						Optional:    true,
						Description: "User defined description associated with the backup. This is stored along with the backup, and is returned while retrieving the backup information, or while listing backups. Users may find it useful to store various types of information here: a backup name or description, ID of the HSM the backup is tied to, etc.",
					},
					"connection": schema.StringAttribute{
						Optional:    true,
						Description: "Name or ID of the SCP connection which stores the details for SCP server.",
					},
					"backup_key": schema.StringAttribute{
						Optional:    true,
						Description: "ID of backup key used for encrypting the backup. The default backup key is used if this is not specified.",
					},
					"filters": schema.ListNestedAttribute{
						Optional:    true,
						Description: filterDescription,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"resource_type": schema.StringAttribute{
									Required:    true,
									Description: "Type of resources to be backed up. Valid values are \"Keys\", \"cte_policies\", \"customer_fragments\" and, \"users_groups\".",
								},
								"resource_query": schema.StringAttribute{
									Optional:    true,
									Description: resourceQueryDescription,
								},
							},
						},
					},
				},
			},
			"uri":         schema.StringAttribute{Computed: true},
			"account":     schema.StringAttribute{Computed: true},
			"created_at":  schema.StringAttribute{Computed: true},
			"updated_at":  schema.StringAttribute{Computed: true},
			"application": schema.StringAttribute{Computed: true},
			"dev_account": schema.StringAttribute{Computed: true},
		},
	}
}

func (r *resourceScheduler) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Create]["+id+"]")

	var plan CreateJobConfigParamsTFSDK
	var payload CreateJobConfigParamsJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Operation.ValueString() != "" && plan.Operation.ValueString() != types.StringNull().ValueString() {
		payload.Operation = plan.Operation.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	if plan.RunOn.ValueString() != "" && plan.RunOn.ValueString() != types.StringNull().ValueString() {
		payload.RunOn = plan.RunOn.ValueString()
	}

	if plan.RunAt.ValueString() != "" && plan.RunAt.ValueString() != types.StringNull().ValueString() {
		payload.RunAt = plan.RunAt.ValueString()
	}

	switch plan.Operation.ValueString() {
	case "database_backup":
		dbBackupParams := getDatabaseOperationBackupParams(plan)
		if dbBackupParams != nil {
			payload.DatabaseBackupParams = dbBackupParams
		}
	}

	if plan.StartDate.ValueString() != "" && plan.StartDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.StartDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided start_date is not in RFC3339 format ",
				"Error parsing the start_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.StartDate = parsedTime
	}

	if plan.EndDate.ValueString() != "" && plan.EndDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.EndDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided end_date is not in RFC3339 format ",
				"Error parsing the end_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.EndDate = parsedTime
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Scheduler Job Config creation failure",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_SCHEDULER_JOB_CONFIGS, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Scheduler Job Configs on CipherTrust Manager: ",
			"Could not create scheduler job configs: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.Disabled = types.BoolValue(gjson.Get(response, "disabled").Bool())

	tflog.Debug(ctx, "[resource_scheduler.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceScheduler) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Read]["+id+"]")

	var state CreateJobConfigParamsTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_SCHEDULER_JOB_CONFIGS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Read]["+id+"]")
		resp.Diagnostics.AddError("Read Error", "Error fetching scheduler job configs : "+err.Error())
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Read]["+id+"]")

}

func (r *resourceScheduler) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Update]["+id+"]")

	var plan CreateJobConfigParamsTFSDK
	var payload CreateJobConfigParamsJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if plan.RunOn.ValueString() != "" && plan.RunOn.ValueString() != types.StringNull().ValueString() {
		payload.RunOn = plan.RunOn.ValueString()
	}

	if plan.RunAt.ValueString() != "" && plan.RunAt.ValueString() != types.StringNull().ValueString() {
		payload.RunAt = plan.RunAt.ValueString()
	}

	switch plan.Operation.ValueString() {
	case "database_backup":
		dbBackupParams := getDatabaseOperationBackupParams(plan)
		if dbBackupParams != nil {
			payload.DatabaseBackupParams = dbBackupParams
		}
	}

	if plan.StartDate.ValueString() != "" && plan.StartDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.StartDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided start_date is not in RFC3339 format ",
				"Error parsing the start_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.StartDate = parsedTime
	}

	if plan.EndDate.ValueString() != "" && plan.EndDate.ValueString() != types.StringNull().ValueString() {
		parsedTime, err := time.Parse(time.RFC3339, plan.EndDate.ValueString())
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
			resp.Diagnostics.AddError(
				"Provided end_date is not in RFC3339 format ",
				"Error parsing the end_date in RFC3339 format : "+err.Error(),
			)
			return
		}
		payload.EndDate = parsedTime
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Scheduler Job Config update failure",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_SCHEDULER_JOB_CONFIGS, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_scheduler.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating Scheduler Job Configs on CipherTrust Manager: ",
			"Could not udpate scheduler job configs: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.Disabled = types.BoolValue(gjson.Get(response, "disabled").Bool())

	tflog.Debug(ctx, "[resource_scheduler.go -> Update Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Update]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceScheduler) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CreateJobConfigParamsTFSDK
	diags := req.State.Get(ctx, &state)
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_scheduler.go -> Delete]["+state.ID.ValueString()+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_SCHEDULER_JOB_CONFIGS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Scheduler Job configs",
			"Could not delete scheduler job configs, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_scheduler.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")

}

func (d *resourceScheduler) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func getDatabaseOperationBackupParams(plan CreateJobConfigParamsTFSDK) *DatabaseBackupParamsJSON {

	if plan.DatabaseBackupParams != nil {
		var databaseBackupParams DatabaseBackupParamsJSON

		if plan.DatabaseBackupParams.Description.ValueString() != "" && plan.DatabaseBackupParams.Description.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.Description = plan.DatabaseBackupParams.Description.ValueString()
		}

		if plan.DatabaseBackupParams.BackupKey.ValueString() != "" && plan.DatabaseBackupParams.BackupKey.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.BackupKey = plan.DatabaseBackupParams.BackupKey.ValueString()
		}
		if plan.DatabaseBackupParams.Connection.ValueString() != "" && plan.DatabaseBackupParams.Connection.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.Connection = plan.DatabaseBackupParams.Connection.ValueString()
		}
		if plan.DatabaseBackupParams.DoSCP.ValueBool() {
			databaseBackupParams.DoSCP = plan.DatabaseBackupParams.DoSCP.ValueBool()
		}
		if plan.DatabaseBackupParams.Scope.ValueString() != "" && plan.DatabaseBackupParams.Scope.ValueString() != types.StringNull().ValueString() {
			databaseBackupParams.Scope = plan.DatabaseBackupParams.Scope.ValueString()
		}
		if plan.DatabaseBackupParams.TiedToHSM.ValueBool() {
			databaseBackupParams.TiedToHSM = plan.DatabaseBackupParams.TiedToHSM.ValueBool()
		}
		if plan.DatabaseBackupParams.RetentionCount.ValueInt64() != types.Int64Null().ValueInt64() {
			databaseBackupParams.RetentionCount = plan.DatabaseBackupParams.RetentionCount.ValueInt64()
		}

		if len(plan.DatabaseBackupParams.Filters) != 0 {
			var filters []BackupFilterJSON
			for _, filter := range plan.DatabaseBackupParams.Filters {
				if !filter.ResourceType.IsNull() {
					newFilter := BackupFilterJSON{
						ResourceType: filter.ResourceType.ValueString(),
					}
					if !filter.ResourceQuery.IsNull() {
						// Parse the JSON string into a map
						var resourceQuery map[string]interface{}
						err := json.Unmarshal([]byte(filter.ResourceQuery.ValueString()), &resourceQuery)
						if err != nil {
							tflog.Error(context.Background(), "Invalid resource_query JSON: "+err.Error())
						}
						newFilter.ResourceQuery = resourceQuery
					}
					filters = append(filters, newFilter)
				}
			}
			databaseBackupParams.Filters = &filters
		}
		return &databaseBackupParams
	}
	return nil
}
