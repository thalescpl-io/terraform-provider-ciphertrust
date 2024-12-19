package scheduler

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
	"time"
)

type CreateJobConfigParamsJSON struct {
	ID                   string                    `json:"id"`
	URI                  string                    `json:"uri"`
	Account              string                    `json:"account"`
	Application          string                    `json:"application"`
	DevAccount           string                    `json:"devAccount"`
	CreatedAt            string                    `json:"createdAt"`
	UpdatedAt            string                    `json:"updatedAt"`
	Name                 string                    `json:"name"`
	Description          string                    `json:"description"`
	Operation            string                    `json:"operation"`
	RunAt                string                    `json:"run_at"`
	RunOn                string                    `json:"run_on"`
	Disabled             bool                      `json:"disabled"`
	StartDate            time.Time                 `json:"start_date"`
	EndDate              time.Time                 `json:"end_date"`
	DatabaseBackupParams *DatabaseBackupParamsJSON `json:"database_backup_params"`
}
type DatabaseBackupParamsJSON struct {
	TiedToHSM      bool                `json:"tiedToHSM,"`
	Description    string              `json:"description,"`
	BackupKey      string              `json:"backupKey,"`
	Scope          string              `json:"scope,"`
	Filters        *[]BackupFilterJSON `json:"filters,"`
	RetentionCount int64               `json:"retentionCount,"`
	DoSCP          bool                `json:"do_scp,"`
	Connection     string              `json:"connection,"`
}
type BackupFilterJSON struct {
	ResourceType  string      `json:"resourceType"`
	ResourceQuery interface{} `json:"resourceQuery"`
}

type CreateJobConfigParamsTFSDK struct {
	ID                   types.String              `tfsdk:"id"`
	URI                  types.String              `tfsdk:"uri"`
	Account              types.String              `tfsdk:"account"`
	Application          types.String              `tfsdk:"application"`
	DevAccount           types.String              `tfsdk:"dev_account"`
	CreatedAt            types.String              `tfsdk:"created_at"`
	UpdatedAt            types.String              `tfsdk:"updated_at"`
	Name                 types.String              `tfsdk:"name"`
	Description          types.String              `tfsdk:"description"`
	Operation            types.String              `tfsdk:"operation"`
	RunAt                types.String              `tfsdk:"run_at"`
	RunOn                types.String              `tfsdk:"run_on"`
	Disabled             types.Bool                `tfsdk:"disabled"`
	StartDate            types.String              `tfsdk:"start_date"`
	EndDate              types.String              `tfsdk:"end_date"`
	DatabaseBackupParams DatabaseBackupParamsTFSDK `tfsdk:"database_backup_params"`
}

type DatabaseBackupParamsTFSDK struct {
	TiedToHSM      types.Bool          `tfsdk:"tied_to_hsm"`
	Description    types.String        `tfsdk:"description"`
	BackupKey      types.String        `tfsdk:"backup_key"`
	Scope          types.String        `tfsdk:"scope"`
	Filters        []BackupFilterTFSDK `tfsdk:"filters"`
	RetentionCount types.Int64         `tfsdk:"retention_count"`
	DoSCP          types.Bool          `tfsdk:"do_scp"`
	Connection     types.String        `tfsdk:"connection"`
}

type BackupFilterTFSDK struct {
	ResourceType  types.String `tfsdk:"resource_type"`
	ResourceQuery types.String `tfsdk:"resource_query"`
}

type CreateJobConfigParamsListJSON struct {
	ID                   string                    `json:"id"`
	URI                  string                    `json:"uri"`
	Account              string                    `json:"account"`
	Application          string                    `json:"application"`
	DevAccount           string                    `json:"devAccount"`
	CreatedAt            string                    `json:"createdAt"`
	UpdatedAt            string                    `json:"updatedAt"`
	Name                 string                    `json:"name"`
	Description          string                    `json:"description"`
	Operation            string                    `json:"operation"`
	RunAt                string                    `json:"run_at"`
	RunOn                string                    `json:"run_on"`
	Disabled             bool                      `json:"disabled"`
	StartDate            time.Time                 `json:"start_date"`
	EndDate              time.Time                 `json:"end_date"`
	DatabaseBackupParams *DatabaseBackupParamsJSON `json:"job_config_params"`
}
