package common

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

func ParseMap(response string, diagnostics *diag.Diagnostics, paramName string) types.Map {
	// Parse the "config" field from the JSON response
	configJSON := gjson.Get(response, paramName).Raw

	if configJSON == "" {
		tflog.Debug(context.Background(), fmt.Sprintf("The '%s' field in the response is empty or missing.", paramName))
		return types.MapNull(types.StringType)
	}

	// Initialize a map to hold the parsed config
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
		diagnostics.AddError(
			"Error parsing config",
			"Unable to parse 'config' field: "+err.Error(),
		)
		return types.MapNull(types.StringType)
	}

	// Convert map[string]interface{} to Terraform types.Map
	convertedMap := make(map[string]attr.Value)
	for key, value := range configMap {
		// Convert each value to a Terraform String or dynamic value based on its type
		convertedMap[key] = types.StringValue(fmt.Sprintf("%v", value))
	}

	return types.MapValueMust(types.StringType, convertedMap)
}

//
//func ParseProducts(response string, diagnostics *diag.Diagnostics, paramName string) []types.String {
//	configJSON := gjson.Get(response, paramName).Raw
//
//	if configJSON == "" {
//		tflog.Debug(context.Background(), fmt.Sprintf("The '%s' field in the response is empty or missing.", paramName))
//		return []types.String{types.StringNull()}
//	}
//
//	var products []string
//	return []types.String{}
//}