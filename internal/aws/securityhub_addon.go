package awscheck

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

type addonCapabilityStatus struct {
	name    string
	enabled bool
}

func formatAddonCapabilityDetails(statuses []addonCapabilityStatus) string {
	enabledCount := 0
	parts := make([]string, 0, len(statuses))
	for _, s := range statuses {
		state := "disabled"
		if s.enabled {
			enabledCount++
			state = "enabled"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", s.name, state))
	}

	if enabledCount == len(statuses) {
		return fmt.Sprintf("enabled=%d/%d", enabledCount, len(statuses))
	}
	return fmt.Sprintf("enabled=%d/%d; %s", enabledCount, len(statuses), strings.Join(parts, ","))
}

func summarizeAddonStatus(result *CheckResult, statuses []addonCapabilityStatus) {
	enabledCount := 0
	for _, s := range statuses {
		if s.enabled {
			enabledCount++
		}
	}

	switch {
	case enabledCount == len(statuses):
		result.Status = "pass"
	case enabledCount == 0:
		result.Status = "fail"
	default:
		result.Status = "warn"
	}
	result.Details = formatAddonCapabilityDetails(statuses)
}

func (c *Checker) CheckSecurityHubAddonCapabilitiesGuardDuty(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Security Hub Add-on (GuardDuty)", Region: region}
	shCli := c.factory.SecurityHub(region)

	callCtx, cancel := withAPITimeout(ctx)
	_, advancedErr := shCli.DescribeSecurityHubV2(callCtx, &securityhub.DescribeSecurityHubV2Input{})
	cancel()
	advancedEnabled := advancedErr == nil

	cli := c.factory.GuardDuty(region)

	callCtx, cancel = withAPITimeout(ctx)
	out, err := cli.ListDetectors(callCtx, &guardduty.ListDetectorsInput{})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("list detectors: %w", err)
		return result
	}
	if len(out.DetectorIds) == 0 {
		result.Status = "fail"
		result.Details = "detector not found"
		return result
	}

	callCtx, cancel = withAPITimeout(ctx)
	detector, err := cli.GetDetector(callCtx, &guardduty.GetDetectorInput{DetectorId: aws.String(out.DetectorIds[0])})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("get detector: %w", err)
		return result
	}

	statusByFeature := make(map[string]bool, len(detector.Features))
	statusByAdditional := make(map[string]bool, 3)
	for _, feature := range detector.Features {
		featureName := strings.ToUpper(strings.TrimSpace(string(feature.Name)))
		statusByFeature[featureName] = isGuardDutyEnabledStatus(string(feature.Status))

		if featureName != "RUNTIME_MONITORING" && featureName != "EKS_RUNTIME_MONITORING" {
			continue
		}
		for _, ac := range feature.AdditionalConfiguration {
			acName := strings.ToUpper(strings.TrimSpace(string(ac.Name)))
			statusByAdditional[acName] = isGuardDutyEnabledStatus(string(ac.Status))
		}
	}

	eksRuntime := statusByAdditional["EKS_ADDON_MANAGEMENT"]
	if !eksRuntime {
		if statusByFeature["RUNTIME_MONITORING"] {
			eksRuntime = true
		}
		if statusByFeature["EKS_RUNTIME_MONITORING"] {
			eksRuntime = true
		}
	}

	statuses := []addonCapabilityStatus{
		{name: "BasicThreatDetection", enabled: isGuardDutyEnabledStatus(string(detector.Status))},
		{name: "EC2MalwareScan", enabled: statusByFeature["EBS_MALWARE_PROTECTION"]},
		{name: "EKSProtection", enabled: statusByFeature["EKS_AUDIT_LOGS"]},
		{name: "S3Protection", enabled: statusByFeature["S3_DATA_EVENTS"]},
		{name: "LambdaProtection", enabled: statusByFeature["LAMBDA_NETWORK_LOGS"]},
		{name: "EKSRuntimeAutoManagement", enabled: eksRuntime},
		{name: "ECSFargateRuntimeAutoManagement", enabled: statusByAdditional["ECS_FARGATE_AGENT_MANAGEMENT"]},
		{name: "EC2RuntimeAutoManagement", enabled: statusByAdditional["EC2_AGENT_MANAGEMENT"]},
		{name: "RDSProtection", enabled: statusByFeature["RDS_LOGIN_EVENTS"]},
	}

	summarizeAddonStatus(&result, statuses)
	if !advancedEnabled {
		if result.Status == "pass" {
			result.Status = "warn"
		}
		result.Details = "advanced=disabled; underlying_service: " + result.Details
	}
	return result
}

func inspectorStateEnabled(s *inspector2types.State) bool {
	if s == nil {
		return false
	}
	return strings.ToUpper(strings.TrimSpace(string(s.Status))) == "ENABLED"
}

func (c *Checker) CheckSecurityHubAddonCapabilitiesInspector(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Security Hub Add-on (Inspector)", Region: region}
	shCli := c.factory.SecurityHub(region)

	callCtx, cancel := withAPITimeout(ctx)
	_, advancedErr := shCli.DescribeSecurityHubV2(callCtx, &securityhub.DescribeSecurityHubV2Input{})
	cancel()
	advancedEnabled := advancedErr == nil

	cli := c.factory.Inspector2(region)

	if c.accountID == "" {
		result.Status = "fail"
		result.Details = "account id is unavailable"
		return result
	}

	callCtx, cancel = withAPITimeout(ctx)
	out, err := cli.BatchGetAccountStatus(callCtx, &inspector2.BatchGetAccountStatusInput{AccountIds: []string{c.accountID}})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("batch get account status: %w", err)
		return result
	}

	if len(out.Accounts) == 0 {
		result.Status = "fail"
		result.Details = "inspector status unavailable"
		return result
	}

	account := out.Accounts[0]
	for _, a := range out.Accounts {
		if strings.TrimSpace(aws.ToString(a.AccountId)) == c.accountID {
			account = a
			break
		}
	}

	if account.ResourceState == nil {
		result.Status = "fail"
		result.Details = "inspector resource state unavailable"
		return result
	}

	statuses := []addonCapabilityStatus{
		{name: "EC2Scan", enabled: inspectorStateEnabled(account.ResourceState.Ec2)},
		{name: "ECRScan", enabled: inspectorStateEnabled(account.ResourceState.Ecr)},
		{name: "LambdaScan", enabled: inspectorStateEnabled(account.ResourceState.Lambda)},
		{name: "LambdaCodeScan", enabled: inspectorStateEnabled(account.ResourceState.LambdaCode)},
		{name: "CodeSecurity", enabled: inspectorStateEnabled(account.ResourceState.CodeRepository)},
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].name < statuses[j].name
	})
	summarizeAddonStatus(&result, statuses)
	if !advancedEnabled {
		if result.Status == "pass" {
			result.Status = "warn"
		}
		result.Details = "advanced=disabled; underlying_service: " + result.Details
	}
	return result
}
