package awscheck

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/support"
	supporttypes "github.com/aws/aws-sdk-go-v2/service/support/types"
	"github.com/aws/smithy-go"
)

func (c *Checker) CheckTrustedAdvisor(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Trusted Advisor", Region: region}

	// Support API endpoint is us-east-1 only.
	cli := c.factory.Support("us-east-1")

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.DescribeTrustedAdvisorChecks(callCtx, &support.DescribeTrustedAdvisorChecksInput{
		Language: aws.String("en"),
	})
	cancel()
	if err != nil {
		if isTrustedAdvisorSupportPlanError(err) {
			result.Status = "warn"
			result.Details = "Trusted Advisor full checks require Business, Enterprise On-Ramp, or Enterprise Support plan"
			return result
		}
		result.Status = "error"
		result.Err = fmt.Errorf("describe trusted advisor checks: %w", err)
		return result
	}

	if len(out.Checks) == 0 {
		result.Status = "fail"
		result.Details = "Trusted Advisor is disabled or no checks are available"
		return result
	}

	check := selectPaidTrustedAdvisorCheck(out.Checks)
	if check == nil || check.Id == nil {
		result.Status = "error"
		result.Err = fmt.Errorf("verify trusted advisor support plan: no paid check found")
		return result
	}

	callCtx, cancel = withAPITimeout(ctx)
	_, err = cli.DescribeTrustedAdvisorCheckResult(callCtx, &support.DescribeTrustedAdvisorCheckResultInput{
		CheckId:  check.Id,
		Language: aws.String("en"),
	})
	cancel()
	if err != nil {
		if isTrustedAdvisorSupportPlanError(err) {
			result.Status = "warn"
			result.Details = "Trusted Advisor full checks require Business, Enterprise On-Ramp, or Enterprise Support plan"
			return result
		}
		result.Status = "error"
		result.Err = fmt.Errorf("describe trusted advisor check result: %w", err)
		return result
	}

	result.Status = "pass"
	result.Details = fmt.Sprintf("Trusted Advisor enabled, available_checks=%d", len(out.Checks))
	return result
}

var trustedAdvisorCoreChecks = map[string]struct{}{
	"Service Limits":        {},
	"IAM Use":               {},
	"MFA on Root Account":   {},
	"EBS Public Snapshots":  {},
	"RDS Public Snapshots":  {},
	"S3 Bucket Permissions": {},
}

func selectPaidTrustedAdvisorCheck(checks []supporttypes.TrustedAdvisorCheckDescription) *supporttypes.TrustedAdvisorCheckDescription {
	for i := range checks {
		name := aws.ToString(checks[i].Name)
		if _, isCore := trustedAdvisorCoreChecks[name]; isCore {
			continue
		}
		category := aws.ToString(checks[i].Category)
		if category == "cost_optimizing" || category == "performance" {
			return &checks[i]
		}
	}

	for i := range checks {
		name := aws.ToString(checks[i].Name)
		if _, isCore := trustedAdvisorCoreChecks[name]; !isCore {
			return &checks[i]
		}
	}

	return nil
}

func isTrustedAdvisorSupportPlanError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if code := apiErr.ErrorCode(); code == "SubscriptionRequiredException" || code == "AccessDeniedException" {
			return true
		}
	}

	msg := err.Error()
	return strings.Contains(msg, "SubscriptionRequiredException") ||
		strings.Contains(msg, "AccessDeniedException") ||
		strings.Contains(msg, "must be subscribed")
}
