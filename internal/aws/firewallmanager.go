package awscheck

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/fms"
)

func (c *Checker) CheckFirewallManager(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "AWS Firewall Manager", Region: region}
	cli := c.factory.FirewallManager(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.GetAdminAccount(callCtx, &fms.GetAdminAccountInput{})
	cancel()
	if err != nil {
		result.Status = "warn"
		result.Details = "Firewall Manager not configured"
		result.Err = err
		return result
	}
	if out.AdminAccount == nil || *out.AdminAccount == "" {
		result.Status = "warn"
		result.Details = "Firewall Manager admin account not set"
		return result
	}

	result.Status = "pass"
	result.Details = "Firewall Manager admin account configured"
	return result
}
