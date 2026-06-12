package awscheck

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

func (c *Checker) CheckSecurityHubCSPM(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Security Hub CSPM", Region: region}
	cli := c.factory.SecurityHub(region)

	callCtx, cancel := withAPITimeout(ctx)
	_, err := cli.DescribeHub(callCtx, &securityhub.DescribeHubInput{})
	cancel()
	if err != nil {
		result.Status = "fail"
		result.Details = "hub is not enabled"
		result.Err = err
		return result
	}

	callCtx, cancel = withAPITimeout(ctx)
	standards, err := cli.GetEnabledStandards(callCtx, &securityhub.GetEnabledStandardsInput{})
	cancel()
	if err != nil {
		result.Status = "pass"
		result.Details = "hub enabled (failed to evaluate standards)"
		result.Err = err
		return result
	}

	result.Status = "pass"
	result.Details = fmt.Sprintf("hub enabled, standards=%d", len(standards.StandardsSubscriptions))
	return result
}

func (c *Checker) CheckSecurityHubAdvanced(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Security Hub Advanced", Region: region}
	cli := c.factory.SecurityHub(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.DescribeSecurityHubV2(callCtx, &securityhub.DescribeSecurityHubV2Input{})
	cancel()
	if err != nil {
		result.Status = "warn"
		result.Details = "advanced is not enabled"
		result.Err = err
		return result
	}

	result.Status = "pass"
	hubArn := aws.ToString(out.HubV2Arn)
	if hubArn == "" {
		hubArn = "unknown"
	}
	result.Details = fmt.Sprintf("advanced enabled, hub=%s", hubArn)
	return result
}
