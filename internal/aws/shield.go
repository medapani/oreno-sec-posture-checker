package awscheck

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/shield"
)

func (c *Checker) CheckShield(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "AWS Shield", Region: region}
	cli := c.factory.Shield(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.DescribeSubscription(callCtx, &shield.DescribeSubscriptionInput{})
	cancel()
	if err != nil {
		result.Status = "warn"
		result.Details = "Shield Advanced not enabled"
		result.Err = err
		return result
	}

	result.Status = "pass"
	result.Details = fmt.Sprintf("Shield Advanced enabled since %s", out.Subscription.StartTime.Format("2006-01-02"))
	return result
}
