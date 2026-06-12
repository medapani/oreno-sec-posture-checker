package awscheck

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/macie2"
)

func (c *Checker) CheckMacie(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Macie", Region: region}
	cli := c.factory.Macie2(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.GetMacieSession(callCtx, &macie2.GetMacieSessionInput{})
	cancel()
	if err != nil {
		result.Status = "fail"
		result.Details = "macie is not enabled"
		result.Err = err
		return result
	}

	if out.Status == "ENABLED" {
		result.Status = "pass"
		result.Details = "enabled"
		return result
	}

	result.Status = "fail"
	result.Details = fmt.Sprintf("status=%s", out.Status)
	return result
}
