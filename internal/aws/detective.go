package awscheck

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/detective"
)

func (c *Checker) CheckDetective(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Detective", Region: region}
	cli := c.factory.Detective(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.ListGraphs(callCtx, &detective.ListGraphsInput{})
	cancel()
	if err != nil {
		result.Status = "fail"
		result.Details = "detective graph not found"
		result.Err = err
		return result
	}
	if len(out.GraphList) == 0 {
		result.Status = "fail"
		result.Details = "detective graph not found"
		return result
	}

	result.Status = "pass"
	result.Details = fmt.Sprintf("graphs=%d", len(out.GraphList))
	return result
}
