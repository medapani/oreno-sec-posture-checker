package awscheck

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
)

func (c *Checker) CheckAccessAnalyzer(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "IAM Access Analyzer", Region: region}
	cli := c.factory.AccessAnalyzer(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.ListAnalyzers(callCtx, &accessanalyzer.ListAnalyzersInput{})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("list analyzers: %w", err)
		return result
	}

	active := 0
	for _, analyzer := range out.Analyzers {
		if string(analyzer.Status) == "ACTIVE" {
			active++
		}
	}
	if active > 0 {
		result.Status = "pass"
		result.Details = fmt.Sprintf("active_analyzers=%d", active)
		return result
	}

	result.Status = "fail"
	result.Details = "no active analyzer"
	return result
}
