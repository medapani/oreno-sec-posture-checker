package awscheck

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
)

func (c *Checker) CheckInspector(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "Inspector", Region: region}
	cli := c.factory.Inspector2(region)

	if c.accountID == "" {
		result.Status = "fail"
		result.Details = "account id is unavailable"
		return result
	}

	callCtx, cancel := withAPITimeout(ctx)
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

	for _, account := range out.Accounts {
		if account.State != nil {
			result.Details = fmt.Sprintf("state=%s", account.State.Status)
			if string(account.State.Status) == "ENABLED" {
				result.Status = "pass"
				return result
			}
		}
	}

	result.Status = "fail"
	if result.Details == "" {
		result.Details = "inspector is not enabled"
	}
	return result
}
