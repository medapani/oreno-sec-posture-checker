package awscheck

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func (c *Checker) CheckBackup(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "AWS Backup", Region: region}
	cli := c.factory.Backup(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.ListBackupVaults(callCtx, &backup.ListBackupVaultsInput{MaxResults: aws.Int32(1)})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("list backup vaults: %w", err)
		return result
	}
	if len(out.BackupVaultList) > 0 {
		result.Status = "pass"
		result.Details = "backup vault exists"
		return result
	}

	result.Status = "warn"
	result.Details = "no backup vault"
	return result
}
