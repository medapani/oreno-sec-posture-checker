package awscheck

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

func (c *Checker) CheckAWSConfig(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "AWS Config", Region: region, CWL: "-"}
	cli := c.factory.ConfigService(region)

	callCtx, cancel := withAPITimeout(ctx)
	recorders, err := cli.DescribeConfigurationRecorders(callCtx, &configservice.DescribeConfigurationRecordersInput{})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("describe recorders: %w", err)
		return result
	}
	if len(recorders.ConfigurationRecorders) == 0 {
		result.Status = "fail"
		result.Details = "recorder not configured"
		return result
	}

	callCtx, cancel = withAPITimeout(ctx)
	status, err := cli.DescribeConfigurationRecorderStatus(callCtx, &configservice.DescribeConfigurationRecorderStatusInput{})
	cancel()
	if err != nil {
		result.Status = "fail"
		result.Details = "recorder configured but status check failed"
		result.Err = err
		return result
	}

	recording := 0
	for _, s := range status.ConfigurationRecordersStatus {
		if s.Recording {
			recording++
		}
	}
	if recording > 0 {
		callCtx, cancel = withAPITimeout(ctx)
		delivery, err := cli.DescribeDeliveryChannels(callCtx, &configservice.DescribeDeliveryChannelsInput{})
		cancel()
		if err != nil {
			result.Status = "fail"
			result.Details = "recorder is recording but delivery channel check failed"
			result.Err = err
			return result
		}

		buckets := make([]string, 0, len(delivery.DeliveryChannels))
		for _, ch := range delivery.DeliveryChannels {
			name := strings.TrimSpace(aws.ToString(ch.S3BucketName))
			if name == "" {
				continue
			}
			buckets = append(buckets, name)
		}

		if len(buckets) > 0 {
			result.S3 = strings.Join(buckets, ",")
			result.Status = "pass"
			result.Details = fmt.Sprintf("recorders=%d recording=%d", len(recorders.ConfigurationRecorders), recording)
			return result
		}

		result.Status = "fail"
		result.Details = "recorder is recording but no S3 delivery bucket configured"
		return result
	}

	result.Status = "fail"
	result.Details = "recorder exists but not recording"
	return result
}
