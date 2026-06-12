package awscheck

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

func (c *Checker) CheckCloudTrail(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "CloudTrail", Region: region}
	cli := c.factory.CloudTrail(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.DescribeTrails(callCtx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("describe trails: %w", err)
		return result
	}
	if len(out.TrailList) == 0 {
		result.Status = "fail"
		result.Details = "trail not configured"
		return result
	}

	logging := 0
	s3Buckets := make([]string, 0, len(out.TrailList))
	logGroups := make([]string, 0, len(out.TrailList))
	for _, trail := range out.TrailList {
		if trail.Name == nil || *trail.Name == "" {
			continue
		}
		callCtx, cancel := withAPITimeout(ctx)
		status, err := cli.GetTrailStatus(callCtx, &cloudtrail.GetTrailStatusInput{Name: trail.Name})
		cancel()
		if err == nil && status.IsLogging != nil && *status.IsLogging {
			logging++

			s3 := strings.TrimSpace(aws.ToString(trail.S3BucketName))
			if s3 != "" {
				s3Buckets = append(s3Buckets, s3)
			}

			lg := extractCloudWatchLogGroupName(strings.TrimSpace(aws.ToString(trail.CloudWatchLogsLogGroupArn)))
			if lg != "" {
				logGroups = append(logGroups, lg)
			}
		}
	}

	if len(s3Buckets) > 0 {
		result.S3 = strings.Join(uniqueStrings(s3Buckets), ",")
	}
	if len(logGroups) > 0 {
		result.CWL = strings.Join(uniqueStrings(logGroups), ",")
	}

	if result.S3 != "" || result.CWL != "" {
		result.Status = "pass"
		result.Details = fmt.Sprintf("trails=%d logging=%d", len(out.TrailList), logging)
		return result
	}

	result.Status = "fail"
	result.Details = fmt.Sprintf("trails=%d but no logging trail detected", len(out.TrailList))
	return result
}

func extractCloudWatchLogGroupName(logGroupARN string) string {
	if logGroupARN == "" {
		return ""
	}
	idx := strings.Index(logGroupARN, ":log-group:")
	if idx == -1 {
		return ""
	}
	name := logGroupARN[idx+len(":log-group:"):]
	if cut := strings.Index(name, ":"); cut != -1 {
		name = name[:cut]
	}
	return strings.TrimSpace(name)
}
