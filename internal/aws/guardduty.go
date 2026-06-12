package awscheck

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func (c *Checker) CheckGuardDutyFindingsExport(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "GuardDuty Findings Export", Region: region, CWL: "-"}
	cli := c.factory.GuardDuty(region)

	callCtx, cancel := withAPITimeout(ctx)
	detectors, err := cli.ListDetectors(callCtx, &guardduty.ListDetectorsInput{})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("list detectors: %w", err)
		return result
	}
	if len(detectors.DetectorIds) == 0 {
		result.Status = "fail"
		result.Details = "detector not found"
		return result
	}

	detectorID := detectors.DetectorIds[0]
	nextToken := (*string)(nil)
	s3Buckets := make([]string, 0)
	publishingCount := 0

	for {
		callCtx, cancel = withAPITimeout(ctx)
		out, err := cli.ListPublishingDestinations(callCtx, &guardduty.ListPublishingDestinationsInput{
			DetectorId: aws.String(detectorID),
			NextToken:  nextToken,
		})
		cancel()
		if err != nil {
			result.Status = "error"
			result.Err = fmt.Errorf("list publishing destinations: %w", err)
			return result
		}

		for _, dst := range out.Destinations {
			if strings.ToUpper(string(dst.Status)) != "PUBLISHING" {
				continue
			}
			publishingCount++
			if dst.DestinationId == nil || strings.TrimSpace(aws.ToString(dst.DestinationId)) == "" {
				continue
			}

			callCtx, cancel = withAPITimeout(ctx)
			detail, err := cli.DescribePublishingDestination(callCtx, &guardduty.DescribePublishingDestinationInput{
				DetectorId:    aws.String(detectorID),
				DestinationId: dst.DestinationId,
			})
			cancel()
			if err != nil {
				result.Status = "error"
				result.Err = fmt.Errorf("describe publishing destination %s: %w", aws.ToString(dst.DestinationId), err)
				return result
			}
			if detail.DestinationProperties == nil {
				continue
			}

			arn := strings.TrimSpace(aws.ToString(detail.DestinationProperties.DestinationArn))
			if arn == "" {
				continue
			}
			s3Buckets = append(s3Buckets, extractS3BucketNameFromARNOrURI(arn))
		}

		if out.NextToken == nil || strings.TrimSpace(aws.ToString(out.NextToken)) == "" {
			break
		}
		nextToken = out.NextToken
	}

	if len(s3Buckets) > 0 {
		result.S3 = strings.Join(uniqueStrings(s3Buckets), ",")
		result.Status = "pass"
		result.Details = fmt.Sprintf("publishing_destinations=%d", publishingCount)
		return result
	}

	result.Status = "fail"
	if publishingCount == 0 {
		result.Details = "findings export destination not configured"
		return result
	}
	result.Details = "publishing destination exists but S3 destination is not active"
	return result
}

var guardDutyProtectionPlanFeatures = map[string]struct{}{
	"S3_DATA_EVENTS":         {},
	"EKS_AUDIT_LOGS":         {},
	"RDS_LOGIN_EVENTS":       {},
	"LAMBDA_NETWORK_LOGS":    {},
	"EKS_RUNTIME_MONITORING": {},
	"RUNTIME_MONITORING":     {},
}

var runtimeMonitoringAdditionalFeatures = []string{
	"EKS_ADDON_MANAGEMENT",
	"ECS_FARGATE_AGENT_MANAGEMENT",
	"EC2_AGENT_MANAGEMENT",
}

func (c *Checker) CheckGuardDuty(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "GuardDuty", Region: region}
	cli := c.factory.GuardDuty(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.ListDetectors(callCtx, &guardduty.ListDetectorsInput{})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("list detectors: %w", err)
		return result
	}
	if len(out.DetectorIds) == 0 {
		result.Status = "fail"
		result.Details = "detector not found"
		return result
	}

	detectorID := out.DetectorIds[0]
	callCtx, cancel = withAPITimeout(ctx)
	detector, err := cli.GetDetector(callCtx, &guardduty.GetDetectorInput{DetectorId: aws.String(detectorID)})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("get detector: %w", err)
		return result
	}

	if string(detector.Status) == "ENABLED" {
		result.Status = "pass"
		result.Details = fmt.Sprintf("detector=%s enabled", detectorID)
		return result
	}
	result.Status = "fail"
	result.Details = fmt.Sprintf("detector=%s status=%s", detectorID, detector.Status)
	return result
}

func (c *Checker) CheckGuardDutyProtectionPlans(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "GuardDuty Protection Plans", Region: region}
	cli := c.factory.GuardDuty(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.ListDetectors(callCtx, &guardduty.ListDetectorsInput{})
	cancel()
	if err != nil || len(out.DetectorIds) == 0 {
		result.Status = "fail"
		result.Details = "detector not found"
		result.Err = err
		return result
	}

	callCtx, cancel = withAPITimeout(ctx)
	detector, err := cli.GetDetector(callCtx, &guardduty.GetDetectorInput{DetectorId: aws.String(out.DetectorIds[0])})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("get detector: %w", err)
		return result
	}

	providedFeatures := make([]string, 0, len(detector.Features))
	enabledFeatures := make([]string, 0, len(detector.Features))
	providedFeatureSet := make(map[string]struct{}, len(detector.Features)+4)
	enabledFeatureSet := make(map[string]struct{}, len(detector.Features)+4)

	addProvided := func(name string) {
		if _, ok := providedFeatureSet[name]; ok {
			return
		}
		providedFeatureSet[name] = struct{}{}
		providedFeatures = append(providedFeatures, name)
	}
	addEnabled := func(name string) {
		if _, ok := enabledFeatureSet[name]; ok {
			return
		}
		enabledFeatureSet[name] = struct{}{}
		enabledFeatures = append(enabledFeatures, name)
	}
	for _, feature := range detector.Features {
		featureName := strings.ToUpper(strings.TrimSpace(string(feature.Name)))
		if _, ok := guardDutyProtectionPlanFeatures[featureName]; !ok {
			continue
		}

		// Runtime Monitoring has three managed agent configurations and each one
		// should be evaluated independently.
		if featureName == "RUNTIME_MONITORING" {
			statusByAdditional := make(map[string]bool, len(feature.AdditionalConfiguration))
			for _, ac := range feature.AdditionalConfiguration {
				acName := strings.ToUpper(strings.TrimSpace(string(ac.Name)))
				statusByAdditional[acName] = isGuardDutyEnabledStatus(string(ac.Status))
			}

			for _, acName := range runtimeMonitoringAdditionalFeatures {
				syntheticName := featureName + "." + acName
				addProvided(syntheticName)
				if statusByAdditional[acName] {
					addEnabled(syntheticName)
				}
			}
			continue
		}

		if featureName == "EKS_RUNTIME_MONITORING" {
			syntheticName := featureName + ".EKS_ADDON_MANAGEMENT"
			addProvided(syntheticName)
			if len(feature.AdditionalConfiguration) > 0 {
				for _, ac := range feature.AdditionalConfiguration {
					acName := strings.ToUpper(strings.TrimSpace(string(ac.Name)))
					if acName == "EKS_ADDON_MANAGEMENT" && isGuardDutyEnabledStatus(string(ac.Status)) {
						addEnabled(syntheticName)
						break
					}
				}
			} else if isGuardDutyEnabledStatus(string(feature.Status)) {
				// Older API responses can omit additional configuration and only
				// return feature status.
				addEnabled(syntheticName)
			}
			continue
		}

		addProvided(featureName)
		if isGuardDutyEnabledStatus(string(feature.Status)) {
			addEnabled(featureName)
		}
	}

	if len(providedFeatures) == 0 {
		result.Status = "warn"
		result.Details = "no GuardDuty protection plan feature is returned in this region"
		return result
	}

	sort.Strings(providedFeatures)
	if len(enabledFeatures) == len(providedFeatures) {
		result.Status = "pass"
		result.Details = "all protection plan features are enabled"
		return result
	}

	if len(enabledFeatures) == 0 {
		result.Status = "fail"
		result.Details = "all GuardDuty protection plan features are disabled"
		return result
	}

	sort.Strings(enabledFeatures)
	missing := make([]string, 0, len(providedFeatures)-len(enabledFeatures))
	for _, name := range providedFeatures {
		if _, ok := enabledFeatureSet[name]; !ok {
			missing = append(missing, name)
		}
	}

	result.Status = "warn"
	result.Details = fmt.Sprintf("missing=%s", strings.Join(missing, ","))
	return result
}

func (c *Checker) checkGuardDutyFeature(ctx context.Context, region, checkName, featureName, passDetail, warnDetail string) CheckResult {
	result := CheckResult{Name: checkName, Region: region}
	cli := c.factory.GuardDuty(region)

	callCtx, cancel := withAPITimeout(ctx)
	out, err := cli.ListDetectors(callCtx, &guardduty.ListDetectorsInput{})
	cancel()
	if err != nil || len(out.DetectorIds) == 0 {
		result.Status = "fail"
		result.Details = "detector not found"
		result.Err = err
		return result
	}

	callCtx, cancel = withAPITimeout(ctx)
	detector, err := cli.GetDetector(callCtx, &guardduty.GetDetectorInput{DetectorId: aws.String(out.DetectorIds[0])})
	cancel()
	if err != nil {
		result.Status = "error"
		result.Err = fmt.Errorf("get detector: %w", err)
		return result
	}

	for _, feature := range detector.Features {
		if string(feature.Name) == featureName && isGuardDutyEnabledStatus(string(feature.Status)) {
			result.Status = "pass"
			result.Details = passDetail
			return result
		}
	}

	result.Status = "warn"
	result.Details = warnDetail
	return result
}

func (c *Checker) CheckGuardDutyMalwareProtectionEC2(ctx context.Context, region string) CheckResult {
	return c.checkGuardDutyFeature(ctx, region,
		"GuardDuty Malware Protection EC2",
		"EBS_MALWARE_PROTECTION",
		"EBS malware scan is enabled",
		"EBS malware scan is disabled",
	)
}

func (c *Checker) CheckGuardDutyMalwareProtectionS3(ctx context.Context, region string) CheckResult {
	result := CheckResult{Name: "GuardDuty Malware Protection S3", Region: region}
	cli := c.factory.GuardDuty(region)

	nextToken := (*string)(nil)
	activeBuckets := make([]string, 0)
	planCount := 0

	for {
		callCtx, cancel := withAPITimeout(ctx)
		out, err := cli.ListMalwareProtectionPlans(callCtx, &guardduty.ListMalwareProtectionPlansInput{NextToken: nextToken})
		cancel()
		if err != nil {
			result.Status = "error"
			result.Err = fmt.Errorf("list malware protection plans: %w", err)
			return result
		}

		for _, summary := range out.MalwareProtectionPlans {
			if summary.MalwareProtectionPlanId == nil || strings.TrimSpace(*summary.MalwareProtectionPlanId) == "" {
				continue
			}
			planCount++

			callCtx, cancel := withAPITimeout(ctx)
			plan, err := cli.GetMalwareProtectionPlan(callCtx, &guardduty.GetMalwareProtectionPlanInput{
				MalwareProtectionPlanId: summary.MalwareProtectionPlanId,
			})
			cancel()
			if err != nil {
				result.Status = "error"
				result.Err = fmt.Errorf("get malware protection plan %s: %w", aws.ToString(summary.MalwareProtectionPlanId), err)
				return result
			}

			if strings.ToUpper(strings.TrimSpace(string(plan.Status))) != "ACTIVE" {
				continue
			}
			if plan.ProtectedResource == nil || plan.ProtectedResource.S3Bucket == nil {
				continue
			}

			bucketName := strings.TrimSpace(aws.ToString(plan.ProtectedResource.S3Bucket.BucketName))
			if bucketName == "" {
				activeBuckets = append(activeBuckets, aws.ToString(summary.MalwareProtectionPlanId))
				continue
			}
			activeBuckets = append(activeBuckets, bucketName)
		}

		if out.NextToken == nil || strings.TrimSpace(aws.ToString(out.NextToken)) == "" {
			break
		}
		nextToken = out.NextToken
	}

	if len(activeBuckets) > 0 {
		sort.Strings(activeBuckets)
		result.Status = "pass"
		result.Details = fmt.Sprintf("active_buckets=%s", strings.Join(activeBuckets, ","))
		return result
	}

	if planCount > 0 {
		result.Status = "warn"
		result.Details = fmt.Sprintf("no active S3 malware protection plan found (plans=%d)", planCount)
		return result
	}

	result.Status = "warn"
	result.Details = "no S3 malware protection plan found"
	return result
}

func isGuardDutyEnabledStatus(status string) bool {
	s := strings.ToUpper(strings.TrimSpace(status))
	return s == "ENABLED" || strings.HasPrefix(s, "ENABLED_")
}

func extractS3BucketNameFromARNOrURI(destination string) string {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return ""
	}
	if strings.HasPrefix(destination, "arn:aws:s3:::") {
		value := strings.TrimPrefix(destination, "arn:aws:s3:::")
		if cut := strings.Index(value, "/"); cut != -1 {
			return value[:cut]
		}
		return value
	}
	if strings.HasPrefix(destination, "s3://") {
		withoutScheme := strings.TrimPrefix(destination, "s3://")
		parts := strings.SplitN(withoutScheme, "/", 2)
		return parts[0]
	}
	return destination
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}
