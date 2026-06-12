package awscheck

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func LoadConfig(ctx context.Context, profile string) (aws.Config, error) {
	opts := make([]func(*config.LoadOptions) error, 0, 1)
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	callCtx, cancel := withAPITimeout(ctx)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(callCtx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load aws config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return cfg, nil
}

func DiscoverRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	cli := ec2.NewFromConfig(cfg)
	callCtx, cancel := withAPITimeout(ctx)
	defer cancel()
	out, err := cli.DescribeRegions(callCtx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, fmt.Errorf("describe regions: %w", err)
	}

	regions := make([]string, 0, len(out.Regions))
	for _, region := range out.Regions {
		if region.RegionName != nil && *region.RegionName != "" {
			regions = append(regions, *region.RegionName)
		}
	}
	sort.Strings(regions)
	return regions, nil
}

func GetAccountID(ctx context.Context, cfg aws.Config) (string, error) {
	cli := sts.NewFromConfig(cfg)
	callCtx, cancel := withAPITimeout(ctx)
	defer cancel()
	out, err := cli.GetCallerIdentity(callCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("get caller identity: %w", err)
	}
	if out.Account == nil || *out.Account == "" {
		return "", fmt.Errorf("account id is empty")
	}
	return *out.Account, nil
}
