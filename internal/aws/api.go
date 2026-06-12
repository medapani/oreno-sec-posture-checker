package awscheck

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/detective"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/fms"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/shield"
	"github.com/aws/aws-sdk-go-v2/service/support"
)

type ClientFactory struct {
	base aws.Config
}

func NewClientFactory(cfg aws.Config) *ClientFactory {
	return &ClientFactory{base: cfg}
}

func (f *ClientFactory) cfgForRegion(region string) aws.Config {
	cfg := f.base
	if region != "" {
		cfg.Region = region
	}
	return cfg
}

func (f *ClientFactory) EC2(region string) *ec2.Client {
	return ec2.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) SecurityHub(region string) *securityhub.Client {
	return securityhub.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) GuardDuty(region string) *guardduty.Client {
	return guardduty.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) AccessAnalyzer(region string) *accessanalyzer.Client {
	return accessanalyzer.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) ConfigService(region string) *configservice.Client {
	return configservice.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) Detective(region string) *detective.Client {
	return detective.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) CloudTrail(region string) *cloudtrail.Client {
	return cloudtrail.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) Inspector2(region string) *inspector2.Client {
	return inspector2.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) Macie2(region string) *macie2.Client {
	return macie2.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) Backup(region string) *backup.Client {
	return backup.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) Shield(region string) *shield.Client {
	return shield.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) FirewallManager(region string) *fms.Client {
	return fms.NewFromConfig(f.cfgForRegion(region))
}

func (f *ClientFactory) Support(region string) *support.Client {
	return support.NewFromConfig(f.cfgForRegion(region))
}
