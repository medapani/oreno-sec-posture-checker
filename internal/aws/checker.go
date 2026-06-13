package awscheck

import (
	"context"
	"sync"
	"sync/atomic"
)

const defaultParallelism = 5

type Checker struct {
	factory   *ClientFactory
	accountID string
}

func NewChecker(factory *ClientFactory, accountID string) *Checker {
	return &Checker{factory: factory, accountID: accountID}
}

func (c *Checker) Run(ctx context.Context, regions []string) []CheckResult {
	return c.RunWithProgress(ctx, regions, nil)
}

func (c *Checker) RunWithProgress(ctx context.Context, regions []string, onProgress func(done, total int, result CheckResult)) []CheckResult {
	tasks := c.buildTasks(ctx, regions)
	return c.runTasks(ctx, tasks, onProgress)
}

func (c *Checker) RunLogsWithProgress(ctx context.Context, regions []string, onProgress func(done, total int, result CheckResult)) []CheckResult {
	tasks := c.buildLogTasks(ctx, regions)
	return c.runTasks(ctx, tasks, onProgress)
}

func (c *Checker) runTasks(ctx context.Context, tasks []checkTask, onProgress func(done, total int, result CheckResult)) []CheckResult {
	total := len(tasks)
	results := make([]CheckResult, total)

	if total == 0 {
		return results
	}

	parallelism := defaultParallelism
	if parallelism > total {
		parallelism = total
	}

	var done int32
	var cbMu sync.Mutex
	jobs := make(chan int)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			results[idx] = tasks[idx].run()
			if onProgress != nil {
				current := int(atomic.AddInt32(&done, 1))
				cbMu.Lock()
				onProgress(current, total, results[idx])
				cbMu.Unlock()
			}
		}
	}

	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go worker()
	}

enqueueLoop:
	for i := range tasks {
		select {
		case <-ctx.Done():
			break enqueueLoop
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	return results
}

type checkTask struct {
	run func() CheckResult
}

func (c *Checker) buildTasks(ctx context.Context, regions []string) []checkTask {
	tasks := make([]checkTask, 0, len(regions)*16+3)

	for _, region := range regions {
		r := region
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckSecurityHubCSPM(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckSecurityHubAdvanced(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckSecurityHubAddonCapabilitiesGuardDuty(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckSecurityHubAddonCapabilitiesInspector(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckGuardDuty(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckGuardDutyFindingsExport(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckGuardDutyProtectionPlans(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckGuardDutyMalwareProtectionEC2(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckGuardDutyMalwareProtectionS3(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckAccessAnalyzer(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckAWSConfig(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckCloudTrail(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckInspector(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckDetective(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckMacie(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckBackup(ctx, r) }})
	}

	// Shield/FMS are effectively global from a posture perspective.
	homeRegion := ""
	if len(regions) > 0 {
		homeRegion = regions[0]
	}
	tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckShield(ctx, homeRegion) }})
	tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckFirewallManager(ctx, homeRegion) }})
	tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckTrustedAdvisor(ctx, homeRegion) }})

	return tasks
}

func (c *Checker) buildLogTasks(ctx context.Context, regions []string) []checkTask {
	tasks := make([]checkTask, 0, len(regions)*3)

	for _, region := range regions {
		r := region
		// logs subcommand focuses only on log output configuration checks.
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckAWSConfig(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckCloudTrail(ctx, r) }})
		tasks = append(tasks, checkTask{run: func() CheckResult { return c.CheckGuardDutyFindingsExport(ctx, r) }})
	}

	return tasks
}
