package awscmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	awscheck "oreno-sec-posture-checker/internal/aws"
	"oreno-sec-posture-checker/internal/utils"
)

func Run() error {
	// Check for help flag
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			printHelp()
			return nil
		}
	}

	ctx := context.Background()
	subcommand, args, err := parseSubcommand(os.Args[1:])
	if err != nil {
		return err
	}

	var profile string
	var regionsCSV string
	var jsonOut bool
	var csvOut bool
	var progress bool
	var verbose bool

	fs := flag.NewFlagSet("oreno-sec-posture-checker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&profile, "profile", "", "AWS shared config profile")
	fs.StringVar(&regionsCSV, "regions", "", "Comma separated region names (default: auto discover enabled regions)")
	fs.BoolVar(&jsonOut, "json", false, "Print JSON output")
	fs.BoolVar(&csvOut, "csv", false, "Print CSV output")
	fs.BoolVar(&progress, "progress", true, "Show progress on stderr")
	fs.BoolVar(&verbose, "verbose", false, "Show error details in logs output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := awscheck.LoadConfig(ctx, profile)
	if err != nil {
		return err
	}

	regions := parseRegions(regionsCSV)
	if len(regions) == 0 {
		regions, err = awscheck.DiscoverRegions(ctx, cfg)
		if err != nil {
			return err
		}
	}
	if len(regions) == 0 {
		return fmt.Errorf("no active regions discovered")
	}

	accountID, err := awscheck.GetAccountID(ctx, cfg)
	if err != nil {
		return err
	}

	checker := awscheck.NewChecker(awscheck.NewClientFactory(cfg), accountID)

	var onProgress func(done, total int, result awscheck.CheckResult)
	if progress {
		var mu sync.Mutex
		onProgress = func(done, total int, result awscheck.CheckResult) {
			mu.Lock()
			defer mu.Unlock()
			region := result.Region
			if region == "" {
				region = "global"
			}
			fmt.Fprintf(os.Stderr, "\r\x1b[2KProgress %d/%d: %s [%s] -> %s", done, total, result.Name, region, result.Status)
			if done == total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	var results []awscheck.CheckResult
	isLogsMode := false
	switch subcommand {
	case "", "all":
		results = checker.RunWithProgress(ctx, regions, onProgress)
	case "logs":
		isLogsMode = true
		results = checker.RunLogsWithProgress(ctx, regions, onProgress)
	default:
		return fmt.Errorf("unknown subcommand %q (supported: all, logs)", subcommand)
	}

	if jsonOut {
		if isLogsMode {
			return utils.PrintLogsJSON(os.Stdout, results, verbose)
		}
		return utils.PrintJSON(os.Stdout, results, verbose)
	}
	if csvOut {
		if isLogsMode {
			return utils.PrintLogsCSV(os.Stdout, results, verbose)
		}
		return utils.PrintCSV(os.Stdout, results, verbose)
	}
	if isLogsMode {
		utils.PrintLogsTable(os.Stdout, results, verbose)
		return nil
	}
	utils.PrintTable(os.Stdout, results, verbose)
	return nil
}

func parseRegions(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	regions := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			regions = append(regions, s)
		}
	}
	return regions
}

func parseSubcommand(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", args, nil
	}
	if strings.HasPrefix(args[0], "-") {
		return "", args, nil
	}
	subcommand := strings.TrimSpace(args[0])
	if subcommand == "" {
		return "", args[1:], nil
	}
	return subcommand, args[1:], nil
}

func printHelp() {
	help := `Usage: oreno-sec-posture-checker [subcommand] [options]

Subcommands:
  all       Run all checks (default)
  logs      Check logs output settings only

Global Options:
  -h, --help       Show this help message
  -v               Show version

Check Options:
  -profile string  AWS shared config profile
  -regions string  Comma separated region names (default: auto discover enabled regions)
  -json            Print JSON output
  -csv             Print CSV output
  -progress bool   Show progress on stderr (default: true)
  -verbose         Show error details (default: false)

Examples:
  oreno-sec-posture-checker
  oreno-sec-posture-checker -profile dev
  oreno-sec-posture-checker -regions ap-northeast-1,us-east-1
  oreno-sec-posture-checker -verbose
  oreno-sec-posture-checker logs -regions ap-northeast-1
  oreno-sec-posture-checker logs -regions ap-northeast-1 -verbose
  oreno-sec-posture-checker -json
  oreno-sec-posture-checker -csv
`
	fmt.Fprint(os.Stdout, help)
}
