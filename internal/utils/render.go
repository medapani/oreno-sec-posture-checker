package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	awscheck "oreno-sec-posture-checker/internal/aws"
)

func PrintTable(w io.Writer, results []awscheck.CheckResult, verbose bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if verbose {
		fmt.Fprintln(tw, "SERVICE\tREGION\t🚥STATUS\tDETAILS\tERROR")
	} else {
		fmt.Fprintln(tw, "SERVICE\tREGION\t🚥STATUS\tDETAILS")
	}
	passCount := 0
	warnCount := 0
	failCount := 0
	for _, r := range results {
		status := r.Status
		switch r.Status {
		case "pass":
			status = "🟢pass"
			passCount++
		case "warn":
			status = "🟡warn"
			warnCount++
		case "fail":
			status = "🔴fail"
			failCount++
		}
		if verbose {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Region, status, r.Details, r.ErrorText())
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, r.Region, status, r.Details)
		}
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\nSUMMARY: 🟢pass=%d  🟡warn=%d  🔴fail=%d\n", passCount, warnCount, failCount)
}

func PrintJSON(w io.Writer, results []awscheck.CheckResult, verbose bool) error {
	type jsonResult struct {
		Name    string `json:"name"`
		Region  string `json:"region,omitempty"`
		Status  string `json:"status"`
		Details string `json:"details,omitempty"`
		Error   string `json:"error,omitempty"`
	}

	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		result := jsonResult{
			Name:    r.Name,
			Region:  r.Region,
			Status:  r.Status,
			Details: r.Details,
		}
		if verbose {
			result.Error = r.ErrorText()
		}
		out = append(out, result)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func PrintCSV(w io.Writer, results []awscheck.CheckResult, verbose bool) error {
	cw := csv.NewWriter(w)
	if verbose {
		if err := cw.Write([]string{"name", "region", "status", "details", "error"}); err != nil {
			return err
		}
	} else {
		if err := cw.Write([]string{"name", "region", "status", "details"}); err != nil {
			return err
		}
	}
	for _, r := range results {
		var record []string
		if verbose {
			record = []string{r.Name, r.Region, r.Status, r.Details, r.ErrorText()}
		} else {
			record = []string{r.Name, r.Region, r.Status, r.Details}
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func PrintLogsTable(w io.Writer, results []awscheck.CheckResult, verbose bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if verbose {
		fmt.Fprintln(tw, "SERVICE\tREGION\t🚥STATUS\tS3\tCloudWatch Logs\tERROR")
	} else {
		fmt.Fprintln(tw, "SERVICE\tREGION\t🚥STATUS\tS3\tCloudWatch Logs")
	}
	passCount := 0
	failCount := 0
	for _, r := range results {
		status := r.Status
		switch r.Status {
		case "pass":
			status = "🟢pass"
			passCount++
		case "fail":
			status = "🔴fail"
			failCount++
		}
		if verbose {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Region, status, r.S3, r.CWL, r.ErrorText())
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Region, status, r.S3, r.CWL)
		}
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\nSUMMARY: 🟢pass=%d  🔴fail=%d\n", passCount, failCount)
}

func PrintLogsJSON(w io.Writer, results []awscheck.CheckResult, verbose bool) error {
	type jsonResult struct {
		Service        string `json:"service"`
		Region         string `json:"region,omitempty"`
		Status         string `json:"status"`
		S3             string `json:"s3,omitempty"`
		CloudWatchLogs string `json:"cloudwatchLogs,omitempty"`
		Error          string `json:"error,omitempty"`
	}

	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		status := r.Status
		if status != "pass" {
			status = "fail"
		}
		result := jsonResult{
			Service:        r.Name,
			Region:         r.Region,
			Status:         status,
			S3:             r.S3,
			CloudWatchLogs: r.CWL,
		}
		if verbose {
			result.Error = r.ErrorText()
		}
		out = append(out, result)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func PrintLogsCSV(w io.Writer, results []awscheck.CheckResult, verbose bool) error {
	cw := csv.NewWriter(w)
	if verbose {
		if err := cw.Write([]string{"service", "region", "status", "s3", "cloudwatch_logs", "error"}); err != nil {
			return err
		}
	} else {
		if err := cw.Write([]string{"service", "region", "status", "s3", "cloudwatch_logs"}); err != nil {
			return err
		}
	}
	for _, r := range results {
		status := r.Status
		if status != "pass" {
			status = "fail"
		}
		var record []string
		if verbose {
			record = []string{r.Name, r.Region, status, r.S3, r.CWL, r.ErrorText()}
		} else {
			record = []string{r.Name, r.Region, status, r.S3, r.CWL}
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
