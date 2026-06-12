package awscheck

// CheckResult is a normalized result for one security posture check.
type CheckResult struct {
	Name    string
	Region  string
	Status  string
	Details string
	S3      string
	CWL     string
	Err     error
}

func (r CheckResult) ErrorText() string {
	if r.Err == nil {
		return ""
	}
	return r.Err.Error()
}
