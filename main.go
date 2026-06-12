package main

import (
	"fmt"
	"os"

	awscmd "oreno-sec-posture-checker/cmd/aws"
)

// app version
var appVersion = "0.0.0"

func main() {
	// Check for -v flag before passing to subcommand
	for _, arg := range os.Args[1:] {
		if arg == "-v" {
			fmt.Printf("oreno-sec-posture-checker version %s\n", appVersion)
			os.Exit(0)
		}
	}

	if err := awscmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
