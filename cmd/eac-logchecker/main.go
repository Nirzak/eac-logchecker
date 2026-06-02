// Command eac-logchecker verifies and signs EAC (Exact Audio Copy) log files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Nirzak/eac-logchecker/eaclogchecker"
)

const version = "1.0.1"

func main() {
	// Dispatch the 'sign' subcommand before the default flag set so that
	// sign-specific flags (--force) don't interfere with the verify flags.
	if len(os.Args) > 1 && os.Args[1] == "sign" {
		signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
		forceFlag := signCmd.Bool("force", false, "Force signing even if EAC version is too old")
		signCmd.Usage = func() {
			fmt.Fprintln(os.Stderr, "Usage: eac-logchecker sign [--force] <input_log> <output_log>")
			signCmd.PrintDefaults()
		}
		_ = signCmd.Parse(os.Args[2:])
		if signCmd.NArg() != 2 {
			signCmd.Usage()
			os.Exit(1)
		}
		if err := eaclogchecker.SignLog(signCmd.Arg(0), signCmd.Arg(1), *forceFlag); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Signed: %s → %s\n", signCmd.Arg(0), signCmd.Arg(1))
		return
	}

	// Default: verify mode.
	var (
		jsonFlag    = flag.Bool("json", false, "Output as JSON")
		versionFlag = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Println("eac-logchecker " + version)
		return
	}

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: eac-logchecker [--json] [--version] <file>\n")
		fmt.Fprintf(os.Stderr, "       eac-logchecker sign [--force] <input_log> <output_log>\n")
		os.Exit(1)
	}

	filePath := flag.Arg(0)

	if !*jsonFlag {
		fmt.Println("Log Integrity Checker   (C) 2010 by Andre Wiethoff")
		fmt.Println()
	}

	results := eaclogchecker.CheckChecksum(filePath)

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(results)
	} else {
		for i, r := range results {
			fmt.Printf("%d. %s\n", i+1, r.Message)
		}
	}
}
