// Tier-2 Docker pair migration test driver.
//
// Connects to the compose stack stood up by ../run.sh (NATS on
// :4222, parent-old /ready on :8081, parent-new /ready on :8082,
// LocalStack on :4566) and exercises one or more scenarios from the
// `AllScenarios` registry. Each scenario is its own end-to-end
// behaviour assertion — see scenarios.go.
//
// Usage:
//
//	go run .                       # all scenarios
//	go run . -scenario smoke       # just one
//	go run . -nats nats://host:4222  # alternate NATS endpoint
//
// Exit code 0 = all pass; 1 = at least one scenario failed; 2 = setup
// failure (couldn't connect to NATS, unknown scenario name, etc.).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	defaultNATSURL       = "nats://localhost:4222"
	defaultParentOldURL  = "http://localhost:8081"
	defaultParentNewURL  = "http://localhost:8082"
	defaultLocalStackURL = "http://localhost:4566"
)

func main() {
	scenarioFlag := flag.String("scenario", "", "Single scenario to run (default: all in AllScenarios)")
	natsURL := flag.String("nats", defaultNATSURL, "NATS URL")
	parentOldURL := flag.String("parent-old", defaultParentOldURL, "parent-old /ready base URL")
	parentNewURL := flag.String("parent-new", defaultParentNewURL, "parent-new /ready base URL")
	localStackURL := flag.String("localstack", defaultLocalStackURL, "LocalStack S3/KMS/SSM endpoint")
	scenarioTimeout := flag.Duration("timeout", 90*time.Second, "Per-scenario wall-clock budget")
	flag.Parse()

	nc, err := nats.Connect(*natsURL,
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(3),
		nats.ReconnectWait(500*time.Millisecond),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: nats connect %s: %v\n", *natsURL, err)
		os.Exit(2)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: jetstream context: %v\n", err)
		os.Exit(2)
	}

	h := &Harness{
		NC:            nc,
		JS:            js,
		ParentOldURL:  *parentOldURL,
		ParentNewURL:  *parentNewURL,
		LocalStackURL: *localStackURL,
	}

	selected := AllScenarios
	if *scenarioFlag != "" {
		s, ok := scenarioByName(*scenarioFlag)
		if !ok {
			fmt.Fprintf(os.Stderr, "FATAL: unknown scenario %q\nAvailable:\n", *scenarioFlag)
			for _, sc := range AllScenarios {
				fmt.Fprintf(os.Stderr, "  - %s\n", sc.Name)
			}
			os.Exit(2)
		}
		selected = []Scenario{s}
	}

	ctx := context.Background()
	failed := 0
	for _, sc := range selected {
		fmt.Printf("=== %s ===\n", sc.Name)
		scCtx, cancel := context.WithTimeout(ctx, *scenarioTimeout)
		err := sc.Run(scCtx, h)
		cancel()
		if err != nil {
			fmt.Printf("  FAIL: %v\n", err)
			failed++
			continue
		}
		fmt.Println("  PASS")
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d/%d scenario(s) failed\n", failed, len(selected))
		os.Exit(1)
	}
	fmt.Printf("\nAll %d scenario(s) passed.\n", len(selected))
}
