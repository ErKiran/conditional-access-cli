package cmd

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"ca-cli/helper"

	"github.com/spf13/cobra"
)

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Run batch What-If evaluations across multiple scenarios",
	Run: func(cmd *cobra.Command, args []string) {
		input, _ := cmd.Flags().GetString("input")
		csvOut, _ := cmd.Flags().GetString("csv")
		jsonOut, _ := cmd.Flags().GetString("json")
		workers, _ := cmd.Flags().GetInt("workers")

		if strings.TrimSpace(input) == "" {
			log.Fatal("--input is required")
		}

		// Read scenarios
		fmt.Printf("%sReading scenarios from %s...%s\n", colorCyan, input, colorReset)
		scenarios, err := helper.ReadScenariosFromCSV(input)
		if err != nil {
			log.Fatalf("Failed to read scenarios: %v", err)
		}
		fmt.Printf("%s✓ Loaded %d scenarios%s\n\n", colorGreen, len(scenarios), colorReset)

		// Execute batch
		gh, err := helper.GetGraphHelper()
		if err != nil {
			log.Fatalf("Error initializing Graph: %v", err)
		}

		fmt.Printf("Starting evaluation with %d workers...\n\n", workers)
		executor := helper.NewBatchExecutor(gh, workers)
		results, summary, err := executor.Execute(scenarios)
		if err != nil {
			log.Fatalf("Batch execution failed: %v", err)
		}

		// Print summary
		printBatchSummary(summary)

		// Write outputs
		if csvOut != "" {
			fmt.Printf("\n%sWriting CSV to %s...%s\n", colorCyan, csvOut, colorReset)
			if err := helper.WriteResultsToCSV(csvOut, results); err != nil {
				log.Fatalf("Failed to write CSV: %v", err)
			}
		}

		if jsonOut != "" {
			fmt.Printf("%sWriting JSON to %s...%s\n", colorCyan, jsonOut, colorReset)
			if err := helper.WriteResultsToJSON(jsonOut, results, summary); err != nil {
				log.Fatalf("Failed to write JSON: %v", err)
			}
		}

		fmt.Printf("\n%s✓ Batch complete%s\n", colorGreen, colorReset)
	},
}

func printBatchSummary(s *helper.BatchSummary) {
	fmt.Printf("%sBatch Summary%s\n", colorCyan, colorReset)
	fmt.Printf("──────────────────────────\n")
	fmt.Printf("Total scenarios:       %d\n", s.TotalScenarios)
	fmt.Printf("Successful evals:      %d\n", s.SuccessfulEvals)
	fmt.Printf("Errors:                %d\n", s.Errors)
	fmt.Printf("Processing time:       %s\n\n", s.ProcessingDuration)

	fmt.Printf("%sResult Distribution%s\n", colorCyan, colorReset)
	fmt.Printf("──────────────────────────\n")
	fmt.Printf("%s✓ Access allowed:%s     %d\n", colorGreen, colorReset, s.AccessAllowed)
	fmt.Printf("%s⚠ MFA required:%s       %d\n", cYellow, colorReset, s.MFARequired)
	fmt.Printf("%s✗ Blocked:%s            %d\n\n", cRed, colorReset, s.Blocked)

	if len(s.TopPolicies) > 0 {
		fmt.Printf("%sTop Applied Policies%s\n", colorCyan, colorReset)
		fmt.Printf("──────────────────────────\n")
		printTopN(s.TopPolicies, 5)
	}

	if len(s.TopNonMatchReasons) > 0 {
		fmt.Printf("\n%sTop Non-Match Reasons%s\n", colorCyan, colorReset)
		fmt.Printf("──────────────────────────\n")
		printTopN(s.TopNonMatchReasons, 5)
	}
}

func printTopN(m map[string]int, n int) {
	type kv struct {
		key   string
		value int
	}
	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].value > sorted[j].value
	})

	count := n
	if len(sorted) < n {
		count = len(sorted)
	}

	for i := 0; i < count; i++ {
		fmt.Printf("  %d. %s (%d)\n", i+1, sorted[i].key, sorted[i].value)
	}
}

func init() {
	batchCmd.Flags().StringP("input", "i", "", "CSV input file with scenarios (required)")
	batchCmd.Flags().StringP("csv", "c", "", "CSV output file")
	batchCmd.Flags().String("json", "", "JSON output file")
	batchCmd.Flags().IntP("workers", "w", 5, "Number of concurrent workers (1-50)")
	batchCmd.MarkFlagRequired("input")
}
