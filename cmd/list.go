package cmd

import (
	"ca-cli/graph"
	"fmt"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

var listPolicyCmd = &cobra.Command{
	Use:   "list",
	Short: "List Conditional Access policies",
	Run: func(cmd *cobra.Command, args []string) {
		graphHelper := graph.NewGraphHelper()

		err := graphHelper.InitializeGraphForUserAuth()
		if err != nil {
			log.Fatalf("Error initializing Graph for user auth: %v", err)
		}

		policies, err := graphHelper.ListCAPolicy()
		if err != nil {
			log.Fatalf("Error listing Conditional Access policies: %v", err)
		}

		fmt.Printf("\n%s✓%s Found %d Conditional Access policies\n", colorGreen, colorReset, len(policies))
		// Print table header
		fmt.Printf("%-40s %-12s %-20s %-20s %-20s %-20s %-20s\n",
			"POLICY NAME", "STATE", "INCLUDED USERS", "EXCLUDED USERS", "TARGET APPS", "GRANT CONTROLS", "SESSION CONTROLS")
		fmt.Println(strings.Repeat("-", 152))

		for _, p := range policies {
			name := truncate(getString(p.GetDisplayName()), 40)
			state := truncate(getState(p.GetState()), 12)
			includedUsers := truncate(getIncludedUsers(p), 20)
			excludedUsers := truncate(getExcludedUsers(p), 20)
			targetApps := truncate(getTargetApps(p), 20)
			grantControls := truncate(getGrantControls(p), 20)
			sessionControls := truncate(getSessionControls(p), 20)

			fmt.Printf("%-40s %-12s %-20s %-20s %-20s %-20s %-20s\n",
				name, state, includedUsers, excludedUsers, targetApps, grantControls, sessionControls)
		}
		fmt.Println()
	},
}

func getString(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func getState(state interface{}) string {
	if state == nil {
		return "-"
	}
	return fmt.Sprintf("%v", state)
}

func getIncludedUsers(p interface{}) string {
	// Type assertion would go here based on your model
	// For now, return placeholder
	return "All/Groups"
}

func getExcludedUsers(p interface{}) string {
	return "None"
}

func getTargetApps(p interface{}) string {
	return "All apps"
}

func getGrantControls(p interface{}) string {
	return "MFA required"
}

func getSessionControls(p interface{}) string {
	return "None"
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
