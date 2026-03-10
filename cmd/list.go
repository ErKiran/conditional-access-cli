package cmd

import (
	"ca-cli/helper"
	"fmt"
	"log"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/spf13/cobra"
)

var listPolicyCmd = &cobra.Command{
	Use:   "list",
	Short: "List Conditional Access policies",
	Run: func(cmd *cobra.Command, args []string) {
		graphHelper, err := helper.GetGraphHelper()

		if err != nil {
			log.Fatalf("Error initializing Graph for user auth: %v", err)
		}

		policies, err := graphHelper.ListCAPolicy()
		if err != nil {
			log.Fatalf("Error listing Conditional Access policies: %v", err)
		}

		fmt.Printf("\n%s✓%s Found %d Conditional Access policies\n", colorGreen, colorReset, len(policies))
		if len(policies) == 0 {
			fmt.Println("No policies found.")
			return
		}

		// Calculate column widths based on content
		colWidths := calculateColumnWidths(policies)

		// Print table header
		printRow(colWidths,
			"POLICY NAME", "STATE", "INCLUDED USERS", "EXCLUDED USERS",
			"TARGET APPS", "GRANT CONTROLS", "SESSION CONTROLS")

		printSeparator(colWidths)

		// Print each policy
		for _, p := range policies {
			name := getString(p.GetDisplayName())
			state := getStateStr(p.GetState())
			includedUsers := getIncludedUsers(p)
			excludedUsers := getExcludedUsers(p)
			targetApps := getTargetApps(p)
			grantControls := getGrantControls(p)
			sessionControls := getSessionControls(p)

			printRow(colWidths, name, state, includedUsers, excludedUsers,
				targetApps, grantControls, sessionControls)
		}
		fmt.Println()
	},
}

func calculateColumnWidths(policies []models.ConditionalAccessPolicyable) []int {
	// Start with minimum widths (header lengths)
	widths := []int{12, 8, 14, 14, 11, 14, 16} // Min widths for headers
	headers := []string{"POLICY NAME", "STATE", "INCLUDED USERS", "EXCLUDED USERS",
		"TARGET APPS", "GRANT CONTROLS", "SESSION CONTROLS"}

	// Set initial widths to header lengths
	for i, h := range headers {
		if len(h) > widths[i] {
			widths[i] = len(h)
		}
	}

	// Check each policy and expand columns as needed
	for _, p := range policies {
		values := []string{
			getString(p.GetDisplayName()),
			getStateStr(p.GetState()),
			getIncludedUsers(p),
			getExcludedUsers(p),
			getTargetApps(p),
			getGrantControls(p),
			getSessionControls(p),
		}

		for i, v := range values {
			if len(v) > widths[i] {
				// Cap maximum width per column to keep table readable
				maxWidth := 50
				if i == 0 { // Policy name can be longer
					maxWidth = 60
				}
				if len(v) > maxWidth {
					widths[i] = maxWidth
				} else {
					widths[i] = len(v)
				}
			}
		}
	}

	return widths
}

func printRow(widths []int, cols ...string) {
	for i, col := range cols {
		if len(col) > widths[i] {
			col = col[:widths[i]-3] + "..."
		}
		fmt.Printf("%-*s  ", widths[i], col)
	}
	fmt.Println()
}

func printSeparator(widths []int) {
	total := 0
	for _, w := range widths {
		total += w + 2 // +2 for spacing
	}
	fmt.Println(strings.Repeat("-", total))
}

func getString(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func getStateStr(state interface{}) string {
	if state == nil {
		return "-"
	}
	return fmt.Sprintf("%v", state)
}

func getIncludedUsers(p models.ConditionalAccessPolicyable) string {
	conditions := p.GetConditions()
	if conditions == nil {
		return "-"
	}
	users := conditions.GetUsers()
	if users == nil {
		return "-"
	}

	includeUsers := users.GetIncludeUsers()
	if includeUsers == nil || len(includeUsers) == 0 {
		return "None"
	}

	if contains(includeUsers, "All") {
		return "All users"
	}

	return fmt.Sprintf("%d users/groups", len(includeUsers))
}

func getExcludedUsers(p models.ConditionalAccessPolicyable) string {
	conditions := p.GetConditions()
	if conditions == nil {
		return "-"
	}
	users := conditions.GetUsers()
	if users == nil {
		return "-"
	}

	excludeUsers := users.GetExcludeUsers()
	if excludeUsers == nil || len(excludeUsers) == 0 {
		return "None"
	}

	return fmt.Sprintf("%d users/groups", len(excludeUsers))
}

func getTargetApps(p models.ConditionalAccessPolicyable) string {
	conditions := p.GetConditions()
	if conditions == nil {
		return "-"
	}
	apps := conditions.GetApplications()
	if apps == nil {
		return "-"
	}

	includeApps := apps.GetIncludeApplications()
	if includeApps == nil || len(includeApps) == 0 {
		return "None"
	}

	if contains(includeApps, "All") {
		return "All apps"
	}

	return fmt.Sprintf("%d apps", len(includeApps))
}

func getGrantControls(p models.ConditionalAccessPolicyable) string {
	grant := p.GetGrantControls()
	if grant == nil {
		return "-"
	}

	controls := grant.GetBuiltInControls()
	if controls == nil || len(controls) == 0 {
		return "None"
	}

	var names []string
	for _, c := range controls {
		names = append(names, fmt.Sprintf("%v", c))
	}

	return strings.Join(names, ", ")
}

func getSessionControls(p models.ConditionalAccessPolicyable) string {
	session := p.GetSessionControls()
	if session == nil {
		return "None"
	}

	var controls []string
	if session.GetApplicationEnforcedRestrictions() != nil {
		controls = append(controls, "App restrictions")
	}
	if session.GetCloudAppSecurity() != nil {
		controls = append(controls, "Cloud App Security")
	}
	if session.GetSignInFrequency() != nil {
		controls = append(controls, "Sign-in frequency")
	}
	if session.GetPersistentBrowser() != nil {
		controls = append(controls, "Persistent browser")
	}

	if len(controls) == 0 {
		return "None"
	}

	return strings.Join(controls, ", ")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
