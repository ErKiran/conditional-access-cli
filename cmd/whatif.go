package cmd

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"ca-cli/graph"

	"github.com/spf13/cobra"
)

const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cGray   = "\033[90m"
)

type officialWhatIfItem struct {
	DisplayName      string
	State            string
	PolicyApplies    bool
	AnalysisReasons  string
	BuiltInControls  []string
	IncludeApps      []string
	IncludeUsers     []string
	IncludeGroups    []string
	ClientAppTypes   []string
	IncludeLocations []string
}

var whatIfCmd = &cobra.Command{
	Use:   "whatif",
	Short: "Simulate Conditional Access policy impact for a sign-in scenario",
	Run: func(cmd *cobra.Command, args []string) {
		user, _ := cmd.Flags().GetString("user")
		app, _ := cmd.Flags().GetString("app")
		platform, _ := cmd.Flags().GetString("platform")
		client, _ := cmd.Flags().GetString("client")
		ip, _ := cmd.Flags().GetString("ip")
		country, _ := cmd.Flags().GetString("country")

		if strings.TrimSpace(user) == "" || strings.TrimSpace(app) == "" {
			log.Fatal("Both --user and --app are required")
		}

		gh, err := getGraphHelper()
		if err != nil {
			log.Fatalf("Error initializing Graph: %v", err)
		}

		input := graph.WhatIfInput{
			User: user, App: app, Platform: platform, Client: client, IP: ip, Country: country,
		}

		resp, err := gh.WhatIfEvaluateOfficial(input)
		if err == nil {
			renderOfficialWhatIf(resp, user, app, client, platform, country)
			return
		}
		fmt.Printf("Official What-If failed, falling back to local evaluator: %v\n", err)

	},
}

func renderOfficialWhatIf(resp map[string]any, inputUser, inputApp, inputClient, inputPlatform, inputCountry string) {
	items := parseOfficialItems(resp)

	fmt.Printf("\n%sSimulation result%s for %s (official Graph What-If)\n\n", colorCyan, colorReset, inputUser)
	fmt.Printf("%sAPPLIED POLICIES%s\n", colorCyan, colorReset)

	finalReq := map[string]struct{}{}
	blocked := false

	for _, it := range items {
		statusText, statusColor, icon := formatPolicyStatus(it.PolicyApplies)

		fmt.Printf("%s %s%-38s%s %s%s%s\n", icon, colorCyan, it.DisplayName, colorReset, statusColor, statusText, cReset)
		fmt.Printf("  %sState:%s %s\n", cGray, cReset, it.State)

		if it.PolicyApplies {
			if len(it.BuiltInControls) > 0 {
				fmt.Printf("  %sControls required:%s %s\n", colorCyan, colorReset, strings.Join(it.BuiltInControls, ", "))
				for _, c := range it.BuiltInControls {
					lc := strings.ToLower(c)
					if strings.Contains(lc, "block") {
						blocked = true
					} else {
						finalReq[c] = struct{}{}
					}
				}
			} else {
				fmt.Printf("  %sControls required:%s none\n", colorCyan, colorReset)
			}
			fmt.Printf("  %sWhy applied:%s all evaluated conditions matched.\n", colorGreen, colorReset)
		} else {
			fmt.Printf("  %sWhy not applied:%s %s\n", cYellow, colorReset, explainAnalysisReason(it.AnalysisReasons))
			printConditionDebug(it, inputUser, inputApp, inputClient, inputPlatform, inputCountry)
		}
		fmt.Println()
	}

	fmt.Printf("%sFINAL EFFECT%s\n", colorCyan, colorReset)
	if blocked {
		fmt.Printf("%s✗ Access is blocked%s by at least one applied policy.\n", cRed, cReset)
		return
	}

	if len(finalReq) == 0 {
		fmt.Printf("%s✓ Access allowed%s (no additional controls required by matched policies).\n", colorGreen, colorReset)
		return
	}

	reqs := make([]string, 0, len(finalReq))
	for req := range finalReq {
		reqs = append(reqs, req)
	}

	sort.Strings(reqs)

	fmt.Printf("%s✓ Access is allowed only if:%s\n", colorGreen, colorReset)
	for _, req := range reqs {
		fmt.Printf("  - %s\n", req)
	}
}

func formatPolicyStatus(applied bool) (text, color, icon string) {
	if applied {
		return "applied", colorGreen, "✓"
	}
	return "not applied", cYellow, "•"
}

func parseOfficialItems(resp map[string]any) []officialWhatIfItem {
	out := []officialWhatIfItem{}
	val, _ := resp["value"].([]any)

	for _, v := range val {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}

		item := officialWhatIfItem{
			DisplayName:     getStringAny(m, "displayName", "Unnamed Policy"),
			State:           getStringAny(m, "state", "unknown"),
			PolicyApplies:   getBoolAny(m, "policyApplies"),
			AnalysisReasons: getStringAny(m, "analysisReasons", ""),
		}

		// grant controls
		if gc, ok := m["grantControls"].(map[string]any); ok {
			item.BuiltInControls = getStringSliceAny(gc, "builtInControls")
		}

		// conditions
		if c, ok := m["conditions"].(map[string]any); ok {
			if apps, ok := c["applications"].(map[string]any); ok {
				item.IncludeApps = getStringSliceAny(apps, "includeApplications")
			}
			if users, ok := c["users"].(map[string]any); ok {
				item.IncludeUsers = getStringSliceAny(users, "includeUsers")
				item.IncludeGroups = getStringSliceAny(users, "includeGroups")
			}
			item.ClientAppTypes = getStringSliceAny(c, "clientAppTypes")

			if loc, ok := c["locations"].(map[string]any); ok {
				item.IncludeLocations = getStringSliceAny(loc, "includeLocations")
			}
		}

		out = append(out, item)
	}

	return out
}

func printConditionDebug(it officialWhatIfItem, inUser, inApp, inClient, inPlatform, inCountry string) {
	fmt.Printf("  %sDebug:%s\n", cGray, cReset)
	fmt.Printf("    %s- Input user:%s %s\n", cGray, cReset, inUser)
	fmt.Printf("    %s- Input app:%s %s\n", cGray, cReset, inApp)
	fmt.Printf("    %s- Input client:%s %s\n", cGray, cReset, inClient)
	fmt.Printf("    %s- Input platform:%s %s\n", cGray, cReset, inPlatform)
	fmt.Printf("    %s- Input country:%s %s\n", cGray, cReset, inCountry)

	if len(it.IncludeApps) > 0 {
		fmt.Printf("    %s- Policy includeApplications:%s %s\n", cGray, cReset, strings.Join(it.IncludeApps, ", "))
	}
	if len(it.IncludeUsers) > 0 || len(it.IncludeGroups) > 0 {
		fmt.Printf("    %s- Policy includeUsers:%s %s\n", cGray, cReset, strings.Join(it.IncludeUsers, ", "))
		fmt.Printf("    %s- Policy includeGroups:%s %s\n", cGray, cReset, strings.Join(it.IncludeGroups, ", "))
	}
	if len(it.ClientAppTypes) > 0 {
		fmt.Printf("    %s- Policy clientAppTypes:%s %s\n", cGray, cReset, strings.Join(it.ClientAppTypes, ", "))
	}
	if len(it.IncludeLocations) > 0 {
		fmt.Printf("    %s- Policy includeLocations:%s %s\n", cGray, cReset, strings.Join(it.IncludeLocations, ", "))
	}
}

func explainAnalysisReason(r string) string {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "application":
		return "target application condition did not match"
	case "users":
		return "user/group scope condition did not match"
	case "clientapp":
		return "client app type condition did not match"
	case "platform":
		return "device platform condition did not match"
	case "location":
		return "location condition did not match"
	default:
		if r == "" {
			return "condition mismatch (unspecified by API)"
		}
		return r
	}
}

func getStringAny(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func getBoolAny(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func getStringSliceAny(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		if s, ok := a.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func init() {
	whatIfCmd.Flags().String("user", "", "User principal name (e.g., alice@contoso.com)")
	whatIfCmd.Flags().String("app", "", "Target app (appId or alias, e.g., office365)")
	whatIfCmd.Flags().String("platform", "", "Device platform (windows, ios, android, macOS, linux)")
	whatIfCmd.Flags().String("client", "", "Client app type (browser, mobileAppsAndDesktopClients, etc.)")
	whatIfCmd.Flags().String("ip", "", "IP address")
	whatIfCmd.Flags().String("country", "", "Country code (e.g., US)")
	whatIfCmd.Flags().Bool("raw", false, "Print raw official Graph response JSON")
	whatIfCmd.Flags().Bool("local", false, "Force local evaluator (skip official Graph What-If API)")
}
