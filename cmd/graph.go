package cmd

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/spf13/cobra"
)

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Visualize Conditional Access policy relationships",
	Run: func(cmd *cobra.Command, args []string) {
		gh, err := getGraphHelper()
		if err != nil {
			log.Fatalf("Error initializing Graph: %v", err)
		}

		policies, err := gh.ListCAPolicy()
		if err != nil {
			log.Fatalf("Error listing Conditional Access policies: %v", err)
		}

		if len(policies) == 0 {
			fmt.Println("No policies found.")
			return
		}

		fmt.Printf("\n%sPolicy Relationship Graph%s\n\n", colorCyan, colorReset)

		appToPolicies := map[string]map[string]struct{}{}
		userToPolicies := map[string]map[string]struct{}{}

		for _, p := range policies {
			name := safe(p.GetDisplayName(), "Unnamed Policy")
			state := policyStateLabel(p.GetState())
			users := graphUsers(p)
			apps := graphApps(p)
			access := graphAccessLabel(p)

			for _, u := range users {
				for _, a := range apps {
					fmt.Printf("[%s] ──> [%s] ──> [%s] (%s, %s)\n", u, a, name, state, access)

					addEdge(appToPolicies, a, name)
					addEdge(userToPolicies, u, name)
				}
			}
		}

		// Overlap summary
		fmt.Printf("\n%sOverlaps%s\n", colorCyan, colorReset)
		printOverlaps("Same app targeted by multiple policies", appToPolicies)
		printOverlaps("Policies that hit same user/group scope", userToPolicies)

		// Block + state summary
		var blockPolicies, reportOnly, enabled []string
		for _, p := range policies {
			name := safe(p.GetDisplayName(), "Unnamed Policy")
			state := strings.ToLower(policyStateLabel(p.GetState()))

			if hasBlockControl(p) {
				blockPolicies = append(blockPolicies, name)
			}
			if strings.Contains(state, "report-only") {
				reportOnly = append(reportOnly, name)
			}
			if strings.Contains(state, "enabled") && !strings.Contains(state, "report-only") {
				enabled = append(enabled, name)
			}
		}

		sort.Strings(blockPolicies)
		sort.Strings(reportOnly)
		sort.Strings(enabled)

		fmt.Printf("\n%sPolicy Categories%s\n", colorCyan, colorReset)
		fmt.Printf("- Policies with block controls: %s\n", joinOrNone(blockPolicies))
		fmt.Printf("- Report-only policies: %s\n", joinOrNone(reportOnly))
		fmt.Printf("- Enabled policies: %s\n", joinOrNone(enabled))
		fmt.Println()
	},
}

func addEdge(idx map[string]map[string]struct{}, key, policy string) {
	if _, ok := idx[key]; !ok {
		idx[key] = map[string]struct{}{}
	}
	idx[key][policy] = struct{}{}
}

func printOverlaps(title string, idx map[string]map[string]struct{}) {
	fmt.Printf("- %s:\n", title)
	keys := make([]string, 0, len(idx))
	for k := range idx {
		if len(idx[k]) > 1 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	if len(keys) == 0 {
		fmt.Println("  none")
		return
	}

	for _, k := range keys {
		policies := make([]string, 0, len(idx[k]))
		for p := range idx[k] {
			policies = append(policies, p)
		}
		sort.Strings(policies)
		fmt.Printf("  %s -> %s\n", k, strings.Join(policies, ", "))
	}
}

func graphUsers(p models.ConditionalAccessPolicyable) []string {
	c := p.GetConditions()
	if c == nil || c.GetUsers() == nil {
		return []string{"Unknown Users"}
	}
	u := c.GetUsers()

	out := []string{}
	if contains(u.GetIncludeUsers(), "All") {
		out = append(out, "All Users")
	}
	if len(u.GetIncludeGroups()) > 0 {
		out = append(out, fmt.Sprintf("%d Group(s)", len(u.GetIncludeGroups())))
	}
	if len(u.GetIncludeRoles()) > 0 {
		out = append(out, fmt.Sprintf("%d Role(s)", len(u.GetIncludeRoles())))
	}
	if len(out) == 0 {
		out = append(out, "Scoped Users")
	}
	return out
}

func graphApps(p models.ConditionalAccessPolicyable) []string {
	c := p.GetConditions()
	if c == nil || c.GetApplications() == nil {
		return []string{"Unknown Apps"}
	}
	a := c.GetApplications()

	if contains(a.GetIncludeApplications(), "All") {
		return []string{"All Cloud Apps"}
	}
	if contains(a.GetIncludeApplications(), "Office365") {
		return []string{"Office 365"}
	}
	if len(a.GetIncludeApplications()) == 0 {
		return []string{"No Apps"}
	}
	return []string{fmt.Sprintf("%d App(s)", len(a.GetIncludeApplications()))}
}

func graphAccessLabel(p models.ConditionalAccessPolicyable) string {
	g := p.GetGrantControls()
	if g == nil || len(g.GetBuiltInControls()) == 0 {
		return "No Grant Controls"
	}
	ctrls := make([]string, 0, len(g.GetBuiltInControls()))
	for _, c := range g.GetBuiltInControls() {
		ctrls = append(ctrls, fmt.Sprintf("%v", c))
	}
	return strings.Join(ctrls, "+")
}

func hasBlockControl(p models.ConditionalAccessPolicyable) bool {
	g := p.GetGrantControls()
	if g == nil {
		return false
	}
	for _, c := range g.GetBuiltInControls() {
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", c)), "block") {
			return true
		}
	}
	return false
}

func policyStateLabel(state interface{}) string {
	s := strings.ToLower(fmt.Sprintf("%v", state))
	switch {
	case strings.Contains(s, "enabledforreportingbutnotenforced"):
		return "report-only"
	case strings.Contains(s, "enabled"):
		return "enabled"
	case strings.Contains(s, "disabled"):
		return "disabled"
	default:
		return s
	}
}

func safe(v *string, fallback string) string {
	if v == nil || strings.TrimSpace(*v) == "" {
		return fallback
	}
	return *v
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}
