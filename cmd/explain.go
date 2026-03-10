package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/spf13/cobra"
)

var explainPolicyCmd = &cobra.Command{
	Use:   "explain [policy-name-or-id]",
	Short: "Explain a Conditional Access policy in human-readable language",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policyIdentifier := args[0]

		_, err := getGraphHelper()

		if err != nil {
			log.Fatalf("Error initializing Graph for user auth: %v", err)
		}

		// Try to find policy by name or ID
		policy, err := findPolicy(policyIdentifier)
		if err != nil {
			log.Fatalf("Error finding policy: %v", err)
		}

		if policy == nil {
			log.Fatalf("Policy not found: %s", policyIdentifier)
		}

		// Print human-readable explanation
		printPolicyExplanation(policy)

		// JSON output flag
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			fmt.Println("\n" + strings.Repeat("=", 80))
			fmt.Printf("%sRaw JSON Response:%s\n\n", colorCyan, colorReset)
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			encoder.Encode(policy)
		}
	},
}

func init() {
	explainPolicyCmd.Flags().BoolP("json", "j", false, "Include raw JSON output")
}

func findPolicy(identifier string) (models.ConditionalAccessPolicyable, error) {
	graphHelper, err := getGraphHelper()

	if err != nil {
		log.Fatalf("Error initializing Graph for user auth: %v", err)
	}
	// First try as ID
	policy, err := graphHelper.GetCAPolicy(identifier)
	if err == nil {
		return policy, nil
	}

	// If not found by ID, search by name
	policies, err := graphHelper.ListCAPolicy()
	if err != nil {
		return nil, err
	}

	for _, p := range policies {
		if p.GetDisplayName() != nil && *p.GetDisplayName() == identifier {
			// Get full policy details
			return graphHelper.GetCAPolicy(*p.GetId())
		}
	}

	return nil, nil
}

func printPolicyExplanation(policy models.ConditionalAccessPolicyable) {
	// Header
	fmt.Printf("\n%sPolicy:%s %s\n", colorCyan, colorReset, getString(policy.GetDisplayName()))
	fmt.Printf("%sState:%s %s\n", colorCyan, colorReset, getStateStr(policy.GetState()))
	fmt.Printf("%sPolicy ID:%s %s\n\n", colorCyan, colorReset, getString(policy.GetId()))

	conditions := policy.GetConditions()
	if conditions == nil {
		fmt.Println("No conditions configured")
		return
	}

	// Applies to section
	fmt.Printf("%s=== Applies to ===%s\n\n", colorGreen, colorReset)

	users := conditions.GetUsers()
	if users != nil {
		printUserScope("Included users", users.GetIncludeUsers(), users.GetIncludeGroups(), users.GetIncludeRoles())
		printUserScope("Excluded users", users.GetExcludeUsers(), users.GetExcludeGroups(), users.GetExcludeRoles())
	}

	apps := conditions.GetApplications()
	if apps != nil {
		printAppScope("Target resources", apps.GetIncludeApplications())
		if len(apps.GetExcludeApplications()) > 0 {
			printAppScope("Excluded resources", apps.GetExcludeApplications())
		}
	}

	clientAppTypes := conditions.GetClientAppTypes()
	if clientAppTypes != nil && len(clientAppTypes) > 0 {
		fmt.Printf("• %sClient apps:%s ", colorCyan, colorReset)
		var types []string
		for _, t := range clientAppTypes {
			types = append(types, fmt.Sprintf("%v", t))
		}
		fmt.Printf("%s\n", strings.Join(types, ", "))
	}

	locations := conditions.GetLocations()
	if locations != nil {
		if len(locations.GetIncludeLocations()) > 0 {
			printLocationScope("Locations", locations.GetIncludeLocations())
		}
		if len(locations.GetExcludeLocations()) > 0 {
			printLocationScope("Excluded locations", locations.GetExcludeLocations())
		}
	}

	platforms := conditions.GetPlatforms()
	if platforms != nil && len(platforms.GetIncludePlatforms()) > 0 {
		fmt.Printf("• %sPlatforms:%s ", colorCyan, colorReset)
		var plat []string
		for _, p := range platforms.GetIncludePlatforms() {
			plat = append(plat, fmt.Sprintf("%v", p))
		}
		fmt.Printf("%s\n", strings.Join(plat, ", "))
	}

	// Access logic section
	fmt.Printf("\n%s=== Access Logic ===%s\n\n", colorGreen, colorReset)

	grant := policy.GetGrantControls()
	if grant != nil {
		controls := grant.GetBuiltInControls()
		operator := grant.GetOperator()

		if len(controls) > 0 {
			operatorText := "AND"
			if operator != nil && strings.ToLower(*operator) == "or" {
				operatorText = "OR"
			}

			fmt.Printf("Require %s of the following:\n", operatorText)
			for _, c := range controls {
				controlName := translateControl(fmt.Sprintf("%v", c))
				fmt.Printf("  • %s\n", controlName)
			}
		}
	}

	session := policy.GetSessionControls()
	if session != nil {
		printSessionExplanation(session)
	}

	// Meaning section
	fmt.Printf("\n%s=== What This Means ===%s\n\n", colorGreen, colorReset)
	fmt.Println(generateHumanExplanation(policy))
	fmt.Println()
}

func printUserScope(label string, users, groups, roles []string) {
	items := []string{}

	if contains(users, "All") {
		items = append(items, "All users")
	} else if len(users) > 0 {
		if contains(users, "GuestsOrExternalUsers") {
			items = append(items, "Guest/External users")
		}
		if len(users) > 1 || !contains(users, "GuestsOrExternalUsers") {
			items = append(items, fmt.Sprintf("%d specific user(s)", len(users)))
		}
	}

	if len(groups) > 0 {
		items = append(items, fmt.Sprintf("%d group(s)", len(groups)))
	}

	if len(roles) > 0 {
		roleNames := []string{}
		for _, role := range roles {
			roleNames = append(roleNames, translateRole(role))
		}
		items = append(items, strings.Join(roleNames, ", "))
	}

	if len(items) > 0 {
		fmt.Printf("• %s%s:%s %s\n", colorCyan, label, colorReset, strings.Join(items, ", "))
	}
}

func printAppScope(label string, apps []string) {
	if len(apps) == 0 {
		return
	}

	if contains(apps, "All") {
		fmt.Printf("• %s%s:%s All cloud apps\n", colorCyan, label, colorReset)
	} else if contains(apps, "Office365") {
		fmt.Printf("• %s%s:%s Office 365\n", colorCyan, label, colorReset)
	} else {
		fmt.Printf("• %s%s:%s %d application(s)\n", colorCyan, label, colorReset, len(apps))
	}
}

func printLocationScope(label string, locations []string) {
	if len(locations) == 0 {
		return
	}

	if contains(locations, "All") {
		fmt.Printf("• %s%s:%s All locations\n", colorCyan, label, colorReset)
	} else if contains(locations, "AllTrusted") {
		fmt.Printf("• %s%s:%s All trusted locations\n", colorCyan, label, colorReset)
	} else {
		fmt.Printf("• %s%s:%s %d location(s)\n", colorCyan, label, colorReset, len(locations))
	}
}

func printSessionExplanation(session models.ConditionalAccessSessionControlsable) {
	var controls []string

	if session.GetApplicationEnforcedRestrictions() != nil && session.GetApplicationEnforcedRestrictions().GetIsEnabled() != nil && *session.GetApplicationEnforcedRestrictions().GetIsEnabled() {
		controls = append(controls, "Application enforced restrictions")
	}
	if session.GetCloudAppSecurity() != nil {
		controls = append(controls, "Cloud App Security monitoring")
	}
	if session.GetSignInFrequency() != nil {
		freq := session.GetSignInFrequency()
		if freq.GetValue() != nil {
			controls = append(controls, fmt.Sprintf("Sign-in frequency: %d %v", *freq.GetValue(), freq.GetTypeEscaped()))
		}
	}
	if session.GetPersistentBrowser() != nil {
		controls = append(controls, fmt.Sprintf("Persistent browser: %v", session.GetPersistentBrowser().GetMode()))
	}

	if len(controls) > 0 {
		fmt.Println("\nSession controls:")
		for _, ctrl := range controls {
			fmt.Printf("  • %s\n", ctrl)
		}
	}
}

func translateControl(control string) string {
	translations := map[string]string{
		"mfa":                  "Multi-factor authentication (MFA)",
		"compliantDevice":      "Device must be marked as compliant",
		"domainJoinedDevice":   "Device must be hybrid Azure AD joined",
		"approvedApplication":  "Require approved client app",
		"compliantApplication": "Require app protection policy",
		"passwordChange":       "Require password change",
	}

	if translated, ok := translations[control]; ok {
		return translated
	}
	return control
}

func translateRole(roleId string) string {
	// Common role GUIDs to names
	roleMap := map[string]string{
		"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
		"194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
		"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
		"29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
	}

	if name, ok := roleMap[roleId]; ok {
		return name
	}
	return "Admin role"
}

func generateHumanExplanation(policy models.ConditionalAccessPolicyable) string {
	conditions := policy.GetConditions()
	if conditions == nil {
		return "This policy has no conditions configured."
	}

	users := conditions.GetUsers()
	apps := conditions.GetApplications()
	grant := policy.GetGrantControls()

	// Build explanation
	var who, what, must string

	// Who
	if users != nil {
		includeUsers := users.GetIncludeUsers()
		includeRoles := users.GetIncludeRoles()

		if contains(includeUsers, "All") {
			who = "Any user"
		} else if len(includeRoles) > 0 {
			who = "Any in-scope admin"
		} else {
			who = "Any in-scope user"
		}
	}

	// What
	if apps != nil {
		includeApps := apps.GetIncludeApplications()
		if contains(includeApps, "All") {
			what = "signing into any cloud app"
		} else if contains(includeApps, "Office365") {
			what = "signing into Office 365"
		} else {
			what = "signing into an in-scope cloud app"
		}
	}

	// Must
	if grant != nil {
		controls := grant.GetBuiltInControls()
		if len(controls) > 0 {
			var requirements []string
			for _, c := range controls {
				ctrl := fmt.Sprintf("%v", c)
				if ctrl == "mfa" {
					requirements = append(requirements, "complete MFA")
				} else if ctrl == "compliantDevice" {
					requirements = append(requirements, "use a compliant device")
				} else {
					requirements = append(requirements, fmt.Sprintf("meet %s requirement", ctrl))
				}
			}
			must = strings.Join(requirements, " and ")
		}
	}

	explanation := fmt.Sprintf("%s %s must %s unless excluded.", who, what, must)

	return explanation
}
