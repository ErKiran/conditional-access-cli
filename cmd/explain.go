package cmd

import (
	"ca-cli/helper"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"sort"
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

		_, err := helper.GetGraphHelper()

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
	graphHelper, err := helper.GetGraphHelper()

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
	fmt.Printf("%sSummary:%s %s\n\n", colorCyan, colorReset, generateHumanExplanation(policy))

	conditions := policy.GetConditions()
	if conditions == nil {
		fmt.Println("No conditions configured")
		return
	}

	// Applies to section
	fmt.Printf("%s=== Who and What This Targets ===%s\n\n", colorGreen, colorReset)

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

		if actions := apps.GetIncludeUserActions(); len(actions) > 0 {
			fmt.Printf("• %sUser actions:%s %s\n", colorCyan, colorReset, strings.Join(formatDetailedList(actions), ", "))
		}
		if authCtx := apps.GetIncludeAuthenticationContextClassReferences(); len(authCtx) > 0 {
			fmt.Printf("• %sAuthentication contexts:%s %s\n", colorCyan, colorReset, strings.Join(formatDetailedList(authCtx), ", "))
		}
	}

	clientAppTypes := conditions.GetClientAppTypes()
	if clientAppTypes != nil && len(clientAppTypes) > 0 {
		fmt.Printf("• %sClient apps:%s ", colorCyan, colorReset)
		var types []string
		for _, t := range clientAppTypes {
			types = append(types, humanizeClientType(fmt.Sprintf("%v", t)))
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
			plat = append(plat, humanizePlatform(fmt.Sprintf("%v", p)))
		}
		fmt.Printf("%s\n", strings.Join(plat, ", "))
		if len(platforms.GetExcludePlatforms()) > 0 {
			var excluded []string
			for _, p := range platforms.GetExcludePlatforms() {
				excluded = append(excluded, humanizePlatform(fmt.Sprintf("%v", p)))
			}
			fmt.Printf("• %sExcluded platforms:%s %s\n", colorCyan, colorReset, strings.Join(excluded, ", "))
		}
	}

	printRiskSection(conditions)

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
	fmt.Printf("\n%s=== Plain-English Walkthrough ===%s\n\n", colorGreen, colorReset)
	fmt.Println(generateReadableWalkthrough(policy))
	fmt.Println()
}

func printUserScope(label string, users, groups, roles []string) {
	if len(users) == 0 && len(groups) == 0 && len(roles) == 0 {
		return
	}

	parts := []string{}

	if len(users) > 0 {
		parts = append(parts, "users="+strings.Join(formatDetailedList(users), ", "))
	}
	if len(groups) > 0 {
		parts = append(parts, "groups="+strings.Join(formatDetailedList(groups), ", "))
	}
	if len(roles) > 0 {
		roleNames := []string{}
		for _, role := range roles {
			roleNames = append(roleNames, translateRole(role)+" ("+role+")")
		}
		parts = append(parts, "roles="+strings.Join(roleNames, ", "))
	}

	fmt.Printf("• %s%s:%s %s\n", colorCyan, label, colorReset, strings.Join(parts, " | "))
}

func printAppScope(label string, apps []string) {
	if len(apps) == 0 {
		return
	}

	fmt.Printf("• %s%s:%s %s\n", colorCyan, label, colorReset, strings.Join(formatDetailedList(apps), ", "))
}

func printLocationScope(label string, locations []string) {
	if len(locations) == 0 {
		return
	}

	fmt.Printf("• %s%s:%s %s\n", colorCyan, label, colorReset, strings.Join(formatDetailedList(locations), ", "))
}

func printSessionExplanation(session models.ConditionalAccessSessionControlsable) {
	var controls []string

	if session.GetApplicationEnforcedRestrictions() != nil && session.GetApplicationEnforcedRestrictions().GetIsEnabled() != nil && *session.GetApplicationEnforcedRestrictions().GetIsEnabled() {
		controls = append(controls, "Application enforced restrictions")
	}
	if session.GetCloudAppSecurity() != nil {
		controls = append(controls, "Cloud App Security session policy")
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

	if who == "" {
		who = "In-scope identities"
	}
	if what == "" {
		what = "performing in-scope sign-ins"
	}
	if must == "" {
		must = "meet this policy's configured requirements"
	}

	explanation := fmt.Sprintf("%s %s must %s unless excluded.", who, what, must)

	return explanation
}

func generateReadableWalkthrough(policy models.ConditionalAccessPolicyable) string {
	conditions := policy.GetConditions()
	if conditions == nil {
		return "This policy has no conditions, so it won’t evaluate meaningful targeting rules."
	}

	parts := []string{}

	if users := conditions.GetUsers(); users != nil {
		if len(users.GetIncludeUsers()) > 0 || len(users.GetIncludeGroups()) > 0 || len(users.GetIncludeRoles()) > 0 {
			parts = append(parts, "It targets the user scope listed above.")
		}
		if len(users.GetExcludeUsers()) > 0 || len(users.GetExcludeGroups()) > 0 || len(users.GetExcludeRoles()) > 0 {
			parts = append(parts, "Some users/groups/roles are explicitly excluded and bypass this policy.")
		}
	}

	if apps := conditions.GetApplications(); apps != nil {
		if len(apps.GetIncludeApplications()) > 0 {
			parts = append(parts, "It applies only when accessing the listed cloud apps/resources.")
		}
		if len(apps.GetExcludeApplications()) > 0 {
			parts = append(parts, "The excluded apps/resources are out of scope.")
		}
		if len(apps.GetIncludeUserActions()) > 0 {
			parts = append(parts, "It is also scoped to specific user actions.")
		}
	}

	if locations := conditions.GetLocations(); locations != nil {
		if len(locations.GetIncludeLocations()) > 0 {
			parts = append(parts, "Location conditions decide where sign-ins are in scope.")
		}
		if len(locations.GetExcludeLocations()) > 0 {
			parts = append(parts, "Excluded locations are treated as exceptions.")
		}
	}

	riskSignals := []string{}
	if v := callStringSliceMethod(conditions, "GetUserRiskLevels"); len(v) > 0 {
		riskSignals = append(riskSignals, "user risk")
	}
	if v := callStringSliceMethod(conditions, "GetSignInRiskLevels"); len(v) > 0 {
		riskSignals = append(riskSignals, "sign-in risk")
	}
	if len(riskSignals) > 0 {
		parts = append(parts, "Risk signals are part of evaluation ("+strings.Join(riskSignals, " and ")+").")
	}

	if grant := policy.GetGrantControls(); grant != nil && len(grant.GetBuiltInControls()) > 0 {
		op := "all"
		if grant.GetOperator() != nil && strings.EqualFold(*grant.GetOperator(), "or") {
			op = "one"
		}
		parts = append(parts, fmt.Sprintf("When the policy matches, the user must satisfy %s listed grant control(s).", op))
	}

	if len(parts) == 0 {
		return "This policy is enabled but has limited visible targeting details in the current response."
	}

	return strings.Join(parts, " ")
}

func printRiskSection(conditions models.ConditionalAccessConditionSetable) {
	riskMap := map[string][]string{
		"User risk":              callStringSliceMethod(conditions, "GetUserRiskLevels"),
		"Sign-in risk":           callStringSliceMethod(conditions, "GetSignInRiskLevels"),
		"Insider risk":           callStringSliceMethod(conditions, "GetInsiderRiskLevels"),
		"Service principal risk": callStringSliceMethod(conditions, "GetServicePrincipalRiskLevels"),
	}

	keys := []string{"User risk", "Sign-in risk", "Insider risk", "Service principal risk"}
	printed := false
	for _, k := range keys {
		vals := riskMap[k]
		if len(vals) == 0 {
			continue
		}
		printed = true
		fmt.Printf("• %s%s:%s %s\n", colorCyan, k, colorReset, strings.Join(formatDetailedList(vals), ", "))
	}

	if printed {
		fmt.Printf("• %sRisk note:%s these values are evaluated as policy conditions, not real-time detections by this CLI.\n", colorCyan, colorReset)
	}
}

func callStringSliceMethod(target any, methodName string) []string {
	rv := reflect.ValueOf(target)
	if !rv.IsValid() {
		return nil
	}

	m := rv.MethodByName(methodName)
	if !m.IsValid() {
		return nil
	}

	out := m.Call(nil)
	if len(out) == 0 {
		return nil
	}

	res := out[0]
	if !res.IsValid() || res.Kind() != reflect.Slice || res.IsNil() {
		return nil
	}

	items := make([]string, 0, res.Len())
	for i := 0; i < res.Len(); i++ {
		items = append(items, fmt.Sprintf("%v", res.Index(i).Interface()))
	}
	return items
}

func formatDetailedList(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, humanizeSpecialValue(v))
	}
	sort.Strings(out)
	return out
}

func humanizeSpecialValue(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return s
	}

	sLower := strings.ToLower(s)
	switch sLower {
	case "all":
		return "All"
	case "none":
		return "None"
	case "alltrusted":
		return "All trusted locations"
	case "office365":
		return "Office 365"
	case "guestsorexternalusers":
		return "Guests or external users"
	default:
		return s
	}
}

func humanizePlatform(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "windows":
		return "Windows"
	case "macos", "mac":
		return "macOS"
	case "ios":
		return "iOS"
	case "android":
		return "Android"
	case "linux":
		return "Linux"
	default:
		return v
	}
}

func humanizeClientType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "browser":
		return "Browser"
	case "mobileappsanddesktopclients":
		return "Mobile apps and desktop clients"
	case "exchangeactivesync":
		return "Exchange ActiveSync"
	case "other":
		return "Other legacy clients"
	default:
		return v
	}
}
