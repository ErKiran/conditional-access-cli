package helper

import (
	"ca-cli/graph"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type BatchExecutor struct {
	gh      *graph.GraphHelper
	workers int
}

func NewBatchExecutor(gh *graph.GraphHelper, workers int) *BatchExecutor {
	if workers < 1 {
		workers = 5
	}
	if workers > 50 {
		workers = 50 // cap to prevent rate limiting
	}
	return &BatchExecutor{gh: gh, workers: workers}
}

func (be *BatchExecutor) Execute(scenarios []BatchScenario) ([]ScenarioResult, *BatchSummary, error) {
	start := time.Now()
	scenarioChan := make(chan BatchScenario, len(scenarios))
	resultChan := make(chan ScenarioResult, len(scenarios))
	var wg sync.WaitGroup

	// Spawn workers
	for i := 0; i < be.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for scenario := range scenarioChan {
				result := be.evaluateScenario(scenario)
				resultChan <- result
			}
		}()
	}

	// Feed scenarios
	go func() {
		for _, s := range scenarios {
			scenarioChan <- s
		}
		close(scenarioChan)
	}()

	// Wait and collect
	wg.Wait()
	close(resultChan)

	results := []ScenarioResult{}
	for r := range resultChan {
		results = append(results, r)
	}

	// Summarize
	summary := summarizeResults(results, time.Since(start))

	return results, summary, nil
}

func (be *BatchExecutor) evaluateScenario(s BatchScenario) ScenarioResult {

	result := ScenarioResult{
		ScenarioID:         s.ID,
		User:               s.User,
		App:                s.App,
		Platform:           s.Platform,
		Client:             s.Client,
		Country:            s.Country,
		IP:                 s.IP,
		UserRisk:           s.UserRisk,
		ProcessedAt:        time.Now().Format(time.RFC3339),
		AppliedPolicies:    []PolicyMatch{}, // avoid null in JSON
		NotAppliedPolicies: []PolicyMatch{}, // avoid null in JSON
	}

	userID, err := be.gh.ResolveUserID(s.User)
	if err != nil {
		result.Error = fmt.Sprintf("user resolution failed: %v", err)
		return result
	}

	input := graph.WhatIfInput{
		User:     userID,
		App:      s.App,
		Platform: s.Platform,
		Client:   s.Client,
		IP:       s.IP,
		Country:  s.Country,
		UserRisk: s.UserRisk,
	}

	resp, err := be.gh.WhatIfEvaluateOfficial(input)
	if err != nil {
		result.Error = fmt.Sprintf("evaluation failed: %v", err)
		return result
	}

	// Apply policy filter if specified
	if strings.TrimSpace(s.Policy) != "" {
		resp = filterResponseByPolicy(resp, s.Policy)
	}

	items := parseOfficialItems(resp)
	blocked := false
	finalReqs := map[string]struct{}{}

	for _, it := range items {
		pm := PolicyMatch{
			PolicyName:    it.DisplayName,
			PolicyID:      it.ID,
			State:         it.State,
			Result:        "not applied",
			GrantControls: it.BuiltInControls,
		}

		if it.PolicyApplies {
			pm.Result = "applied"
			pm.Reason = "all conditions matched"
			result.AppliedPolicies = append(result.AppliedPolicies, pm)

			for _, c := range it.BuiltInControls {
				lc := strings.ToLower(c)
				if contains(lc, "block") {
					blocked = true
				} else {
					finalReqs[c] = struct{}{}
				}
			}
		} else {
			pm.Reason = explainAnalysisReason(it.AnalysisReasons)
			result.NotAppliedPolicies = append(result.NotAppliedPolicies, pm)
		}
	}

	// Determine final effect
	if blocked {
		result.FinalEffect = "blocked"
	} else if len(finalReqs) == 0 {
		result.FinalEffect = "access_allowed"
	} else {
		ctrls := make([]string, 0, len(finalReqs))
		for c := range finalReqs {
			ctrls = append(ctrls, strings.ToLower(strings.TrimSpace(c)))
		}
		sort.Strings(ctrls) // deterministic
		result.FinalEffect = "requires_" + strings.Join(ctrls, "_and_")
	}

	return result
}

func filterResponseByPolicy(resp map[string]any, policyNameOrID string) map[string]any {
	val, ok := resp["value"].([]any)
	if !ok {
		return resp
	}

	filtered := []any{}
	policyLower := strings.ToLower(strings.TrimSpace(policyNameOrID))

	for _, v := range val {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}

		displayName := getStringAny(m, "displayName", "")
		policyID := getStringAny(m, "id", "")

		if strings.Contains(strings.ToLower(displayName), policyLower) ||
			strings.Contains(strings.ToLower(policyID), policyLower) {
			filtered = append(filtered, v)
		}
	}

	resp["value"] = filtered
	return resp
}

func summarizeResults(results []ScenarioResult, duration time.Duration) *BatchSummary {
	summary := &BatchSummary{
		TotalScenarios:     len(results),
		TopPolicies:        make(map[string]int),
		TopNonMatchReasons: make(map[string]int),
	}

	for _, r := range results {
		if r.Error != "" {
			summary.Errors++
			continue
		}

		summary.SuccessfulEvals++

		effect := strings.ToLower(strings.TrimSpace(r.FinalEffect))
		switch {
		case effect == "access_allowed":
			summary.AccessAllowed++
		case effect == "blocked":
			summary.Blocked++
		case strings.HasPrefix(effect, "requires_") && strings.Contains(effect, "mfa"):
			summary.MFARequired++
		}

		for _, p := range r.AppliedPolicies {
			summary.TopPolicies[p.PolicyName]++
		}
		for _, p := range r.NotAppliedPolicies {
			summary.TopNonMatchReasons[p.Reason]++
		}
	}

	summary.ProcessingDuration = fmt.Sprintf("%.2fs", duration.Seconds())
	return summary
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0)
}

// OfficialPolicyItem represents a parsed policy item from the official response
type OfficialPolicyItem struct {
	DisplayName     string
	State           string
	ID              string
	PolicyApplies   bool
	AnalysisReasons string
	BuiltInControls []string
}

// Helper to parse official response (reuse from whatif.go context)
func parseOfficialItems(resp map[string]any) []OfficialPolicyItem {
	// This should match your existing parseOfficialItems logic
	out := []OfficialPolicyItem{}

	val, _ := resp["value"].([]any)
	for _, v := range val {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}

		item := OfficialPolicyItem{
			DisplayName:     getStringAny(m, "displayName", "Unnamed"),
			State:           getStringAny(m, "state", "unknown"),
			PolicyApplies:   getBoolAny(m, "policyApplies"),
			AnalysisReasons: getStringAny(m, "analysisReasons", ""),
		}

		if gc, ok := m["grantControls"].(map[string]any); ok {
			item.BuiltInControls = getStringSliceAny(gc, "builtInControls")
		}

		out = append(out, item)
	}
	return out
}

func explainAnalysisReason(r string) string {
	switch r {
	case "application":
		return "application condition not met"
	case "users":
		return "user/group scope not met"
	case "clientapp":
		return "client app type not met"
	case "platform":
		return "platform condition not met"
	case "location":
		return "location condition not met"
	default:
		return "condition not met"
	}
}

func getStringAny(m map[string]any, key, defaultVal string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return defaultVal
}

func getBoolAny(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getStringSliceAny(m map[string]any, key string) []string {
	if v, ok := m[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return []string{}
}
