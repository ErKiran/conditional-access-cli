package helper

import (
	"ca-cli/graph"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	once           sync.Once
	sharedGraph    *graph.GraphHelper
	sharedGraphErr error
)

func GetGraphHelper() (*graph.GraphHelper, error) {
	once.Do(func() {
		sharedGraph = graph.NewGraphHelper()
		sharedGraphErr = sharedGraph.InitializeGraphForAppAuth()
	})
	return sharedGraph, sharedGraphErr
}

type BatchScenario struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	App      string `json:"app"`
	Platform string `json:"platform"`
	Client   string `json:"client"`
	Country  string `json:"country"`
	IP       string `json:"ip"`
	Policy   string `json:"policy,omitempty"` // Optional policy filter
}

type PolicyMatch struct {
	PolicyName      string   `json:"policyName"`
	PolicyID        string   `json:"policyId"`
	State           string   `json:"state"`
	Result          string   `json:"result"`
	Reason          string   `json:"reason"`
	GrantControls   []string `json:"grantControls"`
	SessionControls []string `json:"sessionControls"`
}

type ScenarioResult struct {
	ScenarioID         string        `json:"scenarioId"`
	User               string        `json:"user"`
	App                string        `json:"app"`
	Platform           string        `json:"platform"`
	Client             string        `json:"client"`
	Country            string        `json:"country"`
	IP                 string        `json:"ip"`
	FinalEffect        string        `json:"finalEffect"`
	AppliedPolicies    []PolicyMatch `json:"appliedPolicies"`
	NotAppliedPolicies []PolicyMatch `json:"notAppliedPolicies"`
	Error              string        `json:"error,omitempty"`
	ProcessedAt        string        `json:"processedAt"`
}

type BatchSummary struct {
	TotalScenarios     int            `json:"totalScenarios"`
	SuccessfulEvals    int            `json:"successfulEvaluations"`
	Errors             int            `json:"errors"`
	AccessAllowed      int            `json:"accessAllowed"`
	MFARequired        int            `json:"mfaRequired"`
	Blocked            int            `json:"blocked"`
	TopPolicies        map[string]int `json:"topPolicies"`
	TopNonMatchReasons map[string]int `json:"topNonMatchReasons"`
	ProcessingDuration string         `json:"processingDuration"`
}

func ReadScenariosFromCSV(filepath string) ([]BatchScenario, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV must have header and at least one data row")
	}

	// Parse header
	header := records[0]
	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.TrimSpace(col)] = i
	}

	// Validate required columns
	required := []string{"user", "app", "platform", "client"}
	for _, req := range required {
		if _, ok := colMap[req]; !ok {
			return nil, fmt.Errorf("missing required column: %s", req)
		}
	}

	scenarios := []BatchScenario{}
	for i, record := range records[1:] {
		id := fmt.Sprintf("scenario-%d", i+1)
		if idIdx, ok := colMap["scenario_id"]; ok && idIdx < len(record) {
			if s := strings.TrimSpace(record[idIdx]); s != "" {
				id = s
			}
		}

		scenario := BatchScenario{
			ID:       id,
			User:     getCSVField(record, colMap, "user"),
			App:      getCSVField(record, colMap, "app"),
			Platform: getCSVField(record, colMap, "platform"),
			Client:   getCSVField(record, colMap, "client"),
			Country:  getCSVField(record, colMap, "country"),
			IP:       getCSVField(record, colMap, "ip"),
			Policy:   getCSVField(record, colMap, "policy"), // Optional
		}

		if strings.TrimSpace(scenario.User) == "" || strings.TrimSpace(scenario.App) == "" {
			return nil, fmt.Errorf("row %d: user and app are required", i+2)
		}

		scenarios = append(scenarios, scenario)
	}

	return scenarios, nil
}

func WriteResultsToCSV(filepath string, results []ScenarioResult) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	header := []string{
		"scenario_id", "user", "app", "platform", "client", "country", "ip",
		"final_effect", "applied_policies_count", "not_applied_policies_count",
		"grant_controls", "error",
	}
	writer.Write(header)

	for _, r := range results {
		grantCtrls := ""
		if len(r.AppliedPolicies) > 0 && len(r.AppliedPolicies[0].GrantControls) > 0 {
			grantCtrls = strings.Join(r.AppliedPolicies[0].GrantControls, ";")
		}

		row := []string{
			r.ScenarioID,
			r.User,
			r.App,
			r.Platform,
			r.Client,
			r.Country,
			r.IP,
			r.FinalEffect,
			fmt.Sprintf("%d", len(r.AppliedPolicies)),
			fmt.Sprintf("%d", len(r.NotAppliedPolicies)),
			grantCtrls,
			r.Error,
		}
		writer.Write(row)
	}

	return nil
}

func WriteResultsToJSON(filepath string, results []ScenarioResult, summary *BatchSummary) error {
	output := map[string]any{
		"summary":  summary,
		"results":  results,
		"metadata": map[string]string{"version": "1.0"},
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0644)
}

func getCSVField(record []string, colMap map[string]int, field string) string {
	if idx, ok := colMap[field]; ok && idx < len(record) {
		return strings.TrimSpace(record[idx])
	}
	return ""
}
