package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type WhatIfInput struct {
	User     string
	App      string
	Client   string
	Platform string
	IP       string
	Country  string
}

// NOTE: Graph What-If is strict about payload shape/values.
func (g *GraphHelper) WhatIfEvaluateOfficial(in WhatIfInput) (map[string]any, error) {
	if g.clientSecretCredential == nil {
		return nil, fmt.Errorf("graph credential not initialized")
	}

	token, err := g.clientSecretCredential.GetToken(
		context.Background(),
		policy.TokenRequestOptions{Scopes: []string{"https://graph.microsoft.com/.default"}},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	userID := strings.TrimSpace(in.User) // Prefer object ID; UPN may fail in some tenants
	appID := normalizeAppForWhatIf(in.App)

	payload := map[string]any{
		"signInIdentity": map[string]any{
			"@odata.type": "#microsoft.graph.userSignIn",
			"userId":      userID,
		},
		"signInContext": map[string]any{
			"@odata.type":         "#microsoft.graph.applicationContext",
			"includeApplications": []string{appID},
		},
		"signInConditions": map[string]any{
			"clientAppType":  normalizeClientApp(in.Client),
			"devicePlatform": normalizePlatform(in.Platform),
			"ipAddress":      strings.TrimSpace(in.IP),
			"country":        strings.ToUpper(strings.TrimSpace(in.Country)),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// Beta only for now to avoid action mismatch behavior on v1.0
	url := "https://graph.microsoft.com/beta/identity/conditionalAccess/evaluate"
	resp, err := doGraphPOST(url, token.Token, body)
	if err != nil {
		return nil, fmt.Errorf("official what-if call failed: %w", err)
	}
	return resp, nil
}

func doGraphPOST(url, bearer string, body []byte) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("graph status %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("invalid json response: %w", err)
	}
	return out, nil
}

func normalizeAppForWhatIf(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "office365", "m365", "microsoft365":
		// Office 365 SharePoint Online first-party app ID commonly used in CA examples
		return "00000003-0000-0ff1-ce00-000000000000"
	default:
		return strings.TrimSpace(v) // expect app GUID
	}
}

func normalizeClientApp(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "browser":
		return "browser"
	case "mobile", "desktop", "mobileappsanddesktopclients":
		return "mobileAppsAndDesktopClients"
	case "eas", "exchangeactivesync":
		return "exchangeActiveSync"
	default:
		return "browser"
	}
}

func normalizePlatform(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "windows":
		return "windows"
	case "mac", "macos":
		return "macOS"
	case "ios":
		return "iOS"
	case "android":
		return "android"
	case "linux":
		return "linux"
	default:
		return "windows"
	}
}
