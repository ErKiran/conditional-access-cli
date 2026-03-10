package graph

import (
	"context"
	"fmt"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

// https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0&tabs=go
func (g *GraphHelper) ListCAPolicy() ([]models.ConditionalAccessPolicyable, error) {
	if g.appClient == nil {
		return nil, fmt.Errorf("graph client not initialized")
	}

	policies, err := g.appClient.Identity().ConditionalAccess().Policies().Get(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("API call failed: %w", err)
	}

	if policies == nil || policies.GetValue() == nil {
		return []models.ConditionalAccessPolicyable{}, nil
	}

	fmt.Printf("✓ Retrieved %d policies from Graph API\n", len(policies.GetValue()))
	return policies.GetValue(), nil
}

// https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-get?view=graph-rest-1.0&tabs=http
func (g *GraphHelper) GetCAPolicy(policyID string) (models.ConditionalAccessPolicyable, error) {
	if g.appClient == nil {
		return nil, fmt.Errorf("graph client not initialized")
	}

	policy, err := g.appClient.Identity().ConditionalAccess().Policies().ByConditionalAccessPolicyId(policyID).Get(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("API call failed: %w", err)
	}

	return policy, nil
}
