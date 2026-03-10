package graph

import (
	"context"
	"fmt"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

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
