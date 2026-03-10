package graph

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

func (g *GraphHelper) GetOrganization() (models.Organizationable, error) {
	orgs, err := g.appClient.Organization().Get(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	if len(orgs.GetValue()) > 0 {
		return orgs.GetValue()[0], nil
	}

	return nil, nil
}
