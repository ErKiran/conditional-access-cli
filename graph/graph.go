package graph

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

type GraphHelper struct {
	clientSecretCredential *azidentity.ClientSecretCredential
	appClient              *msgraphsdk.GraphServiceClient
}

func NewGraphHelper() *GraphHelper {
	return &GraphHelper{}
}

func getEnvOrErr(key string) (string, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return "", fmt.Errorf("missing required env var: %s", key)
	}
	return v, nil
}

// App-only auth (client credentials)
func (g *GraphHelper) InitializeGraphForAppAuth() error {
	clientID, err := getEnvOrErr("CLIENT_ID")
	if err != nil {
		return err
	}
	tenantID, err := getEnvOrErr("TENANT_ID")
	if err != nil {
		return err
	}
	clientSecret, err := getEnvOrErr("CLIENT_SECRET")
	if err != nil {
		return err
	}

	options := &azidentity.ClientSecretCredentialOptions{
		DisableInstanceDiscovery: false,
	}

	credential, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, options)
	if err != nil {
		return fmt.Errorf("creating client credential failed: %w", err)
	}

	scopes := []string{"https://graph.microsoft.com/.default"}

	// Force fresh token acquisition
	token, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: scopes,
	})
	if err != nil {
		return fmt.Errorf("acquiring graph token failed: %w", err)
	}

	fmt.Printf("✓ Token acquired (expires: %s)\n", token.ExpiresOn.Format("15:04:05"))

	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(credential, scopes)
	if err != nil {
		return fmt.Errorf("creating graph client failed: %w", err)
	}

	g.clientSecretCredential = credential
	g.appClient = client
	return nil
}

// Backward compatibility with existing callers
func (g *GraphHelper) InitializeGraphForUserAuth() error {
	return g.InitializeGraphForAppAuth()
}

func cmdContext() context.Context {
	return context.Background()
}
