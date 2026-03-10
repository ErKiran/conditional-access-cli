package cmd

import (
	"ca-cli/graph"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with Microsoft Entra",
	Run: func(cmd *cobra.Command, args []string) {
		graphHelper := graph.NewGraphHelper()

		err := graphHelper.InitializeGraphForUserAuth()
		if err != nil {
			log.Fatalf("Error initializing Graph for user auth: %v", err)
		}

		org, err := graphHelper.GetOrganization()
		if err != nil {
			log.Fatalf("Error connecting to Microsoft Graph: %v", err)
		}

		fmt.Printf("\n%s✓%s Successfully authenticated to Microsoft Graph\n", colorGreen, colorReset)
		fmt.Printf("%sOrganization:%s %s\n", colorCyan, colorReset, *org.GetDisplayName())
	},
}
