package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"ca-cli/graph"

	"github.com/spf13/cobra"
)

var whatIfCmd = &cobra.Command{
	Use:   "whatif",
	Short: "Simulate Conditional Access policy impact for a sign-in scenario",
	Run: func(cmd *cobra.Command, args []string) {
		user, _ := cmd.Flags().GetString("user")
		app, _ := cmd.Flags().GetString("app")
		platform, _ := cmd.Flags().GetString("platform")
		client, _ := cmd.Flags().GetString("client")
		ip, _ := cmd.Flags().GetString("ip")
		country, _ := cmd.Flags().GetString("country")
		raw, _ := cmd.Flags().GetBool("raw")
		local, _ := cmd.Flags().GetBool("local")

		if strings.TrimSpace(user) == "" || strings.TrimSpace(app) == "" {
			log.Fatal("Both --user and --app are required")
		}

		gh, err := getGraphHelper()
		if err != nil {
			log.Fatalf("Error initializing Graph: %v", err)
		}

		input := graph.WhatIfInput{
			User: user, App: app, Platform: platform, Client: client, IP: ip, Country: country,
		}

		if !local {
			resp, err := gh.WhatIfEvaluateOfficial(input)
			if err == nil {
				fmt.Printf("\nSimulation result for %s (official Graph What-If)\n", user)
				if raw {
					b, _ := json.MarshalIndent(resp, "", "  ")
					fmt.Println(string(b))
				} else {
					// Minimal safe output until you map full response schema for your tenant.
					fmt.Println("Official evaluation succeeded. Use --raw to inspect response fields.")
				}
				return
			}
			fmt.Printf("Official What-If failed, falling back to local evaluator: %v\n", err)
		}
	},
}

func init() {
	whatIfCmd.Flags().String("user", "", "User principal name (e.g., alice@contoso.com)")
	whatIfCmd.Flags().String("app", "", "Target app (appId or alias, e.g., office365)")
	whatIfCmd.Flags().String("platform", "", "Device platform (windows, ios, android, macOS, linux)")
	whatIfCmd.Flags().String("client", "", "Client app type (browser, mobileAppsAndDesktopClients, etc.)")
	whatIfCmd.Flags().String("ip", "", "IP address")
	whatIfCmd.Flags().String("country", "", "Country code (e.g., US)")
	whatIfCmd.Flags().Bool("raw", false, "Print raw official Graph response JSON")
	whatIfCmd.Flags().Bool("local", false, "Force local evaluator (skip official Graph What-If API)")
}
