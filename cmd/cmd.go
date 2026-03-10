package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	colorReset = "\033[0m"
	colorGreen = "\033[32m"
	colorCyan  = "\033[36m"
)

var rootCmd = &cobra.Command{
	Use:   "ca",
	Short: "Entra Conditional Access CLI Tool",
	Long:  "Entra Conditional Access CLI Tool for listing, managing conditional access policies.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Conditional Access policy commands",
}

var entraCmd = &cobra.Command{
	Use:   "entra",
	Short: "Authenticate with Microsoft Entra",
}

func init() {
	entraCmd.AddCommand(authCmd)

	rootCmd.AddCommand(listPolicyCmd)
	rootCmd.AddCommand(entraCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
