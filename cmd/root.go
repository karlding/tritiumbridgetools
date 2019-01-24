package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "tritiumbridgetools",
	Short: "tritiumbridgetools provides tooling for working with a Tritium CAN-Ethernet bridge",
	Long:  `A suite of tooling that simpliflies working with the Tritium CAN-Ethernet bridge.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
