package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(proxyCommand)
}

var proxyCommand = &cobra.Command{
	Use:   "proxy",
	Short: "",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}
