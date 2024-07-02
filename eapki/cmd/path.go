package cmd

import (
	"fmt"

	"github.com/YoshihikoAbe/eapki/drmfs"
	"github.com/spf13/cobra"
)

// pathCmd represents the path command
var pathCmd = &cobra.Command{
	Use:   "path CODE PATH",
	Short: "Convert a path/filename to an obfuscated drmfs path",
	Args:  cobra.MinimumNArgs(2),

	Run: func(cmd *cobra.Command, args []string) {
		p := drmfs.PathObfuscator{}
		p.Init(args[0])
		fmt.Println(p.Obfuscate(args[1]))
	},
}

func init() {
	rootCmd.AddCommand(pathCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pathCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pathCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
