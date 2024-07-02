package cmd

import (
	"encoding/json"
	"os"

	"github.com/YoshihikoAbe/avsproperty"
	"github.com/YoshihikoAbe/eapki/drmfs"
	"github.com/spf13/cobra"
)

// fcheckCmd represents the fcheck command
var fcheckCmd = &cobra.Command{
	Use:   "fcheck ROOT ALLFILES/FILEPATH",
	Short: "Perform file integrity check",
	Args:  cobra.MinimumNArgs(2),
	Run:   runCheck,
}

func init() {
	rootCmd.AddCommand(fcheckCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// fcheckCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// fcheckCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runCheck(cmd *cobra.Command, args []string) {
	root := args[0]
	fileList := args[1]

	prop := avsproperty.Property{}
	if err := prop.ReadFile(fileList); err != nil {
		fatal(err)
	}

	result, err := drmfs.CheckContents(prop.Root, root)
	if err != nil {
		fatal(err)
	}
	b, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		fatal(err)
	}
	os.Stdout.Write(b)
}
