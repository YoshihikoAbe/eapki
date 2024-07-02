package cmd

import (
	"encoding/json"
	"os"

	"github.com/YoshihikoAbe/eapki/dongle"
	"github.com/YoshihikoAbe/eapki/keyring"
	"github.com/spf13/cobra"
)

// keyringCmd represents the keyring command
var keyringCmd = &cobra.Command{
	Use:   "keyring FILENAME",
	Short: "Create keyring dump",
	Args:  cobra.MinimumNArgs(1),

	Run: runKeyring,
}

func init() {
	rootCmd.AddCommand(keyringCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keyringCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keyringCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runKeyring(cmd *cobra.Command, args []string) {
	filename := args[0]

	dongle, err := dongle.Find(dongle.LicenseKey)
	if err != nil {
		fatal(err)
	}

	f, err := os.Open(filename)
	if err != nil {
		fatal(err)
	}
	kr, err := keyring.New(f, dongle)
	if err != nil {
		fatal(err)
	}

	mks := keyring.MemoryKeySource{
		Code:    kr.ContentsCode(),
		Version: kr.Version(),
		Master:  kr.MasterKey(),
	}
	data, err := json.Marshal(mks)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(mks.Code+"_"+mks.Version+".json", data, 0666); err != nil {
		fatal(err)
	}
}
