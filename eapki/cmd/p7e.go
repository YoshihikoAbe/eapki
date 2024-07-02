package cmd

import (
	"fmt"
	"os"

	"github.com/YoshihikoAbe/eapki/dongle"
	"github.com/YoshihikoAbe/eapki/p7e"
	"github.com/spf13/cobra"
)

// p7eCmd represents the p7e command
var p7eCmd = &cobra.Command{
	Use:   "p7e FILES...",
	Short: "Decrypt PKCS #7 encrypted files (kdm.dll, etc...)",

	Args: cobra.MinimumNArgs(1),
	Run:  runP7E,
}

func init() {
	rootCmd.AddCommand(p7eCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// p7eCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// p7eCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runP7E(cmd *cobra.Command, args []string) {
	dongle, err := dongle.Find(dongle.LicenseKey)
	if err != nil {
		fatal(err)
	}

	for _, inName := range args {
		in, err := os.ReadFile(inName)
		if err != nil {
			fatal(err)
		}

		out, err := p7e.Decrypt(in, dongle)
		if err != nil {
			fatal(err)
		}
		outName := inName + ".out"
		if err := os.WriteFile(outName, out, 0666); err != nil {
			fatal(err)
		}

		fmt.Println(inName, "->", outName)
	}
}
