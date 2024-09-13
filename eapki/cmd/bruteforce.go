package cmd

import (
	"fmt"
	"os"

	"github.com/YoshihikoAbe/eapki/obfuscate"
	"github.com/spf13/cobra"
)

// obfuscateCmd represents the obfuscate command
var bruteforceCmd = &cobra.Command{
	Use:   "bruteforce FILES...",
	Short: "Deobfuscate files used early in the eapki client's boot process using precomputed obfuscator states",
	Args:  cobra.MinimumNArgs(1),
	Run:   runBruteforce,
}

func init() {
	rootCmd.AddCommand(bruteforceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// obfuscateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// obfuscateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runBruteforce(cmd *cobra.Command, args []string) {
	noDec := 0
	for _, name := range args {
		enc, err := os.ReadFile(name)
		if err != nil {
			fatal(err)
		}

		dec, err := obfuscate.Bruteforce(enc)
		if err != nil {
			fmt.Fprintln(os.Stderr, name+": decrypt failed:", err)
			continue
		}

		if err := os.WriteFile(name+".dec", dec, 0644); err != nil {
			fatal(err)
		}
		noDec++
		fmt.Println("successfully decrypted", name)
	}
	fmt.Printf("decrypted %d/%d files\n", noDec, len(args))
}
