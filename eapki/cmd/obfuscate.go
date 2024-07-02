package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/YoshihikoAbe/eapki/obfuscate"
	"github.com/spf13/cobra"
)

// obfuscateCmd represents the obfuscate command
var obfuscateCmd = &cobra.Command{
	Use:   "obfuscate BOOTSTRAP FILES...",
	Short: "Obfuscate or deobfuscate files used early in the eapki client's boot process (kbt.dll, etc...)",
	Args:  cobra.MinimumNArgs(2),
	Run:   runObfuscate,
}

func init() {
	rootCmd.AddCommand(obfuscateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// obfuscateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// obfuscateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	obfuscateCmd.Flags().BoolP("obfuscate", "o", false, "Perform obfuscation. By default, deobfuscation is performed")
}

func runObfuscate(cmd *cobra.Command, args []string) {
	bootstrapName := args[0]
	files := args[1:]

	b, err := os.ReadFile(bootstrapName)
	if err != nil {
		fatal(err)
	}
	o, err := obfuscate.NewObfuscator(b)
	if err != nil {
		fatal(err)
	}

	var do func(io.Writer, io.Reader) error
	if obfuscate, _ := cmd.Flags().GetBool("obfuscate"); obfuscate {
		do = o.Obfuscate
	} else {
		do = o.Deobfuscate
	}

	for _, inName := range files {
		in, err := os.Open(inName)
		if err != nil {
			fatal(err)
		}
		outName := inName + ".out"
		out, err := os.Create(outName)
		if err != nil {
			fatal(err)
		}

		if err := do(out, in); err != nil {
			fatal(err)
		}

		out.Close()
		in.Close()

		fmt.Println(inName, "->", outName)
	}
}
