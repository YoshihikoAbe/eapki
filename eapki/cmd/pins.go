package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/YoshihikoAbe/eapki/dongle"
	"github.com/spf13/cobra"
)

// pinCmd represents the pin command
var pinsCmd = &cobra.Command{
	Use:   "pins SERIAL",
	Short: "List possible dongle pins",
	Args:  cobra.MinimumNArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		pg, err := dongle.NewPinGenerator(bytes.ToLower([]byte(args[0])))
		if err != nil {
			fatal(err)
		}
		for i := 0; i < dongle.NumberOfPins; i++ {
			fmt.Println(base64.StdEncoding.EncodeToString(pg.Generate()))
		}
	},
}

func init() {
	rootCmd.AddCommand(pinsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pinCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pinCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
