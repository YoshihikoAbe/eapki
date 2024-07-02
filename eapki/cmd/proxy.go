package cmd

import (
	"log"

	"github.com/YoshihikoAbe/eapki/dongle"
	"github.com/YoshihikoAbe/eapki/proxy"
	"github.com/spf13/cobra"
)

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy ADDRESS REMOTE",
	Short: "Start authentication proxy",
	Long: `A TLS/SSL proxy that performs client certificate authentication on behalf of its clients.
It uses the newest client certificate from the connected account key.`,
	Args: cobra.MinimumNArgs(2),
	Run:  runProxy,
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runProxy(cmd *cobra.Command, args []string) {
	dongle, err := dongle.Find(dongle.AccountKey)
	if err != nil {
		log.Fatalln(err)
	}
	log.Fatalln(proxy.Listen(args[0], args[1], dongle))
}
