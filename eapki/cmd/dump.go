package cmd

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/YoshihikoAbe/eapki/dongle"
	"github.com/YoshihikoAbe/eapki/drmfs"
	"github.com/YoshihikoAbe/eapki/keyring"
	"github.com/spf13/cobra"
)

// dumpCmd represents the dump command
var dumpCmd = &cobra.Command{
	Use:   "dump SOURCE DESTINATION",
	Short: "Dump the contents of an encrypted filesystem",
	Args:  cobra.MinimumNArgs(2),

	Run: runDump,
}

func init() {
	rootCmd.AddCommand(dumpCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dumpCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dumpCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	dumpCmd.Flags().StringP("key", "k", "", "Keyring dump file")
	dumpCmd.Flags().IntP("workers", "w", 0, "Number of workers. Specify a value less than one, and the number of logical CPUs available to the process will be used")
}

func runDump(cmd *cobra.Command, args []string) {
	src := args[0]
	dest := args[1]
	keyFile, _ := cmd.Flags().GetString("key")
	workers, _ := cmd.Flags().GetInt("workers")
	if workers < 1 {
		workers = runtime.NumCPU()
	}

	ks, err := getKeySource(keyFile)
	if err != nil {
		log.Fatalln("failed to initialize key source:", err)
	}

	start := time.Now()
	ch, err := drmfs.Dump(src, ks)
	if err != nil {
		log.Fatalln(err)
	}

	wg := sync.WaitGroup{}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			for {
				file, ok := <-ch
				if !ok {
					wg.Done()
					return
				}

				func(file drmfs.DrmFile) {
					defer file.Close()

					dir, _ := path.Split(file.Path)
					if err := os.MkdirAll(path.Join(dest, dir), 0777); err != nil {
						log.Fatalln(err)
						return
					}

					out, err := os.Create(path.Join(dest, file.Path))
					if err != nil {
						log.Fatalln(err)
						return
					}
					defer out.Close()

					if _, err := io.Copy(out, file); err != nil {
						log.Fatalln(err)
					}
				}(file)
			}
		}()
	}
	wg.Wait()
	log.Println("time elapsed:", time.Since(start))
}

func getKeySource(keyFile string) (keyring.KeySource, error) {
	if keyFile != "" {
		return loadKeyFile(keyFile)
	}
	return dongle.Find(dongle.LicenseKey)
}

func loadKeyFile(name string) (keyring.KeySource, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	ks := &keyring.MemoryKeySource{}
	if err := json.Unmarshal(data, ks); err != nil {
		return nil, err
	}

	return ks, nil
}
