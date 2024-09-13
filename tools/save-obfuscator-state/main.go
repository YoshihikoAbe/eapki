package main

import (
	"os"

	"github.com/YoshihikoAbe/eapki/obfuscate"
)

func main() {
	b, _ := os.ReadFile(os.Args[1])
	obfus, _ := obfuscate.NewObfuscator(b)
	os.WriteFile(os.Args[2], []byte(obfus), 0644)
}
