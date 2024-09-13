package obfuscate

import (
	"bytes"
	"embed"
	"strconv"
)

//go:embed states/*
var states embed.FS

var obfuscators []Obfuscator

func init() {
	entries, err := states.ReadDir("states")
	if err != nil {
		panic(err)
	}

	obfuscators = make([]Obfuscator, len(entries))
	for i, entry := range entries {
		b, err := states.ReadFile("states/" + entry.Name())
		if err != nil {
			panic(err)
		}
		obfuscators[i] = b
	}
}

func Bruteforce(in []byte) ([]byte, error) {
	if len := len(in); len < 5 {
		return nil, obfuscateError("file smaller than the minimum allowed size: " + strconv.Itoa(int(len)) + " < 5")
	}
	rd := bytes.NewReader(in)
	buf := bytes.NewBuffer(nil)

	for _, obfus := range obfuscators {
		rd.Seek(0, 0)
		if err := obfus.Deobfuscate(buf, rd); err != nil {
			return nil, err
		}
		switch string(buf.Bytes()[:4]) {
		case "<?xm":
			fallthrough
		case "<!--":
			fallthrough
		case "<con":
			fallthrough
		case "MZ\x90\x00":
			return buf.Bytes(), nil
		}
		buf.Reset()
	}
	return nil, obfuscateError("all bruteforce attempts failed")
}
