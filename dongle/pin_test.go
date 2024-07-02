package dongle

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestPin(t *testing.T) {
	pins := [3][]byte{}
	pins[0], _ = base64.StdEncoding.DecodeString("v0wNBOdwWybQ/5Gm3FRl1A==")
	pins[1], _ = base64.StdEncoding.DecodeString("fqa3fqUnIY7hAZQfY8bnTg==")
	pins[2], _ = base64.StdEncoding.DecodeString("fiY3fiUnIQ5hARQfY0ZnTg==")

	pg, _ := NewPinGenerator([]byte("05"))
	for i, want := range pins {
		if !bytes.Equal(pg.Generate(), want) {
			t.Fatalf("(%d): invalid pin", i)
		}
	}
}
