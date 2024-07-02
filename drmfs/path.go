package drmfs

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
	"strconv"
)

type PathObfuscator struct {
	hash hash.Hash
}

func (po *PathObfuscator) Init(contentsCode string) {
	key := sha1.Sum([]byte(contentsCode + "test"))
	po.hash = hmac.New(sha1.New, key[:])
}

func (po PathObfuscator) Obfuscate(path string) string {
	po.hash.Write([]byte(path))
	sum := po.hash.Sum(nil)
	po.hash.Reset()

	out, _ := formatHashPath(sum)
	return out
}

func formatHashPath(b []byte) (string, error) {
	const tbl = "0123456789abcdef"

	if size := len(b); size != sha1.Size {
		return "", drmError("invalid path size: " + strconv.Itoa(size))
	}

	out := make([]byte, 43)
	out[0] = tbl[b[0]>>4]
	out[1] = '/'
	out[2] = tbl[b[0]&15]
	out[3] = '/'
	out[4] = tbl[b[1]>>4]
	out[5] = '/'
	out[6] = tbl[b[1]&15]

	for i, b := range b[2:] {
		i *= 2
		out[i+7] = tbl[b>>4]
		out[i+8] = tbl[b&15]
	}

	return string(out), nil
}
