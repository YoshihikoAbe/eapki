package p7e

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
)

type p7eError string

func (e p7eError) Error() string {
	return "eapki/p7e: " + string(e)
}

func Decrypt(data []byte, decrypter crypto.Decrypter) ([]byte, error) {
	const blockSize = 16

	if size := len(data); size < 260+blockSize {
		return nil, p7eError("file too small")
	}

	key := data[80 : 80+128]
	iv := data[239 : 239+16]
	content := data[260:]

	key, err := decrypter.Decrypt(nil, key, nil)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCDecrypter(block, iv)

	if len(content)%blockSize != 0 {
		return nil, p7eError("size of content is not a multiple of the cipher's block size")
	}
	cbc.CryptBlocks(content, content)

	padding := content[len(content)-1]
	if padding > blockSize {
		return nil, p7eError("invalid padding")
	}
	return content[:len(content)-int(padding)], nil
}
