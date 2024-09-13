package obfuscate

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha512"
	"debug/pe"
	"encoding"
	"encoding/binary"
	"io"
	"strconv"
	"unsafe"
)

type obfuscateError string

func (e obfuscateError) Error() string {
	return "eapki/obfuscate: " + string(e)
}

type Obfuscator []byte

func NewObfuscator(bootstrap []byte) (Obfuscator, error) {
	f, err := pe.NewFile(bytes.NewReader(bootstrap))
	if err != nil {
		return nil, err
	}

	var (
		checksum  uintptr
		subsystem uintptr
		directory uintptr
		size      uint32
	)
	if header, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		size = header.SizeOfHeaders
		checksum = unsafe.Offsetof(header.CheckSum)
		subsystem = unsafe.Offsetof(header.Subsystem)
		directory = unsafe.Offsetof(header.DataDirectory)
	} else {
		header := f.OptionalHeader.(*pe.OptionalHeader32)
		size = header.SizeOfHeaders
		checksum = unsafe.Offsetof(header.CheckSum)
		subsystem = unsafe.Offsetof(header.Subsystem)
		directory = unsafe.Offsetof(header.DataDirectory)
	}
	optional := uintptr(binary.LittleEndian.Uint32(bootstrap[60:])) + 4 + unsafe.Sizeof(pe.FileHeader{})
	directory = optional + directory + (unsafe.Sizeof(pe.DataDirectory{}) * 4)

	hash := sha1.New()
	hash.Write(bootstrap[:optional+checksum])
	hash.Write(bootstrap[optional+subsystem : directory])
	hash.Write(bootstrap[directory+unsafe.Sizeof(pe.DataDirectory{}) : size])

	for _, s := range f.Sections {
		if _, err := io.Copy(hash, s.Open()); err != nil {
			return nil, err
		}
	}

	b, _ := hash.(encoding.BinaryMarshaler).MarshalBinary()
	return b, nil
}

func (o Obfuscator) Deobfuscate(wr io.Writer, rd io.Reader) error {
	header := make([]byte, 67)
	if _, err := io.ReadFull(rd, header); err != nil {
		return err
	}
	if i := header[0]; i != 0 {
		return obfuscateError("invalid magic number in header: " + strconv.Itoa(int(i)) + " != 0")
	}

	_, err := io.Copy(wr, cipher.StreamReader{
		S: o.makeCipher(header),
		R: rd,
	})
	return err
}

func (o Obfuscator) Obfuscate(wr io.Writer, rd io.Reader) error {
	b, err := io.ReadAll(rd)
	if err != nil {
		return err
	}

	header := make([]byte, 3, 67)
	hash := sha512.New()
	hash.Write(b)
	header = hash.Sum(header)
	header[1] = header[3] ^ 'O'
	header[2] = header[4] ^ 'D'
	if _, err := wr.Write(header); err != nil {
		return err
	}

	_, err = cipher.StreamWriter{
		S: o.makeCipher(header),
		W: wr,
	}.Write(b)
	return err
}

func (o Obfuscator) makeCipher(header []byte) cipher.Stream {
	hash := sha1.New()
	hash.(encoding.BinaryUnmarshaler).UnmarshalBinary(o)
	hash.Write(header[19 : 19+16])
	block, _ := aes.NewCipher(hash.Sum(nil)[:16])
	return cipher.NewCTR(block, header[3:3+16])
}
