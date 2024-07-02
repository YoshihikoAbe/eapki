package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
)

const (
	headerSize        = 168
	entrySize         = 20
	masterSize        = 128
	contentHeaderSize = 30
	kekSize           = 32
	cekSize           = 62
)

type keyringError string

func (e keyringError) Error() string {
	return "eapki/keyring: " + string(e)
}

type keyEntry struct {
	kekOffset uint32
	cekOffset uint32
}

type keyringString struct {
	Size  uint32
	Value [64]byte
}

func (s keyringString) string() string {
	if s.Size > 64 {
		s.Size = 64
	}
	return string(s.Value[:s.Size])
}

type Keyring struct {
	rd io.ReaderAt

	entries []keyEntry
	keks    []byte

	kekOffset uint32
	headSize  uint32

	master  []byte
	code    string
	version string
}

func New(rd io.ReaderAt, ks KeySource) (*Keyring, error) {
	var header struct {
		HeadSize     uint32
		Code         keyringString
		Version      keyringString
		KeyCount     uint32
		_            uint64
		MasterOffset uint32
		MasterSize   uint32
		EakekOffset  uint32
		EakekSize    uint32
	}

	if err := binary.Read(io.NewSectionReader(rd, 0, headerSize), binary.BigEndian, &header); err != nil {
		return nil, err
	}

	if header.MasterSize != masterSize {
		return nil, keyringError("invalid master key size")
	}
	if header.EakekSize != contentHeaderSize {
		return nil, keyringError("invalid eakek header size")
	}
	code := header.Code.string()
	if code != ks.ContentsCode() {
		return nil, keyringError("invalid contents code")
	}

	kr := &Keyring{
		rd: rd,

		entries: make([]keyEntry, header.KeyCount),
		keks:    make([]byte, header.KeyCount*kekSize),

		headSize: header.HeadSize,

		code:    code,
		version: header.Version.string(),
	}

	/*
	 */

	entries := make([]byte, entrySize*header.KeyCount)
	if _, err := rd.ReadAt(entries, headerSize); err != nil {
		return nil, err
	}

	for i := range kr.entries {
		entry := &kr.entries[i]
		entry.kekOffset = binary.BigEndian.Uint32(entries)
		if binary.BigEndian.Uint32(entries[4:]) != kekSize {
			return nil, keyringError("invalid kek size")
		}
		entry.cekOffset = binary.BigEndian.Uint32(entries[8:])
		if binary.BigEndian.Uint32(entries[16:]) != cekSize {
			return nil, keyringError("invalid cek size")
		}
		entries = entries[entrySize:]
	}

	/*
	 */

	master := make([]byte, masterSize)
	if _, err := rd.ReadAt(master, int64(header.MasterOffset)+152); err != nil {
		return nil, err
	}
	master, err := ks.DecryptKey(master)
	if err != nil {
		return nil, err
	}
	kr.master = master

	/*
	 */

	eakekOffset := header.EakekOffset + 160
	eakek, err := kr.makeContentReader(io.NewSectionReader(rd, int64(eakekOffset), int64(contentHeaderSize+len(kr.keks))), master)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(eakek, kr.keks); err != nil {
		return nil, err
	}
	kr.kekOffset = eakekOffset + contentHeaderSize

	/*
	 */

	return kr, nil
}

func (kr *Keyring) MakeReader(rd io.Reader, key uint32) (io.Reader, error) {
	if key > uint32(len(kr.entries)) {
		return nil, keyringError("key not found")
	}
	entry := kr.entries[key]

	ko := (entry.kekOffset + headerSize + entrySize*key) - kr.kekOffset
	if int64(ko)+kekSize > int64(len(kr.keks)) {
		return nil, keyringError("invalid kek offset")
	}
	kek := kr.keks[ko : ko+kekSize]

	crd, err := kr.makeContentReader(io.NewSectionReader(kr.rd, int64(kr.headSize+entry.cekOffset), cekSize), kek)
	if err != nil {
		return nil, err
	}
	cek := make([]byte, cekSize-contentHeaderSize)
	if _, err := io.ReadFull(crd, cek); err != nil {
		return nil, err
	}

	return kr.makeContentReader(rd, cek)
}

func (kr *Keyring) MasterKey() []byte {
	return kr.master
}

func (kr *Keyring) ContentsCode() string {
	return kr.code
}

func (kr *Keyring) Version() string {
	return kr.version
}

func (kr *Keyring) makeContentReader(rd io.Reader, key []byte) (io.Reader, error) {
	header := make([]byte, contentHeaderSize)
	if _, err := io.ReadFull(rd, header); err != nil {
		return nil, err
	}

	if header[0] != 6 || header[1] != 3 {
		return nil, keyringError("invalid encrypted file header")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamReader{S: cipher.NewCTR(block, header[14:]), R: rd}, nil
}
