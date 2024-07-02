package keyring

type KeySource interface {
	ContentsCode() string
	DecryptKey(b []byte) ([]byte, error)
}

type MemoryKeySource struct {
	Code    string `json:"code"`
	Version string `json:"version"`
	Master  []byte `json:"master"`
}

func (ks MemoryKeySource) ContentsCode() string {
	return ks.Code
}

func (ks MemoryKeySource) DecryptKey(b []byte) ([]byte, error) {
	return ks.Master, nil
}
