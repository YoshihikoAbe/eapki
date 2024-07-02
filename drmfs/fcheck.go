package drmfs

import (
	"bytes"
	"crypto/md5"
	"io"
	"os"
	"path"
	"time"

	"github.com/YoshihikoAbe/avsproperty"
)

var (
	md5NodeName, _  = avsproperty.NewNodeName("dst_md5")
	sizeNodeName, _ = avsproperty.NewNodeName("dst_size")
)

type CheckResult struct {
	Time time.Time

	Broken       []string `json:"broken"`
	Missing      []string `json:"missing"`
	TotalBroken  int      `json:"total_broken"`
	TotalMissing int      `json:"total_missing"`
	TotalFiles   int      `json:"total_files"`
}

func CheckContents(list *avsproperty.Node, root string) (*CheckResult, error) {
	if list.Name().String() != "list" {
		return nil, drmError("invalid root node")
	}

	result := &CheckResult{
		Time:    time.Now(),
		Broken:  []string{},
		Missing: []string{},
	}

	hash := md5.New()
	for _, entry := range list.Children() {
		if !entry.Name().Equals(fileNodeName) {
			continue
		}
		result.TotalFiles++

		pathNode := entry.SearchChildNodeName(pathNodeName)
		md5Node := entry.SearchChildNodeName(md5NodeName)
		sizeNode := entry.SearchChildNodeName(sizeNodeName)
		if pathNode == nil || md5Node == nil || sizeNode == nil {
			return nil, drmError("invalid file node in list")
		}

		filename := pathNode.StringValue()
		rd, err := os.Open(path.Join(root, filename))
		if err != nil {
			result.Missing = append(result.Missing, filename)
			result.TotalMissing++
			continue
		}

		if _, err := io.CopyN(hash, rd, int64(sizeNode.UintValue())); err != nil {
			rd.Close()
			return nil, err
		}
		rd.Close()
		if !bytes.Equal(md5Node.BinaryValue(), hash.Sum(nil)) {
			result.Broken = append(result.Broken, filename)
			result.TotalBroken++
		}
		hash.Reset()
	}

	return result, nil
}
