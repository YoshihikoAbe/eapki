package drmfs

import (
	"bytes"
	"io"
	"log"
	"os"
	"path"

	"github.com/YoshihikoAbe/avsproperty"
	"github.com/YoshihikoAbe/eapki/keyring"
)

var (
	dirNodeName, _  = avsproperty.NewNodeName("dir")
	fileNodeName, _ = avsproperty.NewNodeName("file")
	nameNodeName, _ = avsproperty.NewNodeName("name")

	keyNodeName, _  = avsproperty.NewNodeName("key_idx")
	pathNodeName, _ = avsproperty.NewNodeName("dst_path")
)

type drmError string

func (err drmError) Error() string {
	return "eapki/drmfs: " + string(err)
}

type DrmFile struct {
	io.Reader
	io.Closer
	Path string
}

func Dump(root string, ks keyring.KeySource) (chan DrmFile, error) {
	state := &dumpState{
		root: root,
		ch:   make(chan DrmFile, 2),
	}
	state.obfuscator.Init(ks.ContentsCode())

	if err := state.openKeyring(ks); err != nil {
		return nil, err
	}
	node, err := state.openFileList()
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(state.ch)
		state.dump(node, "")
	}()
	return state.ch, nil
}

type dumpState struct {
	obfuscator PathObfuscator
	keyring    *keyring.Keyring
	root       string
	ch         chan DrmFile
}

func (state *dumpState) dump(node *avsproperty.Node, current string) {
	for _, child := range node.Children() {
		filename := child.AttributeValueNodeName(nameNodeName)
		if len(filename) == 0 {
			log.Println("name attribute not found")
			continue
		}

		if entry := child.Name(); entry.Equals(dirNodeName) {
			// recursively walk directory
			state.dump(child, path.Join(current, filename))
		} else if entry.Equals(fileNodeName) {
			if err := state.dumpFile(child, path.Join(current, filename)); err != nil {
				log.Println(err)
			}
		} else {
			log.Println(filename+":", "invalid file type:", entry)
		}
	}
}

func (state *dumpState) dumpFile(node *avsproperty.Node, realPath string) error {
	var (
		inPath string
		key    uint32
		err    error
	)

	// is the path obfuscated?
	if child := node.SearchChildNodeName(pathNodeName); child != nil {
		if inPath, err = formatHashPath(child.BinaryValue()); err != nil {
			return err
		}
	} else {
		inPath = realPath
	}
	file, err := os.Open(path.Join(state.root, inPath))
	if err != nil {
		log.Println(realPath+":", err)
		return nil
	}

	// is the file encrypted under drmfs?
	if child := node.SearchChildNodeName(keyNodeName); child != nil {
		key = uint32(child.UintValue())
	}
	rd := io.Reader(file)
	if key != 0 {
		if rd, err = state.keyring.MakeReader(file, key); err != nil {
			return err
		}
	}

	state.ch <- DrmFile{
		Reader: rd,
		Closer: file,
		Path:   realPath,
	}
	return nil
}

func (state *dumpState) openKeyring(ks keyring.KeySource) error {
	rd, err := state.readFile("keyring.dat", -1)
	if err != nil {
		return err
	}
	kr, err := keyring.New(rd, ks)
	if err != nil {
		return err
	}

	state.keyring = kr
	return nil
}

func (state *dumpState) openFileList() (*avsproperty.Node, error) {
	rd, err := state.readFile("file.inf", 0)
	if err != nil {
		return nil, err
	}

	prop := &avsproperty.Property{}
	if err := prop.Read(rd); err != nil {
		return nil, err
	}
	root := prop.Root
	if root == nil || root.Name().String() != "fileinfo" {
		return nil, drmError("invalid root node in file list")
	}
	return root, nil
}

func (state *dumpState) readFile(filename string, key int64) (*bytes.Reader, error) {
	f, err := os.Open(path.Join(state.root, state.obfuscator.Obfuscate(filename)))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rd := io.Reader(f)
	if key >= 0 {
		rd, err = state.keyring.MakeReader(f, 0)
		if err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}

	state.ch <- DrmFile{
		Reader: bytes.NewReader(b),
		Closer: io.NopCloser(nil),
		Path:   filename,
	}
	return bytes.NewReader(b), nil
}
