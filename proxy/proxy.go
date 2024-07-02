package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"

	"github.com/YoshihikoAbe/eapki/dongle"
)

func Listen(address, remote string, account *dongle.Dongle) error {
	if account.Type() != dongle.AccountKey {
		panic("Invalid dongle type")
	}

	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer l.Close()

	state := &listenState{
		remote: remote,
		tls: &tls.Config{
			InsecureSkipVerify: true,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{account.Certificate().Raw},
					PrivateKey:  account,
				},
			},
		},
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("received connection:", conn.RemoteAddr())
		go state.accept(conn)
	}
}

type listenState struct {
	remote string
	tls    *tls.Config
}

func (state *listenState) accept(conn net.Conn) {
	remote, err := tls.Dial("tcp", state.remote, state.tls)
	if err != nil {
		conn.Close()
		log.Println(err)
		return
	}

	log.Println("established connection with remote server:", conn.RemoteAddr(), "->", remote.RemoteAddr())

	go state.transmit(conn, remote)
	go state.transmit(remote, conn)
}

func (state *listenState) transmit(in, out net.Conn) {
	defer in.Close()
	defer out.Close()
	if err := state.doTransmit(in, out); err != nil {
		if err != io.EOF && !errors.Is(err, net.ErrClosed) {
			log.Println(err)
		}
	}
}

func (state *listenState) doTransmit(in, out net.Conn) error {
	b := make([]byte, 8192)
	for {
		n, err := in.Read(b)
		if err != nil {
			return err
		}
		if _, err := out.Write(b[:n]); err != nil {
			return err
		}
	}
}
