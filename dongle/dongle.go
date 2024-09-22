package dongle

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log"
	"os"
	"runtime"

	"github.com/miekg/pkcs11"
)

var (
	certTmpl = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	}
	valueTmpl = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}
)

type dongleError string

func (err dongleError) Error() string {
	return "eapki/dongle: " + string(err)
}

type KeyType int

const (
	LicenseKey KeyType = iota
	AccountKey
)

// implements keyring.KeySource, crypto.Decrypter, and crypto.Signer
type Dongle struct {
	typ KeyType

	ctx *pkcs11.Ctx
	sh  pkcs11.SessionHandle

	cert *x509.Certificate
	priv pkcs11.ObjectHandle
}

func Find(typ KeyType) (*Dongle, error) {
	dongle := &Dongle{
		typ: typ,
	}
	if err := dongle.initModule(); err != nil {
		return nil, err
	}
	if err := dongle.find(); err != nil {
		dongle.Close()
		return nil, err
	}
	return dongle, nil
}

func (dongle *Dongle) Type() KeyType {
	return dongle.typ
}

func (dongle *Dongle) Certificate() *x509.Certificate {
	return dongle.cert
}

func (dongle *Dongle) ContentsCode() string {
	if dongle.typ != LicenseKey {
		return ""
	}
	return dongle.cert.Subject.CommonName
}

func (dongle *Dongle) CommonName() string {
	return dongle.cert.Subject.CommonName
}

func (dongle *Dongle) Public() crypto.PublicKey {
	return dongle.cert.PublicKey
}

func (dongle *Dongle) DecryptKey(b []byte) ([]byte, error) {
	return dongle.Decrypt(nil, b, nil)
}

func (dongle *Dongle) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if opts != nil {
		return nil, dongleError("invalid options for Decrypt")
	}

	if err := dongle.ctx.DecryptInit(dongle.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, dongle.priv); err != nil {
		return nil, err
	}
	return dongle.ctx.Decrypt(dongle.sh, msg)
}

func (dongle *Dongle) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var saltLen uint32

	pss, ok := opts.(*rsa.PSSOptions)
	if !ok {
		return nil, dongleError("invalid options for Sign")
	}

	// adapted from https://github.com/ThalesGroup/crypto11/blob/a81014c7c41025fb5533c0c6b1b14bec016be695/rsa.go#L247

	switch pss.SaltLength {
	case rsa.PSSSaltLengthAuto:
		return nil, dongleError("unsupported PSS salt length")
	case rsa.PSSSaltLengthEqualsHash:
		saltLen = uint32(pss.Hash.Size())
	default:
		saltLen = uint32(pss.SaltLength)
	}

	mech, mgf, err := hashToPKCS11(pss.Hash)
	if err != nil {
		return nil, err
	}
	param := binary.LittleEndian.AppendUint32(nil, uint32(mech))
	param = binary.LittleEndian.AppendUint32(param, uint32(mgf))
	param = binary.LittleEndian.AppendUint32(param, saltLen)
	if err := dongle.ctx.SignInit(dongle.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, param)}, dongle.priv); err != nil {
		return nil, err
	}
	return dongle.ctx.Sign(dongle.sh, digest)
}

func (dongle *Dongle) Close() {
	if dongle.sh != 0 {
		dongle.ctx.CloseSession(dongle.sh)
	}
	dongle.ctx.Finalize()
	dongle.ctx.Destroy()
}

func (dongle *Dongle) find() error {
	slots, err := dongle.ctx.GetSlotList(true)
	if err != nil {
		return err
	}

	for _, slot := range slots {
		log.Println("opening session on slot", slot)

		if dongle.sh, err = dongle.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION); err != nil {
			return err
		}
		if err := dongle.initSession(slot); err != nil {
			dongle.ctx.CloseSession(dongle.sh)
			log.Println(err)
			continue
		}

		log.Println("initialized dongle:", dongle.cert.Subject.CommonName)
		return nil
	}
	return dongleError("dongle not found")
}

func (dongle *Dongle) initSession(slot uint) error {
	if err := dongle.findCert(); err != nil {
		return err
	}
	if err := dongle.login(slot); err != nil {
		return err
	}
	return dongle.findPriv()
}

func (dongle *Dongle) login(slot uint) error {
	info, err := dongle.ctx.GetTokenInfo(slot)
	if err != nil {
		return err
	}
	if info.Flags&pkcs11.CKF_USER_PIN_COUNT_LOW != 0 {
		return dongleError("number of remaining login attempts is low")
	}

	pg, err := NewPinGenerator([]byte(info.SerialNumber))
	if err != nil {
		return err
	}
	for i := 0; i < NumberOfPins; i++ {
		if err := dongle.ctx.Login(dongle.sh, pkcs11.CKU_USER, string(pg.Generate())); err == nil {
			return nil
		} else {
			log.Printf("login attempt failed (%d/%d)\n", i+1, NumberOfPins)
		}
	}
	return dongleError("all login attempts failed")
}

func (dongle *Dongle) findPriv() error {
	pub, ok := dongle.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return dongleError("certificate does not contain an RSA public key")
	}

	// search for a private key with the same modulus as the public key
	priv, err := dongle.findObjects([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, pub.N.Bytes()),
	})
	if err != nil {
		return err
	}

	dongle.priv = priv[0]
	return nil
}

func (dongle *Dongle) findCert() error {
	var newest *x509.Certificate

	objs, err := dongle.findObjects(certTmpl)
	if err != nil {
		return err
	}

	// find the newest certificate
	for _, obj := range objs {
		attribs, err := dongle.ctx.GetAttributeValue(dongle.sh, obj, valueTmpl)
		if err != nil {
			return err
		}

		cert, err := x509.ParseCertificate(attribs[0].Value)
		if err != nil {
			return err
		}

		if newest == nil || cert.NotAfter.After(newest.NotAfter) {
			newest = cert
		}
	}

	ou := newest.Subject.OrganizationalUnit
	if len(ou) == 0 {
		return dongleError("certificate missing OU in subject")
	}
	if (dongle.typ == LicenseKey && ou[0] == "e-AMUSEMENT/License") ||
		(dongle.typ == AccountKey && (ou[0] == "e-AMUSEMENT/Game" || ou[0] == "e-AMUSEMENT/Charge")) {
		dongle.cert = newest
		return nil
	}
	return dongleError("invalid certificate for dongle type: " + ou[0])
}

func (dongle *Dongle) findObjects(tmpl []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := dongle.ctx.FindObjectsInit(dongle.sh, tmpl); err != nil {
		return nil, err
	}
	defer dongle.ctx.FindObjectsFinal(dongle.sh)

	objs, _, err := dongle.ctx.FindObjects(dongle.sh, 30)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, dongleError("no objects found")
	}

	return objs, nil
}

func (dongle *Dongle) initModule() error {
	name := getModuleName()
	if dongle.ctx = pkcs11.New(name); dongle.ctx == nil {
		return dongleError(name + ": " + " failed to open module")
	}
	if err := dongle.ctx.Initialize(); err != nil {
		dongle.ctx.Destroy()
		return err
	}
	return nil
}

func getModuleName() (module string) {
	module = os.Getenv("PKCS11_MODULE")
	if module == "" {
		if runtime.GOOS == "windows" {
			module = "eTPkcs11.dll"
		} else if runtime.GOOS == "linux" {
			module = "libeTPkcs11.so"
		} else {
			panic("automatic module detection not supported on this platform")
		}
	}
	return
}

// adapted from https://github.com/ThalesGroup/crypto11/blob/a81014c7c41025fb5533c0c6b1b14bec016be695/rsa.go#L230
func hashToPKCS11(hash crypto.Hash) (mech uint, mgf uint, err error) {
	switch hash {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil
	default:
		return 0, 0, dongleError("invalid hash function")
	}
}
