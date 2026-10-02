package ledger

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSH signatures in the OpenSSH "SSHSIG" format (PROTOCOL.sshsig), the same format
// `ssh-keygen -Y sign` and git's SSH commit signing produce. A ledger signature verifies with:
//
//	ssh-keygen -Y verify -f allowed_signers -I <identity> -n arbiter-ledger -s sig.txt < msg
//
// where msg is the entry_hash as 64 lowercase hex characters with no newline.

// Namespace separates ledger signatures from git commit signatures ("git") made with the same
// key, so one can't be replayed as the other.
const Namespace = "arbiter-ledger"

const (
	sshsigMagic   = "SSHSIG"
	sshsigVersion = 1
	sshsigHash    = "sha512"
	armorBegin    = "-----BEGIN SSH SIGNATURE-----"
	armorEnd      = "-----END SSH SIGNATURE-----"
)

// Signer signs ledger entry hashes.
type Signer interface {
	Sign(message []byte) (string, error) // armored SSHSIG
	PublicKey() ssh.PublicKey
}

// SSHSigner signs with an in-process SSH key (the supervisor key, §8.B).
type SSHSigner struct {
	signer    ssh.Signer
	namespace string
}

// NewSSHSigner wraps an SSH key. Ed25519 is recommended: its signatures are deterministic,
// so the same entry signs to the same bytes on every platform.
func NewSSHSigner(s ssh.Signer) *SSHSigner { return NewSSHSignerNamespace(s, Namespace) }

// NewSSHSignerNamespace is NewSSHSigner for another namespace, e.g. "git" for commit and tag
// signatures (§8.D).
func NewSSHSignerNamespace(s ssh.Signer, namespace string) *SSHSigner {
	return &SSHSigner{signer: s, namespace: namespace}
}

func (s *SSHSigner) PublicKey() ssh.PublicKey { return s.signer.PublicKey() }

func (s *SSHSigner) Sign(message []byte) (string, error) {
	sig, err := s.signer.Sign(rand.Reader, signedData(s.namespace, message))
	if err != nil {
		return "", fmt.Errorf("sshsig: sign: %w", err)
	}
	var blob bytes.Buffer
	blob.WriteString(sshsigMagic)
	_ = binary.Write(&blob, binary.BigEndian, uint32(sshsigVersion))
	writeString(&blob, s.signer.PublicKey().Marshal())
	writeString(&blob, []byte(s.namespace))
	writeString(&blob, nil) // reserved
	writeString(&blob, []byte(sshsigHash))
	writeString(&blob, ssh.Marshal(sig))
	return armor(blob.Bytes()), nil
}

// Sig is a parsed SSHSIG blob.
type Sig struct {
	PublicKey ssh.PublicKey // the key the signature claims; trust it only after checking it elsewhere
	Namespace string
	signature ssh.Signature
	blob      []byte
}

// Armor re-encodes the signature in canonical armor (70-column base64 lines, LF endings, no
// trailing newline), whatever whitespace the parsed text had.
func (s *Sig) Armor() string { return armor(s.blob) }

// ParseSSHSig decodes an armored SSHSIG without verifying it. The embedded public key tells a
// verifier which allowed_signers line to check; it is never trusted on its own.
func ParseSSHSig(armored string) (*Sig, error) {
	blob, err := dearmor(armored)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(blob)
	magic := make([]byte, len(sshsigMagic))
	if _, err := r.Read(magic); err != nil || string(magic) != sshsigMagic {
		return nil, errors.New("sshsig: bad magic")
	}
	var version uint32
	if err := binary.Read(r, binary.BigEndian, &version); err != nil || version != sshsigVersion {
		return nil, fmt.Errorf("sshsig: unsupported version %d", version)
	}
	fields := make([][]byte, 5) // publickey, namespace, reserved, hash_algorithm, signature
	for i := range fields {
		if fields[i], err = readString(r); err != nil {
			return nil, fmt.Errorf("sshsig: truncated signature: %w", err)
		}
	}
	if r.Len() != 0 {
		return nil, errors.New("sshsig: trailing data")
	}
	if string(fields[3]) != sshsigHash {
		return nil, fmt.Errorf("sshsig: hash algorithm %q, want %q", fields[3], sshsigHash)
	}
	pub, err := ssh.ParsePublicKey(fields[0])
	if err != nil {
		return nil, fmt.Errorf("sshsig: bad public key: %w", err)
	}
	sig := &Sig{PublicKey: pub, Namespace: string(fields[1]), blob: blob}
	if err := ssh.Unmarshal(fields[4], &sig.signature); err != nil {
		return nil, fmt.Errorf("sshsig: bad signature blob: %w", err)
	}
	// OpenSSH's sshsig refuses SHA-1 RSA signatures; x/crypto would accept them, and git would
	// then report an object Arbiter accepted as badly signed.
	if sig.signature.Format == ssh.KeyAlgoRSA {
		return nil, errors.New("sshsig: ssh-rsa (SHA-1) signatures are not accepted; use rsa-sha2-256 or rsa-sha2-512")
	}
	return sig, nil
}

// VerifySSHSig checks an armored SSHSIG over message, made by pub in namespace.
func VerifySSHSig(pub ssh.PublicKey, namespace string, message []byte, armored string) error {
	sig, err := ParseSSHSig(armored)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig.PublicKey.Marshal(), pub.Marshal()) {
		return errors.New("sshsig: signed by a different key")
	}
	if sig.Namespace != namespace {
		return fmt.Errorf("sshsig: namespace %q, want %q", sig.Namespace, namespace)
	}
	if err := pub.Verify(signedData(namespace, message), &sig.signature); err != nil {
		return fmt.Errorf("sshsig: %w", err)
	}
	return nil
}

func signedData(namespace string, message []byte) []byte {
	h := sha512.Sum512(message)
	var b bytes.Buffer
	b.WriteString(sshsigMagic)
	writeString(&b, []byte(namespace))
	writeString(&b, nil) // reserved
	writeString(&b, []byte(sshsigHash))
	writeString(&b, h[:])
	return b.Bytes()
}

func writeString(b *bytes.Buffer, s []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.Write(s)
}

func readString(r *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if int64(n) > int64(r.Len()) {
		return nil, errors.New("length exceeds data")
	}
	s := make([]byte, n)
	_, err := r.Read(s)
	return s, err
}

// armor wraps like ssh-keygen: 70-column base64 lines, LF endings, no trailing newline
// (the ledger stores it inside a JSON string).
func armor(blob []byte) string {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(armorBegin)
	for len(enc) > 0 {
		n := min(70, len(enc))
		b.WriteByte('\n')
		b.WriteString(enc[:n])
		enc = enc[n:]
	}
	b.WriteString("\n" + armorEnd)
	return b.String()
}

func dearmor(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if !strings.HasPrefix(s, armorBegin) || !strings.HasSuffix(s, armorEnd) {
		return nil, errors.New("sshsig: missing armor")
	}
	body := strings.Join(strings.Fields(s[len(armorBegin):len(s)-len(armorEnd)]), "")
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("sshsig: bad base64: %w", err)
	}
	return blob, nil
}
