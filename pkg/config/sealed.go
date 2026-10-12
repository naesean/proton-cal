package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Session encryption: session.json may be sealed under a passphrase the user
// chooses at login. Argon2id stretches the passphrase into an AES-256-GCM
// key; the KDF parameters (incl. salt) are stored beside the ciphertext so a
// later process can re-derive the key from the passphrase alone. Neither the
// passphrase nor the derived key is ever written to disk.

// sealedVersion is the current sealed-format version. A plaintext session.json
// (older versions, or `login --no-passphrase`) has no "sealed" field.
const sealedVersion = 1

// minPassphraseLen guards against trivially brute-forceable passphrases (the
// ciphertext is exposed to offline guessing by anyone who can read the file).
const minPassphraseLen = 8

// ErrSessionLocked is returned when loading a passphrase-protected session
// without a way to prompt for the passphrase (e.g. the MCP server).
var ErrSessionLocked = errors.New("the saved session is passphrase-protected and cannot be unlocked here " +
	"(the MCP server cannot prompt; run `proton-cal login --no-passphrase` to use it)")

// ErrWrongPassphrase is returned when the passphrase does not decrypt the
// saved session.
var ErrWrongPassphrase = errors.New("wrong session passphrase")

// sealedSession is the on-disk shape of an encrypted session.json.
type sealedSession struct {
	Sealed     int       `json:"sealed"`
	KDF        kdfParams `json:"kdf"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
}

// kdfParams are the Argon2id parameters a session key was derived with.
type kdfParams struct {
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
}

func (p kdfParams) equal(o kdfParams) bool {
	return bytes.Equal(p.Salt, o.Salt) && p.Time == o.Time && p.Memory == o.Memory && p.Threads == o.Threads
}

// valid bounds the stored parameters so a corrupt file cannot make key
// derivation allocate unbounded memory.
func (p kdfParams) valid() bool {
	return len(p.Salt) >= 16 && p.Time >= 1 && p.Time <= 16 &&
		p.Memory >= 8*1024 && p.Memory <= 1024*1024 && p.Threads >= 1
}

// newKDFParams returns the default parameters (RFC 9106's second recommended
// Argon2id setting: t=3, 64 MiB, p=4) with a fresh random salt.
func newKDFParams() (kdfParams, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return kdfParams{}, err
	}
	return kdfParams{Salt: salt, Time: 3, Memory: 64 * 1024, Threads: 4}, nil
}

// sessionKey is a derived AES-256 key plus the parameters it came from.
type sessionKey struct {
	kdf kdfParams
	key []byte
}

func deriveKey(passphrase string, p kdfParams) *sessionKey {
	return &sessionKey{kdf: p, key: argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.Memory, p.Threads, 32)}
}

// isSealed reports whether data is a sealed session (vs plaintext JSON).
func isSealed(data []byte) bool {
	var probe struct {
		Sealed int `json:"sealed"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.Sealed != 0
}

func parseSealed(data []byte) (sealedSession, error) {
	var sealed sealedSession
	if err := json.Unmarshal(data, &sealed); err != nil {
		return sealed, fmt.Errorf("parsing session.json: %w", err)
	}
	if sealed.Sealed != sealedVersion {
		return sealed, fmt.Errorf("session.json: unsupported sealed format version %d", sealed.Sealed)
	}
	if !sealed.KDF.valid() {
		return sealed, errors.New("session.json: invalid key-derivation parameters")
	}
	return sealed, nil
}

func (k *sessionKey) seal(plaintext []byte) ([]byte, error) {
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.MarshalIndent(sealedSession{
		Sealed:     sealedVersion,
		KDF:        k.kdf,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
	}, "", "  ")
}

func (k *sessionKey) open(sealed sealedSession) ([]byte, error) {
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	if len(sealed.Nonce) != aead.NonceSize() {
		return nil, errors.New("session.json: invalid nonce")
	}
	return aead.Open(nil, sealed.Nonce, sealed.Ciphertext, nil)
}

func (k *sessionKey) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
