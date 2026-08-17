// Package secretbox provides versioned AES-256-GCM encryption with AAD-bound
// records. Node tokens keep the historical AAD `nodes/api_token/%d`.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type Mode int

const (
	ModeOff Mode = iota
	ModeMigration
	ModeRequired
)

const (
	encPrefix = "enc:"
	encScheme = "enc:v1:"
	KeyLen    = 32
	nonceLen  = 12
)

type SecretRef struct {
	Namespace string
	RecordID  string
	Field     string
	LegacyAAD string
}

func (r SecretRef) AAD() []byte {
	if r.LegacyAAD != "" {
		return []byte(r.LegacyAAD)
	}
	return []byte("3x-ui/" + r.Namespace + "/" + r.RecordID + "/" + r.Field)
}

func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return ModeOff, nil
	case "migration":
		return ModeMigration, nil
	case "required":
		return ModeRequired, nil
	default:
		return ModeOff, fmt.Errorf("secretbox: unknown mode %q (want off|migration|required)", s)
	}
}

type Keyring struct {
	ActiveID string
	Keys     map[string][KeyLen]byte
}

func (kr *Keyring) active() ([KeyLen]byte, error) {
	k, ok := kr.Keys[kr.ActiveID]
	if !ok {
		return [KeyLen]byte{}, fmt.Errorf("secretbox: active key %q not in keyring", kr.ActiveID)
	}
	return k, nil
}

type Codec struct {
	mode Mode
	ring *Keyring
}

func NewCodec(mode Mode, ring *Keyring) (*Codec, error) {
	if mode == ModeOff {
		return &Codec{mode: ModeOff}, nil
	}
	if ring == nil || len(ring.Keys) == 0 {
		return nil, errors.New("secretbox: encryption mode requires a key, but none was loaded")
	}
	if _, err := ring.active(); err != nil {
		return nil, err
	}
	return &Codec{mode: mode, ring: ring}, nil
}

func (c *Codec) Enabled() bool { return c.mode != ModeOff }

func (c *Codec) Mode() Mode { return c.mode }

func IsEncrypted(stored string) bool { return strings.HasPrefix(stored, encPrefix) }

func (c *Codec) Encrypt(ref SecretRef, plaintext []byte) (string, error) {
	if c.mode == ModeOff {
		return "", errors.New("secretbox: refusing plaintext write while encryption is off")
	}
	if len(plaintext) == 0 {
		return "", nil
	}
	stored := string(plaintext)
	if IsEncrypted(stored) {
		if _, err := c.Decrypt(ref, stored); err != nil {
			return "", fmt.Errorf("secretbox: refusing to store undecryptable ciphertext: %w", err)
		}
		return stored, nil
	}
	key, err := c.ring.active()
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, ref.AAD())
	blob := append(nonce, ct...)
	return encScheme + c.ring.ActiveID + ":" + base64.RawURLEncoding.EncodeToString(blob), nil
}

func (c *Codec) Decrypt(ref SecretRef, ciphertext string) ([]byte, error) {
	if c.mode == ModeOff {
		return nil, errors.New("secretbox: encrypted value encountered but encryption is disabled")
	}
	if !IsEncrypted(ciphertext) {
		return nil, errors.New("secretbox: expected ciphertext")
	}
	rest, ok := strings.CutPrefix(ciphertext, encScheme)
	if !ok {
		return nil, fmt.Errorf("secretbox: unsupported ciphertext scheme in %q", firstN(ciphertext, 12))
	}
	keyID, b64, ok := strings.Cut(rest, ":")
	if !ok || keyID == "" {
		return nil, errors.New("secretbox: malformed ciphertext (missing key id)")
	}
	if c.ring == nil {
		return nil, errors.New("secretbox: encrypted value encountered but encryption is disabled (no key)")
	}
	key, ok := c.ring.Keys[keyID]
	if !ok {
		return nil, fmt.Errorf("secretbox: no key %q in keyring", keyID)
	}
	blob, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("secretbox: base64 decode: %w", err)
	}
	if len(blob) < nonceLen {
		return nil, errors.New("secretbox: ciphertext too short")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, blob[:nonceLen], blob[nonceLen:], ref.AAD())
	if err != nil {
		return nil, fmt.Errorf("secretbox: authentication failed: %w", err)
	}
	return pt, nil
}

func (c *Codec) ActiveKeyID() string {
	if c.ring == nil {
		return ""
	}
	return c.ring.ActiveID
}

var (
	mu      sync.RWMutex
	current *Codec
)

func Init(c *Codec) {
	mu.Lock()
	defer mu.Unlock()
	current = c
}

func Active() *Codec {
	mu.RLock()
	c := current
	mu.RUnlock()
	if c == nil {
		off, _ := NewCodec(ModeOff, nil)
		return off
	}
	return c
}

func (c *Codec) EncryptedWithActive(stored string) bool {
	if c.ring == nil || !IsEncrypted(stored) {
		return false
	}
	rest, ok := strings.CutPrefix(stored, encScheme)
	if !ok {
		return false
	}
	keyID, _, ok := strings.Cut(rest, ":")
	return ok && keyID == c.ring.ActiveID
}

func newGCM(key [KeyLen]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
