// Package nodetoken encrypts replayable per-node bearer tokens at rest with
// row-bound AES-GCM and versioned key IDs.
package nodetoken

import (
	"fmt"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/crypto/secretbox"
)

type Mode = secretbox.Mode

const (
	ModeOff       = secretbox.ModeOff
	ModeMigration = secretbox.ModeMigration
	ModeRequired  = secretbox.ModeRequired
	keyLen        = secretbox.KeyLen
	aadKeyFormat  = "nodes/api_token/%d"
)

type (
	Keyring       = secretbox.Keyring
	KeySource     = secretbox.KeySource
	FileKeySource = secretbox.FileKeySource
	EnvKeySource  = secretbox.EnvKeySource
)

func ParseMode(s string) (Mode, error) {
	m, err := secretbox.ParseMode(s)
	if err != nil {
		return ModeOff, fmt.Errorf("nodetoken: unknown NODE_TOKEN_ENCRYPTION %q (want off|migration|required)", s)
	}
	return m, nil
}

func parseKeyring(active string, b64keys map[string]string) (*Keyring, error) {
	return secretbox.ParseKeyring(active, b64keys)
}

type Codec struct {
	box *secretbox.Codec
}

func NewCodec(mode Mode, ring *Keyring) (*Codec, error) {
	box, err := secretbox.NewCodec(mode, ring)
	if err != nil {
		if strings.Contains(err.Error(), "secretbox:") {
			return nil, fmt.Errorf("nodetoken: %s", strings.TrimPrefix(err.Error(), "secretbox: "))
		}
		return nil, err
	}
	return &Codec{box: box}, nil
}

func (c *Codec) Enabled() bool { return c.box.Enabled() }

func (c *Codec) Box() *secretbox.Codec { return c.box }

func nodeRef(nodeID int) secretbox.SecretRef {
	return secretbox.SecretRef{LegacyAAD: fmt.Sprintf(aadKeyFormat, nodeID)}
}

func IsEncrypted(stored string) bool { return secretbox.IsEncrypted(stored) }

func (c *Codec) Encrypt(nodeID int, plaintext string) (string, error) {
	if c.box.Mode() == ModeOff || plaintext == "" {
		return plaintext, nil
	}
	if IsEncrypted(plaintext) {
		if _, err := c.Decrypt(nodeID, plaintext); err != nil {
			return "", fmt.Errorf("nodetoken: refusing to store undecryptable ciphertext: %w", err)
		}
		return plaintext, nil
	}
	enc, err := c.box.Encrypt(nodeRef(nodeID), []byte(plaintext))
	if err != nil {
		return "", err
	}
	return enc, nil
}

func (c *Codec) Decrypt(nodeID int, stored string) (string, error) {
	if c.box.Mode() == ModeOff {
		return stored, nil
	}
	if !IsEncrypted(stored) {
		return stored, nil
	}
	pt, err := c.box.Decrypt(nodeRef(nodeID), stored)
	if err != nil {
		return "", fmt.Errorf("nodetoken: authentication failed for node %d: %w", nodeID, err)
	}
	return string(pt), nil
}

func (c *Codec) ActiveKeyID() string { return c.box.ActiveKeyID() }

func (c *Codec) EncryptedWithActive(stored string) bool {
	return c.box.EncryptedWithActive(stored)
}

var (
	mu      sync.RWMutex
	current *Codec
)

func Init(c *Codec) {
	mu.Lock()
	defer mu.Unlock()
	current = c
	if c != nil {
		secretbox.Init(c.box)
	} else {
		secretbox.Init(nil)
	}
}

func get() *Codec {
	mu.RLock()
	c := current
	mu.RUnlock()
	if c == nil {
		off, _ := NewCodec(ModeOff, nil)
		return off
	}
	return c
}

func Encrypt(nodeID int, plaintext string) (string, error) { return get().Encrypt(nodeID, plaintext) }
func Decrypt(nodeID int, stored string) (string, error)    { return get().Decrypt(nodeID, stored) }
func Enabled() bool                                        { return get().Enabled() }
func Active() *Codec                                       { return get() }
