package secretbox

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testRing(t *testing.T, activeID string, ids ...string) *Keyring {
	t.Helper()
	kr := &Keyring{ActiveID: activeID, Keys: map[string][KeyLen]byte{}}
	for _, id := range ids {
		var k [KeyLen]byte
		for i := range k {
			k[i] = byte(i) + id[len(id)-1]
		}
		kr.Keys[id] = k
	}
	return kr
}

func TestRoundTripAndAAD(t *testing.T) {
	c, err := NewCodec(ModeRequired, testRing(t, "k1", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	ref := SecretRef{Namespace: "pia/profile-token", RecordID: "uid-1", Field: "token"}
	enc, err := c.Encrypt(ref, []byte("s3cret-token"))
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(enc) || !strings.HasPrefix(enc, "enc:v1:k1:") {
		t.Fatalf("unexpected ciphertext form: %q", enc)
	}
	pt, err := c.Decrypt(ref, enc)
	if err != nil || string(pt) != "s3cret-token" {
		t.Fatalf("round-trip mismatch: %q err=%v", pt, err)
	}
	other := ref
	other.RecordID = "uid-2"
	if _, err := c.Decrypt(other, enc); err == nil {
		t.Fatal("AAD record swap must fail")
	}
	other = ref
	other.Field = "private-key"
	if _, err := c.Decrypt(other, enc); err == nil {
		t.Fatal("AAD field swap must fail")
	}
}

func TestDecryptRejectsMalformedCiphertext(t *testing.T) {
	c, err := NewCodec(ModeRequired, testRing(t, "k1", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	ref := SecretRef{Namespace: "n", RecordID: "1", Field: "t"}
	enc, err := c.Encrypt(ref, []byte("tok"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(enc, ":")
	blob, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 1
	tampered := strings.Join([]string{parts[0], parts[1], parts[2], base64.RawURLEncoding.EncodeToString(blob)}, ":")
	cases := map[string]string{
		"unknown key id":     "enc:v1:zz:" + strings.TrimPrefix(enc, "enc:v1:k1:"),
		"unsupported scheme": "enc:v9:k1:AAAA",
		"missing key id":     "enc:v1:AAAA",
		"truncated blob":     "enc:v1:k1:AAAA",
		"tampered body":      tampered,
	}
	for name, ciphertext := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Decrypt(ref, ciphertext); err == nil {
				t.Fatal("expected decryption error")
			}
		})
	}
}

func TestRefusePlaintextModeOff(t *testing.T) {
	c, _ := NewCodec(ModeOff, nil)
	if _, err := c.Encrypt(SecretRef{Namespace: "pia/x", RecordID: "1", Field: "t"}, []byte("tok")); err == nil {
		t.Fatal("ModeOff must refuse PIA plaintext writes")
	}
}

func TestNonceIsRandom(t *testing.T) {
	c, _ := NewCodec(ModeRequired, testRing(t, "k1", "k1"))
	ref := SecretRef{Namespace: "n", RecordID: "1", Field: "t"}
	a, _ := c.Encrypt(ref, []byte("same"))
	b, _ := c.Encrypt(ref, []byte("same"))
	if a == b {
		t.Fatal("nonce reuse")
	}
}

func TestRotation(t *testing.T) {
	c1, _ := NewCodec(ModeRequired, testRing(t, "k1", "k1", "k2"))
	ref := SecretRef{LegacyAAD: "nodes/api_token/3"}
	old, _ := c1.Encrypt(ref, []byte("tok"))
	c, _ := NewCodec(ModeRequired, testRing(t, "k2", "k1", "k2"))
	pt, err := c.Decrypt(ref, old)
	if err != nil || string(pt) != "tok" {
		t.Fatalf("old key must decrypt, got %q err=%v", pt, err)
	}
	neu, _ := c.Encrypt(ref, []byte("tok"))
	if !c.EncryptedWithActive(neu) || c.EncryptedWithActive(old) {
		t.Fatal("rotation active-key tracking failed")
	}
}

func TestFileKeySourceRejectsLoosePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes are not enforced on windows")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "k.json")
	key := make([]byte, KeyLen)
	body, _ := json.Marshal(struct {
		Active string            `json:"active"`
		Keys   map[string]string `json:"keys"`
	}{Active: "k1", Keys: map[string]string{"k1": base64.StdEncoding.EncodeToString(key)}})
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileKeySource{Path: p}).Load(); err == nil {
		t.Fatal("0644 key file must be rejected")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := (FileKeySource{Path: p}).Load()
	if err != nil || kr.ActiveID != "k1" {
		t.Fatalf("0600 key file should load: %+v %v", kr, err)
	}
}

func TestParseKeyringRejectsDelimiter(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, KeyLen))
	if _, err := ParseKeyring("region:k1", map[string]string{"region:k1": key}); err == nil {
		t.Fatal("delimiter in key id must fail")
	}
}
