package pia

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/crypto/secretbox"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	piaprotocol "github.com/mhsanaei/3x-ui/v3/internal/pia"
)

type fakeAuth struct{ token string }

func (f fakeAuth) Authenticate(context.Context, string, []byte) (piaprotocol.Token, error) {
	return piaprotocol.Token{Value: []byte(f.token), ExpiresAt: time.Now().Add(24 * time.Hour)}, nil
}

type fakeCatalog struct{ payload []byte }

func (f fakeCatalog) Fetch(context.Context) (piaprotocol.ServerListSnapshot, error) {
	return piaprotocol.ServerListSnapshot{Payload: f.payload, SchemaHint: "6", SignatureVerified: true}, nil
}

type fakeRegistrar struct{ n int }

func (f *fakeRegistrar) RegisterKey(_ context.Context, server piaprotocol.WireGuardServer, _ string, _ string) (piaprotocol.Registration, error) {
	f.n++
	key := make([]byte, 32)
	key[0] = byte(f.n)
	return piaprotocol.Registration{
		PeerIP:     netip.MustParsePrefix("10.8.0." + itoaOctet(f.n) + "/32"),
		ServerKey:  base64.StdEncoding.EncodeToString(key),
		ServerIP:   server.IP,
		ServerPort: 1337,
		DNSServers: []netip.Addr{netip.MustParseAddr("10.0.0.243")},
	}, nil
}

func itoaOctet(n int) string {
	return []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}[n-1]
}

func setupPIATest(t *testing.T) *Service {
	t.Helper()
	t.Setenv("XUI_PIA_ENABLED", "true")
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })
	var k [secretbox.KeyLen]byte
	k[0] = 9
	kr := &secretbox.Keyring{ActiveID: "k1", Keys: map[string][secretbox.KeyLen]byte{"k1": k}}
	box, err := secretbox.NewCodec(secretbox.ModeRequired, kr)
	if err != nil {
		t.Fatal(err)
	}
	secretbox.Init(box)
	payload := []byte(`{"version":6,"groups":{"wg":[{"name":"wireguard","ports":[1337]}]},"regions":[{"id":"us-east","name":"US East","country":"US","geo":false,"offline":false,"port_forward":true,"servers":{"wg":[{"ip":"198.51.100.10","cn":"useast1"},{"ip":"198.51.100.20","cn":"useast2"},{"ip":"198.51.100.30","cn":"useast3"}]}}]}`)
	return &Service{
		Auth: fakeAuth{token: "tokentokentokentoken12"}, Catalog: fakeCatalog{payload: payload},
		Registrar: &fakeRegistrar{}, Box: box, Now: time.Now,
	}
}

func TestThreeReadyBindingsHaveDistinctKeysAndTags(t *testing.T) {
	svc := setupPIATest(t)
	ctx := context.Background()
	profile, err := svc.CreateProfile("acct")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, profile.UID, "p1234567", []byte("TEST-PIA-PASSWORD-MUST-NOT-LEAK")); err != nil {
		t.Fatal(err)
	}
	hosts := []string{"useast1", "useast2", "useast3"}
	views := make([]*EgressView, 0, 3)
	for i, host := range hosts {
		e, err := svc.CreateEgress(ctx, CreateEgressInput{ProfileUID: profile.UID, Name: "e" + itoaOctet(i+1), RegionID: "us-east", ServerHostname: host})
		if err != nil {
			t.Fatal(err)
		}
		ready, err := svc.Provision(ctx, e.UID)
		if err != nil {
			t.Fatal(err)
		}
		if ready.Status != model.PiaEgressReady || ready.PublicKey == "" || ready.OutboundTag == "" {
			t.Fatalf("egress not ready: %+v", ready)
		}
		views = append(views, ready)
	}
	if views[0].OutboundTag == views[1].OutboundTag || views[1].OutboundTag == views[2].OutboundTag || views[0].PublicKey == views[1].PublicKey {
		t.Fatalf("tags/keys must differ: %+v", views)
	}
	ready, skipped, err := svc.ReadyOutbounds()
	if err != nil || len(skipped) != 0 || len(ready) != 3 {
		t.Fatalf("ready=%d skipped=%v err=%v", len(ready), skipped, err)
	}
	raw, _ := json.Marshal(views)
	if strings.Contains(string(raw), "TEST-PIA-PASSWORD-MUST-NOT-LEAK") || strings.Contains(string(raw), "tokentokentokentoken12") {
		t.Fatalf("secret leaked in views: %s", raw)
	}
}

func TestModeOffRefusesTokenWrite(t *testing.T) {
	svc := setupPIATest(t)
	off, _ := secretbox.NewCodec(secretbox.ModeOff, nil)
	svc.Box = off
	secretbox.Init(off)
	profile, _ := svc.CreateProfile("acct")
	_, err := svc.Authenticate(context.Background(), profile.UID, "p1234567", []byte("password-long-enough"))
	if err == nil || piaprotocol.CodeOf(err) != piaprotocol.CodeEncryptionRequired {
		t.Fatalf("want encryption required, got %v", err)
	}
}

func TestDeleteReferencedEgressConflicts(t *testing.T) {
	svc := setupPIATest(t)
	ctx := context.Background()
	profile, _ := svc.CreateProfile("acct")
	_, _ = svc.Authenticate(ctx, profile.UID, "p1234567", []byte("password-long-enough"))
	e, err := svc.CreateEgress(ctx, CreateEgressInput{ProfileUID: profile.UID, Name: "e1", RegionID: "us-east", ServerHostname: "useast1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Provision(ctx, e.UID); err != nil {
		t.Fatal(err)
	}
	tpl := `{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","outboundTag":"` + e.OutboundTag + `"}]}}`
	if err := database.GetDB().Create(&model.Setting{Key: "xrayTemplateConfig", Value: tpl}).Error; err != nil {
		t.Fatal(err)
	}
	err = svc.DeleteEgress(e.UID, "", false)
	if err == nil || piaprotocol.CodeOf(err) != piaprotocol.CodeDependencyConflict {
		t.Fatalf("want conflict, got %v", err)
	}
	if err := svc.DeleteEgress(e.UID, "direct", false); err != nil {
		t.Fatal(err)
	}
}

func TestCiphertextAADSwapFails(t *testing.T) {
	svc := setupPIATest(t)
	ctx := context.Background()
	a, _ := svc.CreateProfile("a")
	b, _ := svc.CreateProfile("b")
	_, _ = svc.Authenticate(ctx, a.UID, "p1234567", []byte("password-long-enough"))
	pa, _ := svc.profileByUID(a.UID)
	pb, _ := svc.profileByUID(b.UID)
	pb.TokenCiphertext = pa.TokenCiphertext
	pb.AuthStatus = model.PiaAuthValid
	if err := database.GetDB().Save(pb).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := svc.decryptProfileToken(svc.Box, pb); err == nil {
		t.Fatal("AAD swap must fail")
	}
}

func TestDisabledFlagBlocksWrites(t *testing.T) {
	svc := setupPIATest(t)
	t.Setenv("XUI_PIA_ENABLED", "false")
	if _, err := svc.CreateProfile("x"); err == nil || piaprotocol.CodeOf(err) != piaprotocol.CodeDisabled {
		t.Fatalf("want disabled, got %v", err)
	}
}
