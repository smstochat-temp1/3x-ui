package pia

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/crypto/secretbox"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	piaprotocol "github.com/mhsanaei/3x-ui/v3/internal/pia"
)

func TestTamperedCatalogIsRejected(t *testing.T) {
	svc := setupPIATest(t)
	svc.Catalog = fakeCatalog{payload: []byte(`{"version":6,"groups":{},"regions":[{"id":"<script>","name":"x","country":"US","servers":{"wg":[]}}]}`)}
	_, err := svc.ListRegions(context.Background())
	if err == nil {
		t.Fatal("tampered/invalid catalog must fail")
	}
}

func TestMissingKeyringSkipsReadyOutbounds(t *testing.T) {
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
	off, _ := secretbox.NewCodec(secretbox.ModeOff, nil)
	svc.Box = off
	ready, skipped, err := svc.ReadyOutbounds()
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 0 || len(skipped) != 1 {
		t.Fatalf("want skip without keyring, ready=%d skipped=%v", len(ready), skipped)
	}
}

func TestProfileViewDoesNotContainPassword(t *testing.T) {
	svc := setupPIATest(t)
	secret := "TEST-PIA-PASSWORD-MUST-NOT-LEAK"
	profile, _ := svc.CreateProfile("acct")
	view, err := svc.Authenticate(context.Background(), profile.UID, "p1234567", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	raw := view.AccountHint + view.UID + view.Name
	if strings.Contains(raw, secret) {
		t.Fatal("password leaked into profile view")
	}
}

func TestExpiredTokenDoesNotMarkReadyEgressOffline(t *testing.T) {
	svc := setupPIATest(t)
	ctx := context.Background()
	profile, err := svc.CreateProfile("acct")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, profile.UID, "p1234567", []byte("password-long-enough")); err != nil {
		t.Fatal(err)
	}
	e, err := svc.CreateEgress(ctx, CreateEgressInput{ProfileUID: profile.UID, Name: "e1", RegionID: "us-east", ServerHostname: "useast1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Provision(ctx, e.UID); err != nil {
		t.Fatal(err)
	}
	svc.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := svc.RotateKey(ctx, e.UID); err == nil || piaprotocol.CodeOf(err) != piaprotocol.CodeTokenRejected {
		t.Fatalf("want token rejected, got %v", err)
	}
	got, err := svc.GetEgress(e.UID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.PiaEgressReady {
		t.Fatalf("ready binding must stay ready after token expiry, got %s", got.Status)
	}
	ready, skipped, err := svc.ReadyOutbounds()
	if err != nil || len(ready) != 1 || len(skipped) != 0 {
		t.Fatalf("ready=%d skipped=%v err=%v", len(ready), skipped, err)
	}
}

func TestConcurrentRotateAndDelete(t *testing.T) {
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
	var rotateErr, deleteErr error
	done := make(chan struct{})
	go func() {
		_, rotateErr = svc.RotateKey(ctx, e.UID)
		done <- struct{}{}
	}()
	go func() {
		deleteErr = svc.DeleteEgress(e.UID, "", false)
		done <- struct{}{}
	}()
	<-done
	<-done
	if deleteErr != nil {
		t.Fatalf("delete failed: %v", deleteErr)
	}
	if rotateErr != nil && piaprotocol.CodeOf(rotateErr) != piaprotocol.CodeNotFound {
		t.Fatalf("unexpected rotate error: %v", rotateErr)
	}
}

func TestConfigReferencesManagedOutboundTag(t *testing.T) {
	routing := []byte(`{"rules":[{"outboundTag":"pia-deadbeef"}]}`)
	if !ConfigReferencesTag(routing, nil, "pia-deadbeef") {
		t.Fatal("expected reference")
	}
	if ConfigReferencesTag(routing, nil, "pia-other") {
		t.Fatal("unexpected reference")
	}
}
