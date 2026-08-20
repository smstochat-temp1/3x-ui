package database

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestPiaModelsMigrateAndCRUD(t *testing.T) {
	if err := InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseDB() })

	db := GetDB()
	slot := PiaBindingActiveSlotPtr()
	profile := &model.PiaProfile{UID: "p1", Name: "acct", AuthStatus: model.PiaAuthValid, Enabled: true}
	if err := db.Create(profile).Error; err != nil {
		t.Fatal(err)
	}
	egress := &model.PiaEgress{
		UID: "e1", ProfileID: profile.Id, Name: "us", OutboundTag: "pia-abcd1234",
		RegionID: "us-east", Status: model.PiaEgressReady, MTU: 1420, KeepaliveSeconds: 25,
		IPv6Policy: model.PiaIPv6Block, SelectionMode: model.PiaSelectionPinned, Enabled: true,
	}
	if err := db.Create(egress).Error; err != nil {
		t.Fatal(err)
	}
	binding := &model.PiaBinding{
		UID: "b1", EgressID: egress.Id, ScopeKey: model.PiaScopeLocal, ActiveSlot: slot,
		PrivateKeyCiphertext: "enc:v1:k1:not-a-real-blob", PublicKey: "pub", PeerIP: "10.0.0.2/32",
		ServerPublicKey: "spk", ServerIP: "198.51.100.10", ServerHostname: "host.example",
		ServerPort: 1337, Active: true, Generation: 1, State: model.PiaEgressReady,
	}
	if err := db.Create(binding).Error; err != nil {
		t.Fatal(err)
	}
	archived := *binding
	archived.Id = 0
	archived.UID = "b2"
	archived.Active = false
	archived.ActiveSlot = nil
	archived.Generation = 0
	if err := db.Create(&archived).Error; err != nil {
		t.Fatal(err)
	}
	dup := *binding
	dup.Id = 0
	dup.UID = "b3"
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("second active binding for same egress/scope must fail unique constraint")
	}
	snap := &model.PiaCatalogSnapshot{
		PayloadJSON: `{"regions":[]}`, PayloadSHA256: "abc", SignatureVerified: true,
		ParserVersion: model.PiaCatalogParserVersion, RegionCount: 0, ServerCount: 0,
	}
	if err := db.Create(snap).Error; err != nil {
		t.Fatal(err)
	}
	var got model.PiaEgress
	if err := db.Where("outbound_tag = ?", "pia-abcd1234").First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.UID != "e1" {
		t.Fatalf("egress uid=%q", got.UID)
	}
}

func PiaBindingActiveSlotPtr() *int {
	v := model.PiaBindingActiveSlot
	return &v
}
