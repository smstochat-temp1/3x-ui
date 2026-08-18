package service

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	piaprotocol "github.com/mhsanaei/3x-ui/v3/internal/pia"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/managedoutbound"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/pia"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestAppendGeneratedOutboundsAndApplyBlock(t *testing.T) {
	cfg := &xray.Config{OutboundConfigs: json_util.RawMessage(`[{"tag":"direct","protocol":"freedom"}]`)}
	if _, err := appendGeneratedOutbounds(cfg, []any{map[string]any{"tag": "pia-abcd1234", "protocol": "wireguard"}}); err != nil {
		t.Fatal(err)
	}
	var obs []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &obs); err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 || obs[1]["tag"] != "pia-abcd1234" {
		t.Fatalf("merge failed: %+v", obs)
	}
	cfg.RouterConfig = json_util.RawMessage(`{"rules":[{"outboundTag":"pia-abcd1234"}]}`)
	if !pia.ConfigReferencesTag(cfg.RouterConfig, nil, "pia-abcd1234") {
		t.Fatal("routing should reference skipped tag")
	}
	if pia.ConfigReferencesTag(cfg.RouterConfig, nil, "missing") {
		t.Fatal("missing tag must not match")
	}
}

type skippedManagedOutboundSource struct{}

func (skippedManagedOutboundSource) Name() string { return "test-skipped" }

func (skippedManagedOutboundSource) Outbounds() ([]any, []string, error) {
	return nil, []string{"pia-deadbeef"}, nil
}

func TestMergeManagedOutboundSourcesReturnsTypedApplyBlock(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })
	managedoutbound.ResetForTest()
	t.Cleanup(managedoutbound.ResetForTest)
	managedoutbound.Register(skippedManagedOutboundSource{})
	cfg := &xray.Config{RouterConfig: json_util.RawMessage(`{"rules":[{"outboundTag":"pia-deadbeef"}]}`)}
	err := mergeManagedOutboundSources(&XrayService{}, cfg)
	if piaprotocol.CodeOf(err) != piaprotocol.CodeApplyBlocked {
		t.Fatalf("got %s, want %s: %v", piaprotocol.CodeOf(err), piaprotocol.CodeApplyBlocked, err)
	}
}

func TestAppendGeneratedOutboundsSkipsDuplicateTag(t *testing.T) {
	cfg := &xray.Config{OutboundConfigs: json_util.RawMessage(`[{"tag":"pia-abcd1234","protocol":"freedom"}]`)}
	duplicates, err := appendGeneratedOutbounds(cfg, []any{map[string]any{"tag": "pia-abcd1234", "protocol": "wireguard"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(duplicates) != 1 || duplicates[0] != "pia-abcd1234" {
		t.Fatalf("unexpected duplicates: %v", duplicates)
	}
	var outbounds []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &outbounds); err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 1 || outbounds[0]["protocol"] != "freedom" {
		t.Fatalf("duplicate generated outbound was not skipped: %+v", outbounds)
	}
}
