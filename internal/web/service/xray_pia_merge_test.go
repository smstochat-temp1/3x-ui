package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/pia"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func TestAppendGeneratedOutboundsAndApplyBlock(t *testing.T) {
	cfg := &xray.Config{OutboundConfigs: json_util.RawMessage(`[{"tag":"direct","protocol":"freedom"}]`)}
	if err := appendGeneratedOutbounds(cfg, []any{map[string]any{"tag": "pia-abcd1234", "protocol": "wireguard"}}); err != nil {
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
