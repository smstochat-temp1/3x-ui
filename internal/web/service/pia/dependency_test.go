package pia

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestRewriteTemplateRemovesEmptySelectorsAndTheirRules(t *testing.T) {
	raw := `{"routing":{"rules":[{"balancerTag":"pool"},{"balancerTag":"pia-old"},{"outboundTag":"pia-old"},{"outboundTag":"direct"}],"balancers":[{"tag":"pool","selector":["pia-old"]}]},"observatory":{"subjectSelector":["pia-old"]},"burstObservatory":{"subjectSelector":["pia-old","direct"]}}`
	next, changed := rewriteTemplate(raw, "pia-old", "", true)
	if !changed {
		t.Fatal("expected template rewrite")
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(next), &cfg); err != nil {
		t.Fatal(err)
	}
	routing := cfg["routing"].(map[string]any)
	if len(routing["balancers"].([]any)) != 0 || len(routing["rules"].([]any)) != 1 {
		t.Fatalf("dangling balancer state remains: %s", next)
	}
	if _, exists := cfg["observatory"]; exists {
		t.Fatalf("empty observatory remains: %s", next)
	}
	burst := cfg["burstObservatory"].(map[string]any)["subjectSelector"].([]any)
	if len(burst) != 1 || burst[0] != "direct" {
		t.Fatalf("unexpected burst selector: %s", next)
	}
}

func TestRewriteDependenciesRollsBackOnUpdateError(t *testing.T) {
	setupPIATest(t)
	original := `{"routing":{"rules":[{"outboundTag":"pia-old"}]}}`
	setting := model.Setting{Key: "xrayTemplateConfig", Value: original}
	if err := database.GetDB().Create(&setting).Error; err != nil {
		t.Fatal(err)
	}
	node := model.Node{Name: "node", OutboundTag: "pia-old"}
	if err := database.GetDB().Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.GetDB().Exec(`CREATE TRIGGER fail_pia_node_update BEFORE UPDATE OF outbound_tag ON nodes BEGIN SELECT RAISE(FAIL, 'blocked'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if err := RewriteOrDeleteDependencies("pia-old", "direct", false); err == nil {
		t.Fatal("expected transactional rewrite error")
	}
	var got model.Setting
	if err := database.GetDB().Where("key = ?", "xrayTemplateConfig").First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.Value != original {
		t.Fatalf("template update was not rolled back: %s", got.Value)
	}
}

func TestCollectDependenciesReturnsDatabaseErrors(t *testing.T) {
	setupPIATest(t)
	if err := database.GetDB().Exec("ALTER TABLE nodes RENAME TO nodes_unavailable").Error; err != nil {
		t.Fatal(err)
	}
	defer database.GetDB().Exec("ALTER TABLE nodes_unavailable RENAME TO nodes")
	if _, err := CollectDependencies("pia-old"); err == nil {
		t.Fatal("expected node query error")
	}
}
