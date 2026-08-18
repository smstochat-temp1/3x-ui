package pia

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	piaprotocol "github.com/mhsanaei/3x-ui/v3/internal/pia"
	"gorm.io/gorm"
)

type Dependency struct {
	Kind  string `json:"kind" example:"routing_rule"`
	Label string `json:"label" example:"rule #3"`
	Field string `json:"field" example:"outboundTag"`
}

func CollectDependencies(tag string) ([]Dependency, error) {
	return collectDependencies(database.GetDB(), tag)
}

func collectDependencies(db *gorm.DB, tag string) ([]Dependency, error) {
	if tag == "" {
		return nil, nil
	}
	var deps []Dependency

	var setting model.Setting
	if err := db.Where("key = ?", "xrayTemplateConfig").First(&setting).Error; err == nil {
		deps = append(deps, scanTemplate(setting.Value, tag)...)
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	var panel model.Setting
	if err := db.Where("key = ?", "panelOutbound").First(&panel).Error; err == nil && panel.Value == tag {
		deps = append(deps, Dependency{Kind: "panel_outbound", Label: "panel", Field: "panelOutbound"})
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	var nodes []model.Node
	if err := db.Where("outbound_tag = ?", tag).Find(&nodes).Error; err != nil {
		return nil, err
	}
	for _, n := range nodes {
		deps = append(deps, Dependency{Kind: "node_egress", Label: n.Name, Field: "outboundTag"})
	}
	var inbounds []model.Inbound
	if err := db.Where("protocol = ?", model.MTProto).Find(&inbounds).Error; err != nil {
		return nil, err
	}
	for _, ib := range inbounds {
		var parsed struct {
			OutboundTag string `json:"outboundTag"`
		}
		if json.Unmarshal([]byte(ib.Settings), &parsed) == nil && parsed.OutboundTag == tag {
			deps = append(deps, Dependency{Kind: "mtproto_egress", Label: ib.Tag, Field: "outboundTag"})
		}
	}
	return deps, nil
}

func scanTemplate(raw, tag string) []Dependency {
	var cfg map[string]any
	if json.Unmarshal([]byte(raw), &cfg) != nil {
		return nil
	}
	var deps []Dependency
	routing, _ := cfg["routing"].(map[string]any)
	if routing != nil {
		if rules, ok := routing["rules"].([]any); ok {
			for i, r := range rules {
				rm, _ := r.(map[string]any)
				field := ""
				switch {
				case strField(rm, "outboundTag") == tag:
					field = "outboundTag"
				case strField(rm, "balancerTag") == tag:
					field = "balancerTag"
				}
				if field != "" {
					deps = append(deps, Dependency{Kind: "routing_rule", Label: ruleLabel(rm, i), Field: field})
				}
			}
		}
		if bals, ok := routing["balancers"].([]any); ok {
			for _, b := range bals {
				bm, _ := b.(map[string]any)
				if selectorContains(bm["selector"], tag) {
					deps = append(deps, Dependency{Kind: "balancer", Label: strField(bm, "tag"), Field: "selector"})
				}
			}
		}
	}
	if obs, ok := cfg["observatory"].(map[string]any); ok && selectorContains(obs["subjectSelector"], tag) {
		deps = append(deps, Dependency{Kind: "observatory", Label: "observatory", Field: "subjectSelector"})
	}
	if obs, ok := cfg["burstObservatory"].(map[string]any); ok && selectorContains(obs["subjectSelector"], tag) {
		deps = append(deps, Dependency{Kind: "observatory", Label: "burstObservatory", Field: "subjectSelector"})
	}
	return deps
}

func RewriteOrDeleteDependencies(tag, replacement string, deleteRules bool) error {
	if tag == "" {
		return nil
	}
	if replacement == "" && !deleteRules {
		return piaprotocol.NewError(piaprotocol.CodeInvalidInput, "A replacement outbound tag or deleteRules is required.")
	}
	return rewriteOrDeleteDependencies(database.GetDB(), tag, replacement, deleteRules)
}

func rewriteOrDeleteDependencies(db *gorm.DB, tag, replacement string, deleteRules bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var setting model.Setting
		if err := tx.Where("key = ?", "xrayTemplateConfig").First(&setting).Error; err == nil {
			next, changed := rewriteTemplate(setting.Value, tag, replacement, deleteRules)
			if changed {
				if err := tx.Model(&setting).Update("value", next).Error; err != nil {
					return err
				}
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		value := replacement
		if err := tx.Model(&model.Setting{}).Where("key = ? AND value = ?", "panelOutbound", tag).Update("value", value).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Node{}).Where("outbound_tag = ?", tag).Update("outbound_tag", value).Error; err != nil {
			return err
		}
		var inbounds []model.Inbound
		if err := tx.Where("protocol = ?", model.MTProto).Find(&inbounds).Error; err != nil {
			return err
		}
		for i := range inbounds {
			next, ok := rewriteJSONStringField(inbounds[i].Settings, "outboundTag", tag, value)
			if ok {
				if err := tx.Model(&inbounds[i]).Update("settings", next).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func rewriteTemplate(raw, tag, replacement string, deleteRules bool) (string, bool) {
	var cfg map[string]any
	if json.Unmarshal([]byte(raw), &cfg) != nil {
		return raw, false
	}
	changed := false
	routing, _ := cfg["routing"].(map[string]any)
	if routing != nil {
		removedBalancers := map[string]struct{}{}
		if bals, ok := routing["balancers"].([]any); ok {
			kept := make([]any, 0, len(bals))
			for _, b := range bals {
				bm, ok := b.(map[string]any)
				if !ok {
					kept = append(kept, b)
					continue
				}
				if rewriteSelector(bm, "selector", tag, replacement) {
					changed = true
					if replacement == "" && selectorEmpty(bm["selector"]) {
						removedBalancers[strField(bm, "tag")] = struct{}{}
						continue
					}
				}
				kept = append(kept, bm)
			}
			routing["balancers"] = kept
		}
		if rules, ok := routing["rules"].([]any); ok {
			kept := make([]any, 0, len(rules))
			for _, r := range rules {
				rm, ok := r.(map[string]any)
				if !ok {
					kept = append(kept, r)
					continue
				}
				if strField(rm, "outboundTag") == tag {
					if replacement != "" {
						rm["outboundTag"] = replacement
						kept = append(kept, rm)
						changed = true
						continue
					}
					if deleteRules {
						changed = true
						continue
					}
				}
				balancerTag := strField(rm, "balancerTag")
				if balancerTag == tag {
					if replacement != "" {
						rm["balancerTag"] = replacement
						changed = true
					} else if deleteRules {
						changed = true
						continue
					}
				}
				if _, removed := removedBalancers[balancerTag]; removed {
					changed = true
					continue
				}
				kept = append(kept, rm)
			}
			routing["rules"] = kept
		}
	}
	for _, key := range []string{"observatory", "burstObservatory"} {
		if obs, ok := cfg[key].(map[string]any); ok && rewriteSelector(obs, "subjectSelector", tag, replacement) {
			changed = true
			if replacement == "" && selectorEmpty(obs["subjectSelector"]) {
				delete(cfg, key)
			}
		}
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return raw, false
	}
	return string(out), changed
}

func selectorEmpty(value any) bool {
	selector, ok := value.([]any)
	return ok && len(selector) == 0
}

func rewriteSelector(m map[string]any, field, tag, replacement string) bool {
	sel, ok := m[field].([]any)
	if !ok {
		return false
	}
	next := make([]any, 0, len(sel))
	changed := false
	for _, item := range sel {
		s, _ := item.(string)
		if s == tag {
			changed = true
			if replacement != "" {
				next = append(next, replacement)
			}
			continue
		}
		next = append(next, item)
	}
	if changed {
		m[field] = next
	}
	return changed
}

func rewriteJSONStringField(raw, field, from, to string) (string, bool) {
	var obj map[string]any
	if json.Unmarshal([]byte(raw), &obj) != nil {
		return raw, false
	}
	cur, _ := obj[field].(string)
	if cur != from {
		return raw, false
	}
	obj[field] = to
	out, err := json.Marshal(obj)
	if err != nil {
		return raw, false
	}
	return string(out), true
}

func selectorContains(sel any, tag string) bool {
	arr, ok := sel.([]any)
	if !ok {
		return false
	}
	for _, item := range arr {
		if s, ok := item.(string); ok && s == tag {
			return true
		}
	}
	return false
}

func strField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func ruleLabel(m map[string]any, i int) string {
	if t := strField(m, "ruleTag"); t != "" {
		return t
	}
	return fmt.Sprintf("rule %d", i)
}
