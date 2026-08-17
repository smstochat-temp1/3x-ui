package pia

import (
	"encoding/json"
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	piaprotocol "github.com/mhsanaei/3x-ui/v3/internal/pia"
)

type Dependency struct {
	Kind  string `json:"kind" example:"routing_rule"`
	Label string `json:"label" example:"rule #3"`
	Field string `json:"field" example:"outboundTag"`
}

func CollectDependencies(tag string) ([]Dependency, error) {
	if tag == "" {
		return nil, nil
	}
	db := database.GetDB()
	var deps []Dependency

	var setting model.Setting
	if err := db.Where("key = ?", "xrayTemplateConfig").First(&setting).Error; err == nil {
		deps = append(deps, scanTemplate(setting.Value, tag)...)
	}
	var panel model.Setting
	if err := db.Where("key = ?", "panelOutbound").First(&panel).Error; err == nil && panel.Value == tag {
		deps = append(deps, Dependency{Kind: "panel_outbound", Label: "panel", Field: "panelOutbound"})
	}
	var nodes []model.Node
	if err := db.Where("outbound_tag = ?", tag).Find(&nodes).Error; err == nil {
		for _, n := range nodes {
			deps = append(deps, Dependency{Kind: "node_egress", Label: n.Name, Field: "outboundTag"})
		}
	}
	var inbounds []model.Inbound
	if err := db.Where("protocol = ?", model.MTProto).Find(&inbounds).Error; err == nil {
		for _, ib := range inbounds {
			var parsed struct {
				OutboundTag string `json:"outboundTag"`
			}
			if json.Unmarshal([]byte(ib.Settings), &parsed) == nil && parsed.OutboundTag == tag {
				deps = append(deps, Dependency{Kind: "mtproto_egress", Label: ib.Tag, Field: "outboundTag"})
			}
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
				if strField(rm, "outboundTag") == tag || strField(rm, "balancerTag") == tag {
					deps = append(deps, Dependency{Kind: "routing_rule", Label: ruleLabel(rm, i), Field: "outboundTag"})
				}
			}
		}
		if bals, ok := routing["balancers"].([]any); ok {
			for i, b := range bals {
				bm, _ := b.(map[string]any)
				if selectorContains(bm["selector"], tag) {
					deps = append(deps, Dependency{Kind: "balancer", Label: strField(bm, "tag"), Field: "selector"})
				}
				_ = i
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
	db := database.GetDB()
	var setting model.Setting
	if err := db.Where("key = ?", "xrayTemplateConfig").First(&setting).Error; err == nil {
		next, changed := rewriteTemplate(setting.Value, tag, replacement, deleteRules)
		if changed {
			if err := db.Model(&setting).Update("value", next).Error; err != nil {
				return err
			}
		}
	}
	if replacement != "" {
		_ = db.Model(&model.Setting{}).Where("key = ? AND value = ?", "panelOutbound", tag).Update("value", replacement).Error
		_ = db.Model(&model.Node{}).Where("outbound_tag = ?", tag).Update("outbound_tag", replacement).Error
		var inbounds []model.Inbound
		if err := db.Where("protocol = ?", model.MTProto).Find(&inbounds).Error; err == nil {
			for i := range inbounds {
				next, ok := rewriteJSONStringField(inbounds[i].Settings, "outboundTag", tag, replacement)
				if ok {
					_ = db.Model(&inbounds[i]).Update("settings", next).Error
				}
			}
		}
	} else if deleteRules {
		_ = db.Model(&model.Setting{}).Where("key = ? AND value = ?", "panelOutbound", tag).Update("value", "").Error
		_ = db.Model(&model.Node{}).Where("outbound_tag = ?", tag).Update("outbound_tag", "").Error
		var inbounds []model.Inbound
		if err := db.Where("protocol = ?", model.MTProto).Find(&inbounds).Error; err == nil {
			for i := range inbounds {
				next, ok := rewriteJSONStringField(inbounds[i].Settings, "outboundTag", tag, "")
				if ok {
					_ = db.Model(&inbounds[i]).Update("settings", next).Error
				}
			}
		}
	}
	return nil
}

func rewriteTemplate(raw, tag, replacement string, deleteRules bool) (string, bool) {
	var cfg map[string]any
	if json.Unmarshal([]byte(raw), &cfg) != nil {
		return raw, false
	}
	changed := false
	routing, _ := cfg["routing"].(map[string]any)
	if routing != nil {
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
				if strField(rm, "balancerTag") == tag && replacement != "" {
					rm["balancerTag"] = replacement
					changed = true
				}
				kept = append(kept, rm)
			}
			routing["rules"] = kept
		}
		if bals, ok := routing["balancers"].([]any); ok {
			for _, b := range bals {
				bm, _ := b.(map[string]any)
				if rewriteSelector(bm, "selector", tag, replacement) {
					changed = true
				}
			}
		}
	}
	if obs, ok := cfg["observatory"].(map[string]any); ok && rewriteSelector(obs, "subjectSelector", tag, replacement) {
		changed = true
	}
	if obs, ok := cfg["burstObservatory"].(map[string]any); ok && rewriteSelector(obs, "subjectSelector", tag, replacement) {
		changed = true
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return raw, false
	}
	return string(out), changed
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
