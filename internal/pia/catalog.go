// Copyright (c) 2026 Masterain. MIT License.
// Adapted from PIA-Wireguard-Config-Generator-GUI (commit 53686fcd).
package pia

import (
	"context"
	"sync"
	"time"
)

type Catalog struct {
	Source   ServerListSource
	CacheTTL time.Duration
	Now      func() time.Time

	mu        sync.Mutex
	cached    []Region
	schema    string
	verified  bool
	fetchedAt time.Time
}

func NewCatalog(source ServerListSource) *Catalog {
	return &Catalog{Source: source, CacheTTL: DefaultCatalogFreshTTL, Now: time.Now}
}

func (c *Catalog) ListRegions(ctx context.Context) ([]Region, string, error) {
	c.mu.Lock()
	age := c.Now().Sub(c.fetchedAt)
	if len(c.cached) > 0 && c.verified && c.CacheTTL > 0 && age >= 0 && age < c.CacheTTL {
		regions, schema := cloneRegions(c.cached), c.schema
		c.mu.Unlock()
		return regions, schema, nil
	}
	c.mu.Unlock()

	snapshot, err := c.Source.Fetch(ctx)
	if err != nil {
		return nil, "", err
	}
	if !snapshot.SignatureVerified {
		return nil, "", NewError(CodeCatalogSignatureInvalid, "The PIA region list was not signature-verified.")
	}
	regions, schema, err := ParseServerList(snapshot.Payload, snapshot.SchemaHint)
	if err != nil {
		return nil, "", err
	}
	c.mu.Lock()
	c.cached = cloneRegions(regions)
	c.schema = schema
	c.verified = true
	c.fetchedAt = c.Now()
	c.mu.Unlock()
	return cloneRegions(regions), schema, nil
}

func (c *Catalog) Invalidate() {
	c.mu.Lock()
	c.cached = nil
	c.schema = ""
	c.verified = false
	c.fetchedAt = time.Time{}
	c.mu.Unlock()
}

func cloneRegions(regions []Region) []Region {
	result := make([]Region, len(regions))
	for i, region := range regions {
		result[i] = region
		result[i].WireGuard = append([]WireGuardServer(nil), region.WireGuard...)
	}
	return result
}
