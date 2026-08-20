// Package pia is a standalone PIA WireGuard control-plane client.
//
// Copyright (c) 2026 Masterain. MIT License.
// Adapted from PIA-Wireguard-Config-Generator-GUI (commit 53686fcd).
package pia

import (
	"context"
	"net/netip"
	"time"
)

type Region struct {
	ID             string
	Name           string
	CountryCode    string
	Geo            bool
	PortForwarding bool
	WireGuard      []WireGuardServer
}

type WireGuardServer struct {
	Hostname string
	IP       netip.Addr
}

func (s WireGuardServer) ID() string {
	return s.Hostname
}

type Token struct {
	Value     []byte
	ExpiresAt time.Time
}

func (t *Token) Clear() {
	if t == nil {
		return
	}
	for i := range t.Value {
		t.Value[i] = 0
	}
	t.Value = nil
}

type Registration struct {
	PeerIP     netip.Prefix
	ServerKey  string
	ServerIP   netip.Addr
	ServerPort uint16
	DNSServers []netip.Addr
}

type Authenticator interface {
	Authenticate(ctx context.Context, username string, password []byte) (Token, error)
}

type CatalogSource interface {
	FetchCatalog(ctx context.Context) (CatalogSnapshot, error)
}

type Registrar interface {
	RegisterKey(ctx context.Context, server WireGuardServer, token string, publicKey string) (Registration, error)
}

type CatalogSnapshot struct {
	Payload           []byte
	Schema            string
	SignatureVerified bool
	Regions           []Region
	Digest            string
}
