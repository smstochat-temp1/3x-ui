package pia

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

func TestBuildWireGuardOutboundGolden(t *testing.T) {
	priv, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keepalive := 25
	ob, raw, err := BuildWireGuardOutbound(BuildInput{
		Tag: "pia-abcd1234", SecretKey: priv, Address: "10.7.0.2/32",
		PeerPublicKey: peer, EndpointHost: "198.51.100.10", EndpointPort: 1337,
		MTU: 1420, KeepaliveSeconds: &keepalive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ob["protocol"] != "wireguard" || ob["tag"] != "pia-abcd1234" {
		t.Fatalf("identity: %#v", ob)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	settings := parsed["settings"].(map[string]any)
	if settings["noKernelTun"] != true {
		t.Fatalf("noKernelTun: %#v", settings["noKernelTun"])
	}
	addr := settings["address"].([]any)
	if len(addr) != 1 || addr[0] != "10.7.0.2/32" {
		t.Fatalf("address: %#v", addr)
	}
	peer0 := settings["peers"].([]any)[0].(map[string]any)
	ips := peer0["allowedIPs"].([]any)
	if len(ips) != 1 || ips[0] != "0.0.0.0/0" {
		t.Fatalf("allowedIPs: %#v", ips)
	}
	if _, ok := parsed["settings"].(map[string]any)["secretKey"].(string); !ok {
		t.Fatal("secretKey missing")
	}
}

func TestBuildWireGuardOutboundPreservesZeroKeepaliveAndFormatsIPv6(t *testing.T) {
	priv, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	_, raw, err := BuildWireGuardOutbound(BuildInput{
		Tag: "pia-abcd1234", SecretKey: priv, Address: "10.7.0.2/32",
		PeerPublicKey: peer, EndpointHost: "2001:db8::1", EndpointPort: 1337,
		MTU: 1420, KeepaliveSeconds: &zero,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"endpoint":"[2001:db8::1]:1337"`) || !strings.Contains(string(raw), `"keepAlive":0`) {
		t.Fatalf("unexpected WireGuard output: %s", raw)
	}
}

func TestBuildWireGuardOutboundRejectsMissingEndpoint(t *testing.T) {
	priv, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := BuildWireGuardOutbound(BuildInput{
		Tag: "pia-abcd1234", SecretKey: priv, Address: "10.7.0.2/32", PeerPublicKey: peer,
	}); err == nil {
		t.Fatal("expected incomplete endpoint error")
	}
}

func TestPublicOutboundViewOmitsSecrets(t *testing.T) {
	v := PublicOutboundView("uid-1", "pia-x", "US East", "host", "ready")
	raw, _ := json.Marshal(v)
	if jsonContainsSecret(string(raw), "secretKey", "private", "token", "password") {
		t.Fatalf("public view leaked secret field: %s", raw)
	}
}

func jsonContainsSecret(s string, keys ...string) bool {
	var value any
	if json.Unmarshal([]byte(s), &value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(node any) bool {
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				for _, secret := range keys {
					if strings.EqualFold(key, secret) {
						return true
					}
				}
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}
