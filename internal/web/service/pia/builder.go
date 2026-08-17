package pia

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

const (
	defaultMTU       = 1420
	defaultKeepalive = 25
)

type BuildInput struct {
	Tag              string
	SecretKey        string
	Address          string
	PeerPublicKey    string
	EndpointHost     string
	EndpointPort     int
	MTU              int
	KeepaliveSeconds int
}

func BuildWireGuardOutbound(in BuildInput) (map[string]any, []byte, error) {
	if strings.TrimSpace(in.Tag) == "" || in.SecretKey == "" || in.PeerPublicKey == "" || in.Address == "" {
		return nil, nil, fmt.Errorf("pia: incomplete wireguard parameters")
	}
	mtu := in.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	ka := in.KeepaliveSeconds
	if ka <= 0 {
		ka = defaultKeepalive
	}
	endpoint := fmt.Sprintf("%s:%d", in.EndpointHost, in.EndpointPort)
	ob := map[string]any{
		"tag":      in.Tag,
		"protocol": "wireguard",
		"settings": map[string]any{
			"secretKey":   in.SecretKey,
			"address":     []string{in.Address},
			"mtu":         mtu,
			"noKernelTun": true,
			"peers": []any{
				map[string]any{
					"publicKey":  in.PeerPublicKey,
					"endpoint":   endpoint,
					"allowedIPs": []string{"0.0.0.0/0"},
					"keepAlive":  ka,
				},
			},
		},
	}
	raw, err := json.Marshal(ob)
	if err != nil {
		return nil, nil, err
	}
	if err := xray.ValidateOutboundConfig(raw); err != nil {
		return nil, nil, err
	}
	return ob, raw, nil
}

func PublicOutboundView(uid, tag, region, hostname, status string) map[string]any {
	return map[string]any{
		"uid":      uid,
		"tag":      tag,
		"protocol": "wireguard",
		"region":   region,
		"server":   hostname,
		"status":   status,
		"managed":  "pia",
	}
}
