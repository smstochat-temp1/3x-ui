# ADR: PIA managed WireGuard egress

- Status: accepted
- Date: 2026-08-17
- Baseline: 3x-ui `8cec47a8`, Go 1.26, xray-core `v1.260327.1-0.20260728075948-5ca6f4b7d4dc`

## Decision

PIA WireGuard exits are **database-managed domain objects**, not a Nord-style
singleton outbound authored in the Xray template JSON.

1. Protocol I/O lives in `internal/pia` with no Gin/GORM/Xray imports.
2. Each egress has a stable immutable outbound tag (`pia-<id>`) and its own key.
3. Token and WireGuard private keys are stored only via AES-GCM secretbox
   (the nodetoken keyring). `ModeOff` refuses PIA writes.
4. Ready bindings are merged in `GetXrayConfig` after subscription outbounds
   and before panel/node/mtproto egress injection.
5. The frontend never receives token, password, or private key material.
6. Multi-node fan-out is out of scope for the first ship; `PiaBinding.node_id`
   is reserved (`NULL` = local panel).
7. Peer `allowedIPs` is IPv4-only (`0.0.0.0/0`). IPv6 is not claimed as a PIA
   tunnel. Existing routing rules are not auto-rewritten.

## Feature flag

`XUI_PIA_ENABLED` defaults to `false`. Routes exist so OpenAPI stays in
contract with the router; writes and Xray injection no-op until enabled,
and secretbox must be `migration` or `required` before a token is stored.

## Consequences

- Nord/WARP/template outbounds are unchanged.
- Deleting or disabling a referenced PIA tag is rejected until the admin
  replaces the references. Apply failure keeps the running Xray process
  because `GetXrayConfig` errors before `RestartXray` stops it.
