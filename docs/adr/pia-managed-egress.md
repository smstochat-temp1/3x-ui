# ADR: PIA managed WireGuard egress

- Status: accepted
- Date: 2026-08-17

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
6. PIA bindings are local-panel scoped; `PiaBinding.node_id` is reserved
   (`NULL` = local panel).
7. Peer `allowedIPs` is IPv4-only (`0.0.0.0/0`). IPv6 is not claimed as a PIA
   tunnel. Existing routing rules are not auto-rewritten.
8. Secretbox must be `migration` or `required` before a token or WireGuard
   private key is stored. Only ready bindings with decryptable keys are injected
   into Xray.

## Consequences

- Nord/WARP/template outbounds are unchanged.
- Deleting or disabling a referenced PIA tag is rejected until the admin
  replaces the references. Apply failure keeps the running Xray process
  because `GetXrayConfig` errors before `RestartXray` stops it.
