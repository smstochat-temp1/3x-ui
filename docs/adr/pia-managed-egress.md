# ADR: PIA WireGuard outbound

- Status: superseded
- Date: 2026-08-17
- Superseded: 2026-08-20

## Decision

PIA WireGuard exits are **template outbounds**, one per distinct server,
authored in the Xray JSON (not a Nord-style singleton).

1. Protocol I/O lives in `internal/pia` (auth, signature-verified server
   list, `/addKey`) with no Gin/GORM/Xray imports.
2. Credentials are stored in the `pia` setting. Signing in exchanges a
   username/password for a token; the password is not stored. Logout
   clears the token only.
3. Adding a server generates a WireGuard key, registers it via `/addKey`,
   and appends a peer (`tag` `pia-<region>-<server>`). The same hostname
   cannot be added twice; a second `/addKey` to that endpoint can invalidate
   the previous peer. Per-row Reset re-registers that hostname in place.
4. Peer `allowedIPs` is IPv4-only (`0.0.0.0/0`). Keepalive is 25s.

The earlier database-managed multi-egress model (profiles, catalog
snapshots, secretbox, runtime injection) is removed.

## Consequences

- WARP/Nord stay unchanged (Nord remains a singleton with a global Reset).
- Delete a PIA outbound from **Xray → Outbounds** (routing cleanup). Reset
  in the PIA modal only renews the WireGuard key.
- PIA does not document a key-list API. Community reports suggest an
  unofficial ~150 concurrent-key cap and idle expiry.
