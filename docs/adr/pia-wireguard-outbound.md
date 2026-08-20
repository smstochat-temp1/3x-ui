# ADR: PIA WireGuard outbounds

- Status: accepted
- Date: 2026-08-20

## Decision

PIA WireGuard peers are ordinary Xray template outbounds. One outbound per
hostname; the panel does not keep a separate egress catalog.

1. Protocol I/O stays in `internal/pia` (auth, signature-verified server list,
   `/addKey`) with no Gin/GORM/Xray imports.
2. Credentials live in the `pia` setting. Login stores a token; the password is
   not stored. Logout clears the token only.
3. Adding a server generates a WireGuard key, registers it via `/addKey`, and
   appends `tag` `pia-<region>-<server>`. The same hostname cannot be added
   twice: a second `/addKey` to that endpoint can invalidate the previous peer.
   Per-row Reset re-registers that hostname in place.
4. Peer `allowedIPs` is IPv4-only (`0.0.0.0/0`). Keepalive is 25s.

## Consequences

- WARP/Nord stay unchanged (Nord remains a singleton with a global Reset).
- Delete a PIA outbound from **Xray → Outbounds** so routing cleanup runs.
- PIA does not document a key-list or delete-key API.
