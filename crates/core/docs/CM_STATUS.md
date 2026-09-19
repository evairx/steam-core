# CM Status

Reviewed: September 19, 2026.

`steam-core` does not contain a Steam Connection Manager implementation. `SteamUser::connect`,
persona changes, and games-played changes return `SteamError::CmNotImplemented`; they do not open
a socket or report local state as a remote Steam operation.

## Provenance Gate

The public `SteamTracking/Protobufs` repository contains protocol-looking CM material, including
`EMsg` values and client/server protobuf messages. Its README describes automatically tracked dumps
produced with SteamKit's protobuf dumper, and the repository declares the Unlicense. It is not in
Valve's verified `ValveSoftware` GitHub organization. That repository-level declaration does not
establish Valve as the source or grant permission to redistribute Valve-owned protocol definitions,
so these definitions are not copied here.

Valve's verified GitHub organization publishes selected networking projects, but no Valve-controlled,
redistributable source for the exact Steam client CM protobuf set below has been verified for this
crate. Do not treat publicly mirrored protocol definitions as an authorization to redistribute them.

## Required Before CM Work

- A Valve-controlled source or a written redistribution grant for every vendored definition.
- A license record, pinned revision, integrity hash, and attribution notice.
- Verified definitions for `EMsg`, protobuf headers, logon/logoff, client heartbeat, persona state,
  games played, and CM directory responses, plus all transitive imports.
- Contract captures from a dedicated test account covering directory selection, WebSocket framing,
  logon, heartbeat, reconnect, and logoff.
- Fuzz/property coverage for frame lengths, protobuf headers, EMsg dispatch, and reconnect state.

Until that gate is met, the portable `CmTransport` and `CmConnection` traits are only host
boundaries. They do not provide a functional CM client or Kotlin/Android binding.
