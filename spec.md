# lit State-based CRDT Snapshot Specification

## 1. Overview
- lit consists of `lit-fs` (FUSE driver), `lit-cli` (agent/CLI), and `lit-relay` (snapshot relay).
- Workspaces are identified by slug (file-system-safe names). Each workspace maintains local state in `~/.lit/workspaces/<slug>`.
- All synchronization happens via **state-based snapshots**. No operation log or blob-specific RPCs exist.

## 2. Snapshot Format
- `WorkspaceSnapshot` (JSON) contains an array of files with `path`, `hash`, `size`, `data`.
- Snapshots are stored under `~/.lit/workspaces/<slug>/state/`:
  - `latest.json`: most recent export.
  - `inbox/`: snapshots fetched from relay / peers awaiting application.
  - `applied/`: snapshots already applied.

## 3. Relay (lit-relay)
- gRPC service provides:
  - `PublishSnapshot(PublishSnapshotRequest)`: client uploads JSON blob; relay stores `snapshot-<version>.json` and updates `metadata.json` (hash, size, timestamp).
  - `FetchSnapshot(FetchSnapshotRequest)`: client retrieves latest snapshot for a slug.
  - `ListWorkspaces(ListWorkspacesRequest)`: returns `(slug, latest_version, updated_at)` for all stored workspaces.
  - `PublishSnapshotStream(stream PublishSnapshotRequest)`: bidirectional stream; clients push snapshots continuously and receive per-version acknowledgements without reopening channels.
  - `SubscribeSnapshots(SubscribeSnapshotsRequest)`: server stream returning `SnapshotEnvelope` events for subscribers whenever a workspace gets a new snapshot (includes workspace, version, bytes, hash, published_at).
- Relay storage layout: `.lit-relay/workspaces/<slug>/` containing snapshot files and metadata.
- No operation streaming, labels, or blob APIs are retained.

## 4. lit CLI Commands
- `lit on [path] [--name slug]`: create workspace slug (default is basename) and mount via `lit-fs`.
- `lit sync --workspace <path> --remote <url> [--repeat N]`: build JSON snapshot from the mounted workspace, PublishSnapshot to relay, immediately FetchSnapshot, drop it into `state/inbox/`, and apply it. Repeat mode runs this loop periodically.
- `lit start [peer]`: start local sync daemon. When `peer`/`--url` is given, the daemon now opens a shared `PublishSnapshotStream` to the relay, watches `state/dirty.flag` for each mounted workspace, and pushes snapshots only after a coalescing window (~2s). In parallel it also subscribes to `SubscribeSnapshots` per workspace and auto-applies incoming snapshots without touching `state/inbox`. Peer-to-peer streaming (without relay) remains future work.
- `lit ls [--remote URL] [--local-only]`: list local slug → mountpoint mappings (including VM mounts) and, unless `--local-only`, query the relay via `ListWorkspaces` to show remote slugs with latest version/timestamp.
- `lit clone <slug> [path] [--remote URL]`: fetch snapshot from relay, materialize it under `path` (default equals slug), then automatically `lit on` that directory using the provided slug so it immediately joins the dirty/Subscribe loops.

## 5. lit-fs Integration
- `lit-fs` captures file events (open/write/close) with PID/UID context and reports to `lit-cli` agent.
- On close, `lit-fs` now writes to `~/.lit/workspaces/<slug>/state/dirty.flag`; `lit-cli` watches the mtime of this file to mark the workspace as `dirty` without invoking blob RPCs.
- Directory operations (mkdir/create/unlink) also touch the same flag immediately so edits outside normal file-close cycles still trigger sync.
- CLI enforces slug hygiene (`[a-z0-9_-]`) when creating workspaces (`lit on --name` or defaults from basename) and persists the slug in `workspace.json`. Internal directories still use hashed paths, but all relay RPCs are keyed by slug.

## 6. Streaming Sync
- `PublishSnapshotStream` is implemented between CLI and relay. The CLI maintains one stream per daemon instance and reuses it to ship snapshots for multiple workspaces without reconnecting.
- `SubscribeSnapshots` now drives automatic state application. For each mounted workspace, `lit start --url ...` maintains a subscription, writes the received snapshot JSON to `state/applied/remote-*.json`, applies it to the mountpoint, and refreshes `state/latest.json`. CLI prints log lines when snapshots are applied or when mounts are offline.
- The sync daemon coalesces dirty events for ~2 seconds before exporting/applying snapshots, ensuring multiple close events produce a single snapshot publication burst per workspace while remote snapshots are applied as soon as the envelope arrives.
- Direct peer-to-peer streaming (without the relay hop) is still on the roadmap; chunking/ACK/backoff policies described earlier remain applicable once peers connect to each other via `lit start <peer>`.

## 7. VM / non-FUSE Scenarios
- macOS/Windows users can run `lit on --vm-config vm.json`, editing via NFS/SMB. State-based snapshots still apply.
- `state/inbox/`/`applied/` directories make manual troubleshooting straightforward even without direct stream.

## 8. Compatibility & Migration
- Legacy interfaces (`lit sync --send-file`, `lit blob-fetch`, etc.) are removed. Existing workspaces must be reinitialized under new slug + snapshot model.
- README and docs reflect new behavior; scripts and memos (vm mount guide, sync experiment) note the snapshot pipeline.

## 9. TODO / Next Steps
- Implement snapshot streaming (publish/subscribe) between peers.
- Hook `lit-fs` close events to coalesce pending snapshots.
- Auto-apply incoming snapshots (without manually writing into inbox).
- Add Auth/compression/retention on relay as needed.
