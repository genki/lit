# TODO (State-based CRDT implementation)

## Snapshot stream (step 1)
- [x] Define gRPC streaming protocol between peers (`PublishSnapshotStream`, `SubscribeSnapshots`).
- [x] Update proto + lit-relay to support streaming snapshot delivery.
- [x] Implement lit-cli side stream client to push snapshots automatically.

## FUSE-trigger integration (step 2)
- [x] Emit snapshot-ready events on fuse close.
- [x] Buffer pending snapshots and coalesce before pushing to stream.

## Mountpoint change detection (step 3)
- [x] Detect remote snapshot updates and apply automatically without manual inbox.
- [x] Provide CLI feedback/logging for applied snapshots.

(Previous tasks archived below)

### Relay / Network Layer
- [ ] Implement authentication/authorization for PublishSnapshot / FetchSnapshot requests.
- [ ] Support optional snapshot compression or chunked upload for large workspaces.
- [ ] Add retention/cleanup policy for `snapshot-*.json` files on relay.

### CLI / lit-fs
- [x] Rework `lit ls` and `lit clone` to call the new `ListWorkspaces` RPC and show/create workspace slugs from relay.
- [ ] Remove unused legacy helpers (`mime_string`, blob index helpers) once the new workflow is complete.
- [ ] Add conflict indicators (e.g., show if local slug is behind remote snapshot version).
- [ ] Update `lit start --repeat` daemon to back off on errors and log sync status per workspace.

### Documentation / Testing
- [ ] Provide migration guidance (existing workspaces must be re-initialized under the new snapshot-only model).
- [ ] Expand README/spec with end-to-end example: `lit on`, edit, `lit sync --workspace`, `lit start <peer>`.
- [ ] Create integration tests (host + Vagrant) verifying snapshot upload/download and application.
- [ ] Document snapshot storage layout (`state/latest.json`, `state/inbox/`, `state/applied/`) and manual troubleshooting steps.

### Future Enhancements
- [ ] Optional encryption/signing of snapshot JSON when stored on relay.
- [ ] Deduplication of large file data (blobs) to avoid storing full contents in each snapshot.
- [ ] Watch list–aware partial snapshots to reduce transfer size.
