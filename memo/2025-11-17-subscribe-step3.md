# 2025-11-17 Subscribe Step3 実装メモ

## 概要
- lit-cli の sync デーモンに `RemoteSnapshotManager` を追加し、各workspaceに対して `SubscribeSnapshots` ストリームを張るようにした。
- 受信した `SnapshotEnvelope` は即座に `WorkspaceSnapshot` に復元し、マウントポイントへ適用、`state/latest.json` 更新、さらに `state/applied/remote-<version>.json` に保存することで履歴を残す。
- lit-fs の dirty flag を監視する `DirtyWorkspaceManager` は `discover_active_workspaces()` の結果を共有し、リモート購読タスクも同じ一覧で管理する。

## 実装ポイント
- `state_sync.rs` に `latest_remote_version` / `archive_remote_snapshot` を追加して、Subscribe時の `from_version` 指定と履歴保存を共通化。
- gRPCストリームはエラー時に再接続し、適用失敗時はwarnログを出して再試行。
- `spec.md`/`TODO.md` を更新し、Step3完了＋自動適用仕様を明記。

## 今後
- Subscribeで得た情報を `lit ls` のステータス表示などへ反映させ、behind状態を示せるようにする。
- P2P直接接続やVMテストなど、残りのTODOを順次消化。
