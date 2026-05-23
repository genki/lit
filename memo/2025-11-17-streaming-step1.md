# 2025-11-17 Snapshot Stream Step1 実装メモ

## 変更概要
- `proto/relay.proto` に `PublishSnapshotStream` / `SubscribeSnapshots` / `SnapshotEnvelope` を追加し、ストリーミングAPIを定義。
- `lit-relay` 側で broadcast channel を管理し、snapshot publish 時に `SubscribeSnapshots` へイベントを流す実装を追加。`PublishSnapshotStream` からの連続uploadもサポート。
- `lit-cli` の sync daemon (`lit start --url ...`) をストリーム前提に置き換え。`SnapshotStreamPublisher` が `mpsc` チャネルで publish リクエストを送り、ackは `tracing` ログに出力。

## 現状課題
- `SubscribeSnapshots` はCLI未利用。Step3の「Mountpoint change detection」で購読し自動適用する予定。
- FUSE closeイベントとの連携 (Step2) 未着手なので、現状はタイマー駆動でワークスペース全体をスナップショット化してストリーム送信している。
- 既存 `lit sync --workspace` は従来通り unary RPC に依存しており、今後整理が必要。

## 次アクション
- Step2: `lit-fs` close通知を CLI に届け、SnapshotStreamPublisher に送る更新を必要時のみ行う設計を検討。
- Step3: `SubscribeSnapshots` 経由で `state/inbox` 相当の経路なしに自動適用し、`lit ls` に反映させる。
