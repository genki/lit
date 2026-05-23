# 2025-11-17 spec/TODOレビュー

## spec.md確認メモ
- スナップショットベースのCRDT同期が唯一の前提。`lit-fs`/`lit-cli`/`lit-relay`の役割とワークスペースslug運用を再確認。
- リレーAPIはPublishSnapshot/FetchSnapshot/ListWorkspacesのみ。`~/.lit/workspaces/<slug>/state/{latest.json,inbox,applied}`の構造を維持。
- `lit start`のgRPCストリームは未着手（TODO）。mac/Win対応のVM/NFSシナリオもスナップショット流儀で扱う。

## TODO.md確認メモ
- Step1: gRPCスナップショットストリーム設計/実装（proto更新、relay側、cli側）。
- Step2: FUSE closeイベントでのスナップショット生成トリガ、バッファ処理。
- Step3: リモートスナップショット検知と自動適用、CLI通知。
- 付随タスク: relay認証/圧縮/クリーンアップ、`lit ls/clone`刷新、旧ヘルパ削除、コンフリクト表示、`lit start`デーモン改善、ドキュメント＆テスト整備、将来拡張（暗号化、重複排除、部分スナップショット）。

## 次の準備方針
- Step1着手前にprotoと`lit-relay`/`lit-cli`のストリーミング実装範囲を洗い出す。
- `lit-fs`のcloseイベントをどこで購読するか（既存hook）を調査リストに追加。
- 自動適用パスでは`state_sync`ユーティリティの拡張が必要なため、テスト方針を整理。
