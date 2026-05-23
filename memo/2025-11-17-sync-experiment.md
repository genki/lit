# 2025-11-17 lit 同期実験メモ

## 背景
- ホスト(macOS, /Users/takiuchi/project/lit)側に `./tmp/test` リポジトリを新規作成し、Vagrant(Ubuntu 24.04, 192.168.1.22) 側の `~/lit/tmp/test` と `lit-relay` 越しにファイル同期できるか検証する。
- macOS では `fuse-overlayfs` が利用できず `lit on ./tmp/test` が失敗したため、今回は `lit sync --send-file` / `lit blob-fetch` を用いた手動同期で確認した。

## 手順
1. ホストで `mkdir -p tmp/test && cd tmp/test && git init`。`host-note.txt` を作成。
2. `tmp/relay-sync` を用意し、`lit-relay --listen 0.0.0.0:50051 --storage-root tmp/relay-sync` をバックグラウンド起動。
3. ホストから `lit sync --remote http://127.0.0.1:50051 --send-file tmp/test/host-note.txt --blob` を実行。`tmp/relay-sync/blobs/tmp%2Ftest%2Fhost-note.txt/00000000000000000001` が生成された。
4. Vagrant に `ssh vagrant` で接続し、`sudo apt-get install build-essential pkg-config libfuse3-dev fuse-overlayfs`・`rustup`・`make install` を実行して `lit 0.1.0` を導入。
5. Vagrant 側で `lit blob-fetch --remote http://192.168.1.20:50051 --path tmp/test/host-note.txt --version 00000000000000000001 --output ~/lit/tmp/test/host-note.txt` を実行し、ホストから送信したファイルを取得。
6. Vagrant 側で `vagrant-note.txt` を作成し、`lit sync --remote http://192.168.1.20:50051 --send-file tmp/test/vagrant-note.txt --blob` を実行。
7. ホストで `lit blob-fetch --remote http://127.0.0.1:50051 --path tmp/test/vagrant-note.txt --version 00000000000000000001 --output tmp/test/vagrant-note.txt` を実行し、Vagrant のファイルを取得。
8. テスト完了後、`kill $(cat tmp/relay-sync/relay.pid)` でリレーを停止。

## 結果
- `tmp/test/host-note.txt` の内容が Vagrant 側に転送され、`~/lit/tmp/test/host-note.txt` として復元できた。
- Vagrant で作成した `~/lit/tmp/test/vagrant-note.txt` もホストの `tmp/test/vagrant-note.txt` に取得でき、両方向の同期が成立した。
- `lit-relay` の blob 参照はパスごとに `00000000000000000001` 形式のバージョンIDが付与されるため、取得時は `tmp/relay-sync/blobs/...` で確認して指定する。

## 課題・メモ
- macOS で FUSE オーバーレイ (`fuse-overlayfs`) が利用できず `lit on` が動作しないため、必要に応じて Linux 上で `lit on` を実行する、もしくは `lit-fs` をmac対応させる必要がある。
- 今回は `lit sync --send-file`/`blob-fetch` による手動同期だが、今後は Vagrant 側で `lit on ~/lit/tmp/test` を実行し自動CRDT同期まで確認したい。

## 再テスト (バイナリ更新後)
1. ホスト/ Vagrant 双方で最新ソースを `rsync` で同期し、`make install` を再実行（Vagrant 側は事前に `sudo apt-get install protobuf-compiler` を追加）。`lit version` は双方とも `0.1.0` を表示。
2. `tmp/relay-sync` 配下で `lit-relay --listen 0.0.0.0:50051` を再起動。
3. ホストで `tmp/test/host-sync-20251117.txt` を作成し、`lit sync --remote http://127.0.0.1:50051 --send-file ... --blob` を実行。Relay 側に `blobs/tmp%2Ftest%2Fhost-sync-20251117.txt/00000000000000000001` が生成された。
4. Vagrant から `lit blob-fetch --remote http://192.168.1.20:50051 --path tmp/test/host-sync-20251117.txt --version 00000000000000000001 --output ~/lit/tmp/test/host-sync-20251117.txt` を実行し、ホスト作成ファイルを取得。
5. Vagrant で `tmp/test/vagrant-sync-20251117.txt` を作成し、`lit sync --remote http://192.168.1.20:50051 --send-file ... --blob` を実行。Relay に `blobs/tmp%2Ftest%2Fvagrant-sync-20251117.txt/00000000000000000001` が生成。
6. ホストで `lit blob-fetch --remote http://127.0.0.1:50051 --path tmp/test/vagrant-sync-20251117.txt --version 00000000000000000001 --output tmp/test/vagrant-sync-20251117.txt` を実行し、Vagrant 側のファイルを復元。
7. 検証後に `kill $(cat tmp/relay-sync/relay.pid)` でリレーを停止。

### 所感
- `lit on tmp/test` は引き続き macOS 側に FUSE 実装が無いためマウント待機でタイムアウトするが、手動同期（`lit sync`/`blob-fetch`）は新バイナリでも問題なく成立。
- Vagrant 側で `protoc` が未導入だと `make install` が失敗するため、`protobuf-compiler` のインストールを忘れないこと。

## 再テスト (vm-config連携後)
1. ホスト/VM 双方で最新バイナリを `make install` 済み（rsyncでソース同期、Vagrant側で `lit version 0.1.0`）。
2. ホストで `tmp/test/host-sync-20251117b.txt` を作成し、`lit sync --send-file ... --blob` → Relay に `tmp%2Ftest%2Fhost-sync-20251117b.txt/00000000000000000001` が追加。
3. Vagrant で `lit blob-fetch --path tmp/test/host-sync-20251117b.txt --version 00000000000000000001` を実行し、内容を取得。
4. Vagrant では `tmp/test/vagrant-sync-20251117b.txt` を作成して `lit sync --send-file ... --blob` を実行。
5. ホストで `lit blob-fetch --path tmp/test/vagrant-sync-20251117b.txt --version 00000000000000000001` を実行し、Vagrant 生成ファイルを復元。
6. テスト完了後 `kill <lit-relay pid>` でローカルリレーを停止。

### 結果
- 双方向とも blob バージョンID `00000000000000000001` で取得でき、`lit sync` → Relay → `lit blob-fetch` のパイプラインが最新バイナリでも動作することを確認。
- 今回のテストでは macOS 側で FUSE マウントは使わず、VM 連携と手動同期の組み合わせで運用可能であることを再確認。

## 検証: `blob-fetch` なしの自動同期可否
- ホストで `tmp/test/auto-host.txt` を作成し、`lit sync --remote ...`（`--send-file`無し）を実行 → 出力は `heartbeat status` のみで、Vagrant 側で `lit sync` を実行しても `~/lit/tmp/test/auto-host.txt` は生成されず(`ls`で未存在)。
- 逆に Vagrant で `tmp/test/auto-vagrant.txt` を追加し双方 `lit sync` を実行しても、ホスト `tmp/test` にはファイルが現れなかった。
- 現行 `lit sync` 実装は `--send-file` を指定したときのみ Operation を送信し、受信側へファイルを展開する RPC が存在しないため、自動的なファイル同期は未実装であることを確認。

## 追加仕様: `lit sync --workspace`
- `lit sync` に `--workspace <path>` を指定すると、watch list のファイルをハッシュ比較して自動的にアップロードし、`ListRefs` で取得したBlobをローカルworkspaceへダウンロードする処理を追加した。
- ハッシュ情報は `~/.lit/workspaces/<id>/upload-index.json`、リモートバージョンは `blob-index.json` に保存し、次回以降は差分のみを送受信する。
- リレーからのBlob適用は `fetch_blob` RPCを直接呼び出して行い、ファイルは`workspace`配下に書き戻される。これにより `lit sync --workspace <dir> --repeat 30` を起動すると持続的に更新が同期される。

## 追加メモ (state snapshot パイプライン)
- `lit-cli/src/state_sync.rs` を追加し、workspace 全体を `WorkspaceSnapshot` (ファイル+ハッシュ) に変換するロジックを実装。snapshot は `~/.lit/workspaces/<slug>/state/latest.json` へ保存される。
- `state/inbox/` に `*.json` を配置すると `lit sync --workspace` が自動で読み込み、workspace mountpoint へ適用後 `state/applied/` へアーカイブする。
- これにより当面は手動で snapshot ファイルをやり取りしても CvRDT 同期を再現できる。将来的には `lit start` 間のストリームで snapshot ファイルを交換予定。
