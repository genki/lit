# lit 仕様書 (State-based CRDT)

## 全体像

lit は FUSE (lit-fs) と state-based CRDT (CvRDT) を組み合わせた「ファイルシステム型ソース追跡ツール」である。各ノードは完全に独立して動作し、ネットワーク分断後に再接続しても CRDT のマージで自動的に整合が取れる。

- **Workspace**: `lit on` により任意ディレクトリを slug (ファイル名互換 ID) 付きで管理対象にする。`~/.lit/workspaces/<slug>/` に仮想ファイルシステムのメタ情報と Automerge 文書を保存する。
- **Fuse 層**: lit-fs が open/write/unlink 等のファイル操作を捕捉し、ユーザー ID/PID も含めて lit-agent (CLI デーモン) へ通知する。
- **State-based CRDT**: lit-agent は各ファイル/ディレクトリを Automerge 文書や Blob version map として管理し、`state export` すると workspace 全体のハッシュと差分を得られる。op-log の順序保証は不要で、state snapshot の join だけで整合する。
- **Relay/Peer**: `lit start` でローカル relay を起動し、`lit start <peer-url>` で既存ノードへ接続。ノード数の制限はなく、1 台や 2 台でも使用可。フェイルオーバーは考えない。

## CLI コマンド

| コマンド | 説明 |
| --- | --- |
| `lit on [path] [--name slug]` | `basename(path)` をデフォルト slug として workspace を作成。`--name` で任意指定可。FUSE をマウントし、状態を CvRDT ドキュメントに保存。 |
| `lit off [path|slug]` | マウント解除。state をローカルに flush する。 |
| `lit ls [--remote peer]` | ローカル workspace の ON/OFF/slug を表示し、接続中 peer からも workspace 一覧を取得して表示。 |
| `lit start` | ローカル relay/sync デーモンを起動。 |
| `lit start <peer>` | 既存ノードへ接続し、state snapshot を双方向に交換。 |
| `lit sync --workspace <slug> [--peer <url>] [--repeat N]` | 指定 workspace の state を export し peer へ送付、peer からの state を import。`--repeat` で常駐 (`lit syncd`) に切り替え。 |
| `lit clone <slug> [path] [--peer <url>]` | peer から slug の state snapshot を取得し `path` (デフォルト `./<slug>`) に workspace を復元。 |
| `lit status [path|slug]` | FUSE ON/OFF・CRDT vector・未適用 snapshot などを表示。 |

## Workspace の構造

```
~/.lit/workspaces/myapp/
  workspace.json      # slug, mountpoint, lower/upper
  lower/, upper/, work/
  crdt/
    state.automerge   # Automerge 文書
    vector.json       # CRDT vector clock
  blob-index.json     # 取得済み Blob のバージョン
  upload-index.json   # 送信済みファイルのハッシュ
  vm.json             # VM 経由マウントの場合のみ
```

- slug は `basename(path)` を正規化して生成。`--name` 未指定でもファイル名互換な ID が必ず付く。
- watch list (`lit add/rm`) は `watch/<session>.json` に保存。state export 時に対象ファイル集合として参照する。

## State Export / Import

1. `lit sync --workspace myapp` を実行すると lit-agent が workspace を走査し、ファイルごとのハッシュと内容 (必要に応じて Blob) を含む snapshot (`WorkspaceSnapshot`) を生成する。
2. snapshot は peer へ送られ、peer は自身の snapshot と比較して差分のみ apply する。Automerge 文書は `merge()` で統合され、Blob はハッシュで照合して取得するだけで良い。
3. state は CvRDT なので、どの順序でマージしても同じ結果になる。ネットワーク分断時は各ノードが snapshot を蓄積し、再接続した瞬間に最新 snapshot を交換するだけでよい。

実装上は `~/.lit/workspaces/<slug>/state/` 配下に snapshot を保存する。

- `latest.json`: 直近に export した snapshot。
- `inbox/`: peer から受け取った snapshot を配置するディレクトリ。`lit sync --workspace` 実行時に自動で読み込み、適用後は `applied/` に移動する。
- `applied/`: 適用済み snapshot の保管場所。監査や手動ロールバック用途に使える。

## Relay / Peer

- `lit start` はローカルノードを起動し、特定のポートで peer 接続を待ち受ける。`lit start <peer>` で相手ノードへダイヤルし、その後は Gossip/フルメッシュ的に snapshot を伝播する。
- フェイルオーバーやリーダー選出は実装しない。ノードが落ちたらそのまま offline 扱いで、再起動時に snapshot を交換する。

## VM / 非 FUSE 環境

- macOS や Windows で FUSE が使えない場合は、`lit on --vm-config vm.json` で Linux VM (Vagrant, WSL2 等) 上に workspace を作成し、ホスト側は NFS/SMB でアクセスする。state-based CRDT なので、VM を含む任意ノード構成で同期できる。

## 今後の実装指針

1. **lit-cli**: `state_sync` モジュールを追加し、`WorkspaceSnapshot` の export/import・ハッシュ管理を提供。`lit sync --workspace` に組み込む。
2. **lit-fs**: FUSE イベントを `lit-agent` に通知し、Automerge ドキュメントへ反映するための gRPC API を追加。CvRDT state をいつでも export できるようにする。
3. **lit-relay**: Snapshot の受信/送信を担当するシンプルな peer プロセスとし、ノード数を意識しない構造にする。`lit start` は relay + syncd をまとめて起動し、`lit start <peer>` で接続する。
4. **CLI エクスペリエンス**: `lit ls` / `lit clone` / `lit status` を slug 前提に再設計し、workspace 命名・取得フローを統一する。
