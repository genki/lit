# lit

litはFUSEでディレクトリ全体をマウントし、 **state-based CRDT** でノード間状態を同期する「ファイルシステム型」ソースコード管理ツールです。`lit on` で workspace 化し、`lit start` / `lit start <peer>` でノード同士を繋ぐと、切断・再接続を意識せずに状態がマージされます。

## 主な特徴

- **State-based CRDT**: 各 workspace は Automerge/Snapshot で表現され、ネットワーク分断後に再接続しても join だけで整合が取れます。
- **自前のlibfuseデーモン**: `lit on <path>` は `lit-fs`(Rust + libfuse) を起動し、PID/UID 付きでファイル操作を捕捉します。`lit off` で通常ディレクトリへ戻せます。
- **watch list 管理**: `lit add` / `lit rm` で追跡対象を指定し、state export 時に同期するファイル集合を制御します。
- **ノード接続**: `lit start` でローカルノードを起動し、`lit start <peer>` で既存ノードへ参加。フェイルオーバーは考慮せず、再接続時の CRDT マージに任せます。
- **lit sync --workspace**: Workspace slug を指定して snapshot を export/import。`--repeat` で常駐動作 (`lit syncd`) とし、FUSE イベントと同期させられます。

## インストール

```bash
sudo apt-get install -y libfuse3-dev
git clone https://github.com/genki/lit.git
cd lit
. "$HOME/.cargo/env"
make install
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## 代表的なコマンド

| コマンド | 説明 |
| --- | --- |
| `lit on [path]` | ディレクトリを初期化＆マウント（省略時はCWD）。`--vm-config <path>` でVM越しマウントも可 |
| `lit off [path]` | マウント解除し、lower→ターゲットへ最新状態を復元 |
| `lit` | 現在のworkspaceステータス（ON/OFF、watch listなど）を表示 |
| `lit info <path>` | 指定ディレクトリで`lit`を実行したのと同じ情報を表示 |
| `lit ls` | 現ユーザーでON状態のlitワークスペースを一覧 |
| `lit add <path...>` | セッション固有watch listに追加（`--global`で共有） |
| `lit rm <path...>` | セッション固有watch listから除外（`--global`で共有分も削除） |
| `lit drop <path...>` | 指定ファイル/ディレクトリとその履歴を完全削除 |
| `lit tag <name> [message]` | 現在の状態をタグとしてスナップショット化 |
| `lit reset <name>` | 指定タグの状態にワークスペースを巻き戻す |
| `lit tag` | 作成済みタグを時刻/タグ名/メッセージで一覧表示 |
| `lit lock [path] [--timeout SEC] [-m MSG]` | パスをロック（省略時はロック一覧）し、他UID/PID/セッションからの変更を拒否 |
| `lit unlock <path>` | 自分が保有するロックを解除 |
| `lit log [path]` | watch対象（または指定パス）の現在差分をpagerで表示 |
| `lit sync --workspace <path> [--remote <url>]` | 指定 workspace を state-based snapshot で同期 (`--repeat` で常駐) |
| `lit start [peer]` | ローカルノードを起動。引数つきで既存ノードに接続し snapshot を交換 |
| `lit stop` | relay/syncデーモンを停止 |
| `lit version` | CLIのバージョン情報を表示 |
| `lit completions <shell>` | bash/zsh/fish などの補完スクリプトを出力 |

`lit log --watch --interval 5`で差分を定期監視したり、`lit sync --workspace ./myapp --remote http://localhost:50051 --repeat 30`で snapshot 同期を常駐化することもできます。

## 基本的なワークフロー

1. `lit on ~/project`でマウント。
2. `cd ~/project`し、追跡したいファイルを`lit add src/main.rs`などで登録。
3. 通常通りエディタやビルドツールで編集。
4. `lit log src/main.rs`で現在差分を確認。
5. 作業を終えたら`lit off ~/project`でアンマウントし、ファイルを通常ディレクトリとして扱える状態に戻す。

## 注意事項

- `lit on`/`lit off`は内部で自前の`lit-fs`デーモン(libfuseベース)を起動/停止します。Linuxでは`libfuse3`と`fusermount3`、macOSではmacFUSEと`umount`/`diskutil umount`が必要です。
- macOS/WindowsでFUSEドライバを導入したくない場合は、Linux VM上で`lit on`を実行しNFS/SMB越しにディレクトリを共有する運用が可能です。`doc/vm-mount.md`と`scripts/lit-vm-mount.sh`を参照してください。CLI側でも`lit on --vm-config <config.json>`（または環境変数`LIT_VM_CONFIG`）で同等の処理を自動化できます。
- `lit sync --workspace <path>` を指定すると、ローカル snapshot (`~/.lit/workspaces/<slug>/state/latest.json`) を生成し、`state/inbox/` に置かれた snapshot を適用します。`--repeat` と組み合わせると常駐デーモン (`lit syncd`) として双方向同期を回せます。
- watch listに登録していないパスは追跡されません。`lit add`で管理したいパスを明示的に追加してください（デフォルトではセッション固有リストに追加されます）。
- `lit log`は`diff`コマンドを利用します。環境によっては`diff`が無い場合があるため、必要に応じてインストールしてください。
- 複数エージェント/シェルで同一UIDを共有する場合は環境変数`LIT_SESSION_ID=<任意のセッション名>`を設定してください。watch list・ロック情報はセッションごとに分離され、PIDが停止した場合のみ別PIDからロック解除できます。

## 開発

```bash
. "$HOME/.cargo/env"
make test   # cargo fmt + cargo test
make install
```

`CARGO_TARGET_DIR` は `~/.cache/lit/target` に固定されており、CLI/Relay双方のビルドキャッシュを共有します。
