# lit

litはFUSEベースでディレクトリ全体をマウントし、編集操作をCRDTログとして収集する「git風ファイルシステム型」ソースコード管理ツールです。通常の`git add`ではなく`lit add`/`lit rm`で管理対象を指定し、`lit on`でディレクトリをマウントすると以後の編集が自動的に追跡されます。

## 主な特徴

- **自前のlibfuseデーモン**: `lit on <path>`は`lit-fs`(Rust + libfuse)を起動し、PID/UID付きでファイル操作を捕捉します。`lit off <path>`でアンマウントするとlowerディレクトリへ書き戻して通常ディレクトリとして再利用できます。
- **watch list 管理**: `lit add`で追跡するファイル/ディレクトリを登録、`lit rm`で解除。watch list は`~/.lit/workspaces/<workspace-id>/watch.json`に保存されます。
- **差分確認 / CRDT同期**: `lit log [path]`はwatch listに登録されたパスの現在差分を`diff -u`形式で生成するだけでなく、内部でAutomergeベースのCRDT(`lit-crdt` crate)へ内容を反映し、将来のマージに備えた変更ログも更新します。
- **ステータス表示**: `lit`単体実行でworkspace ID、ON/OFF状態、lower/upper/mountpoint、watch list を確認できます。
- **gRPCリレー**: `lit sync`/`lit blob-fetch`などは`lit-relay`と通信し、CRDT操作やblobバージョンを交換する仕組みを提供します。

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
| `lit on [path]` | ディレクトリを初期化＆マウント（省略時はCWD） |
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
| `lit sync --remote <url>` | gRPCリレーとCRDTログ/スナップショット同期 |
| `lit blob-fetch --path <p> --version <id>` | バージョン化blobを取得 |
| `lit version` | CLIのバージョン情報を表示 |
| `lit completions <shell>` | bash/zsh/fish などの補完スクリプトを出力 |

`lit log --watch --interval 5`で差分を定期監視したり、`lit sync --remote <url> --repeat 30`でリレー同期を自動実行したりといった常駐モードも利用できます。

## 基本的なワークフロー

1. `lit on ~/project`でマウント。
2. `cd ~/project`し、追跡したいファイルを`lit add src/main.rs`などで登録。
3. 通常通りエディタやビルドツールで編集。
4. `lit log src/main.rs`で現在差分を確認。
5. 作業を終えたら`lit off ~/project`でアンマウントし、ファイルを通常ディレクトリとして扱える状態に戻す。

## 注意事項

- `lit on`/`lit off`は内部で自前の`lit-fs`デーモン(libfuseベース)と`fusermount3`を利用します。`libfuse3`がインストールされていることを確認してください。
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
