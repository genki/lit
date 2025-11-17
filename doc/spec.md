# lit 仕様書

## 目的
litはFUSE互換のユーザ空間ファイルシステムとして振る舞い、通常のディレクトリを透過的に監視・管理する。開発者は既存のツールチェーンを変更せずにlitをマウントしたディレクトリ上で作業を行い、全編集履歴を高精度で追跡・復元できる。

## コマンド体系
- すべてのCLIは`lit <subcommand>`形式で提供し、POSIX互換のサブコマンド構成にする。
- サブコマンド実装はRust製CLI(`clap`など)で用意し、常駐デーモンとはUNIXドメインソケット/gRPCで通信する。

| サブコマンド | 主用途 | 主要オプション | 備考 |
| --- | --- | --- | --- |
| `lit on [dir]` | ディレクトリをlit管理下に移行し`lit-fs`をマウント | なし | `dir`省略時はCWD。`lower/upper/work`を`~/.lit/workspaces/<id>/`配下に作成 |
| `lit off [dir]` | FUSEマウントを解除し最新内容をターゲットに戻す | なし | アンマウント後は通常ディレクトリとして扱える |
| `lit` | 現在のステータスを表示 | なし | ON/OFF、workspace ID、watch listを表示 |
| `lit add <path...>` / `lit rm <path...>` | watch listへ追加/削除 | なし | `watch.json`に追跡対象を記録し、`lit log`の対象を制御 |
| `lit drop <path...>` | ファイルと履歴(CRDT/スナップショット)を完全削除 | なし | `lower/upper/mountpoint`から対象を除去 |
| `lit log [path]` | watch対象の差分を`diff -u`形式で表示 | `path`を指定すると単一エントリ | 表示時にAutomergeドキュメントへ反映 |
| `lit tag [name] [message]` | `name`指定時はスナップショット作成、未指定時はタグ一覧 | なし | タグは`tags/<name>/tree`にフルコピー、`meta.json`にメッセージ保存 |
| `lit reset <name>` | 指定タグの状態へロールバック | なし | `upper/lower`をタグのツリーで置き換える |
| `lit lock [path] [--timeout SEC] [-m MSG]` | ロック取得（省略時はロック一覧） | timeoutは秒指定 | ロック情報は`locks.json`に保存され、`lit-fs`がUID/PIDで強制 |
| `lit unlock <path>` | 自分のUIDが保持するロックを解除 | なし | locker PIDが死亡していれば別PIDからでも解除可 |
| `lit sync --remote <url>` | `lit-relay`と操作ログ/Blobを同期 | `--token`, `--send-file`, `--blob` | Operation/BlobをgRPC経由で送信、ACKを受信 |
| `lit blob-fetch --path <p> --version <id>` | RelayからBlobを取得 | `--output` | `lit sync --blob`で保存したバージョンIDを利用 |
| `lit version` | CLIビルドバージョン表示 | なし | `cargo pkg version`を出力 |
| `lit completions <shell>` | シェル補完スクリプトを生成 | bash/zsh/fish/powershell/elvish | `lit completions bash > /etc/bash_completion.d/lit` 等で利用 |

- CLIは`$HOME/.lit`配下にworkspace状態(`workspaces/<id>/`)、ロック(`locks.json`)、watch list、CRDTファイルを保存し、`lit-fs`デーモンを自動起動する。

### ワークスペース管理
- `lit on`は対象ディレクトリの内容を`lower`に退避し、作業コピーを`upper`に複製した上で`lit-fs`(libfuseベースのRustデーモン)を`mountpoint`へアタッチする。`lit-fs`はPID/UIDを取得できるため、操作ログやロック強制に利用できる。
- `lit off`は`fusermount3 -u`でアンマウントし、`upper`の内容をターゲットへ戻す。`lower`はベースラインとして保持され、次回`lit log`で差分を計算する際の参照になる。
- watch listは共有(`watch.json`)とセッション別(`watch/<session>.json`)に分かれており、`lit add/rm`はデフォルトでセッション側を更新する。セッションIDは環境変数`LIT_SESSION_ID`で外部から指定でき、未設定時はCLIが自動生成する。`lit log`は両者の和集合のみを対象に`diff`を生成し、Automergeベースの`lit-crdt`ドキュメントに反映する。

#### セッションIDの扱い
- CLIは起動時に環境変数`LIT_SESSION_ID`を参照し、未設定の場合は`~/.lit/session-id`から既存IDを読み取る。ファイルにもIDが存在しない場合は`default-<UUID>`形式で新規IDを生成し、以後同じ値を再利用する。
- watch listはグローバル(`watch.json`)とセッション別(`watch/<session>.json`)の2階層で管理される。`lit add/rm`はデフォルトでセッション側を更新し、`--global`を付与した場合のみ共通リストを操作する。
- `lit log`や`lit status`は両リストの和集合を表示する。`lit drop`などwatch listを変化させる操作は、該当パスがどちらのリストにあっても削除する。

### タグとロック
- タグは`~/.lit/workspaces/<id>/tags/<name>/tree`にワークスペース全体を複製し、`meta.json`に作成時刻とメッセージを保存する。`lit tag`を引数なしで呼ぶと作成済みタグを時系列で出力し、`lit reset <name>`で任意タグへ復元できる。
- ロック情報は`locks.json`に配列で保存され、各エントリに`path`, `owner_uid`, `owner_pid`, `owner_session`, `message`, `expires_at`を持つ。`lit lock <path>`は同一UIDかつ同一セッション(`LIT_SESSION_ID`)ならPIDの死活を確認して再取得でき、`lit unlock <path>`は元PIDが存在しない場合に同UIDの別PIDから解除できる。`lit-fs`は書き込み系操作(write/mkdir/create/unlink)の前に`locks.json`を読み込み、UID/PIDが一致しない操作をEACCESで拒否しつつメッセージをstderrへ出力する。

## リレー(gRPC)API仕様
- `lit relay`はRust製gRPCサーバで、TLS(mTLS推奨)上にBearerトークン認証(JWT/PAT)を重ねる。CLIは`~/.lit/credentials`に保存したAPIトークンを使用する。
- 主要RPC:
  1. `OpenSession(OpenSessionRequest) -> OpenSessionResponse`
     - クライアントがノードID/ホスト情報/サポートCRDTバージョン/最新ローカルバージョンベクタを送信。RelayはセッションIDとサーバ側ベクタを返し、同期すべき操作範囲を通知。
  2. `StreamOps(stream OperationEnvelope) -> stream Ack`
     - 双方向ストリーム。クライアントは操作ログ・スナップショットメタデータ・ラベルを送信し、Relayは処理結果とACK/エラーを逐次返す。未ACK分は再接続時に再送。
  3. `FetchSnapshot(FetchSnapshotRequest) -> stream SnapshotChunk`
     - 指定スナップショットIDまたは`since`パラメータからチャンク化して返却。
  4. `ListRefs(ListRefsRequest) -> ListRefsResponse`
     - ラベル、最新スナップショット、blobバージョンIDなどの参照情報を取得。
  5. `Heartbeat(HeartbeatRequest) -> HeartbeatResponse`
     - 長時間接続のヘルスチェック。Relayはタイムアウト時にセッションを閉じる。
- 認証/認可:
  - gRPCハンドシェイク時にTLSを必須化。組織内はmTLS、公開RelayはTLS+Bearerトークンを推奨。
  - RelayはPostgreSQL等でAPIトークン/ノード登録情報を管理し、Push/Pull権限やアクセス可能な名前空間を制御。
- 障害時再接続:
  - クライアントは再接続時に`OpenSession`で前回セッションIDと最後にACKされた操作IDを提示。Relayは欠落操作のみ再送要求して冪等性を維持する。

### Proto定義(抜粋)
```proto
syntax = "proto3";
package lit.relay.v1;

message VersionVector { repeated Entry entries = 1; message Entry { string replica_id = 1; int64 counter = 2; } }
message OpenSessionRequest { string node_id = 1; string host = 2; string crdt_version = 3; VersionVector local_vector = 4; }
message OpenSessionResponse { string session_id = 1; VersionVector relay_vector = 2; repeated string missing_log_ranges = 3; }

message OperationEnvelope {
  string session_id = 1;
  oneof payload {
    Operation op = 2;
    SnapshotMeta snapshot = 3;
    Label label = 4;
  }
  bytes checksum = 5;
}
message Ack { string session_id = 1; uint64 last_applied_op = 2; string error = 3; }

service RelayService {
  rpc OpenSession(OpenSessionRequest) returns (OpenSessionResponse);
  rpc StreamOps(stream OperationEnvelope) returns (stream Ack);
  rpc FetchSnapshot(FetchSnapshotRequest) returns (stream SnapshotChunk);
  rpc ListRefs(ListRefsRequest) returns (ListRefsResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}
```
※詳細protoは`proto/relay.proto`で管理し、`prost`でRustコードを生成する。

## システム要件
- **FUSE互換実装**: ユーザ空間で動作し、POSIXファイル操作(オープン/クローズ/リード/ライト/renameなど)やメタデータ操作(chmod/chown/utimens、ディレクトリ作成/削除、シンボリックリンク/ハードリンク、拡張属性)を余さずフックしてイベントを取得する。
- **マウントターゲット**: 任意の既存ディレクトリで`lit on <path>`を実行すると、内容を`~/.lit/workspaces/<id>/lower/upper`へ退避し、`lit-fs`がFUSEマウントを提供する。アンマウント時(`lit off`)もデータを失わない。
- **履歴記録**: 監視下ファイルに対するすべての編集操作をイベントログに記録。ログにはタイムスタンプ、操作種別、呼び出しコンテキスト(UID/PID)、対象パス、メタデータ差分を含め、任意の時点(ブロックIDやメタデータのロジカルクロック)に再生して状態復元できる。
- **データ分類**: 管理対象ファイルをテキスト(文字列CRDTで内容を追跡)とblob(バイナリ/大容量)に二分し、blobは内容差分を取らずバージョン単位で保管する。拡張子や MIME で自動判別し、手動オーバーライドも可能とする。
- **履歴記録**: 監視下ファイルに対するすべての編集操作をイベントログに記録。ログにはタイムスタンプ、操作種別、呼び出しコンテキスト(UID/PID)、対象パス、メタデータ差分を含め、任意の時点(ブロックIDやメタデータのロジカルクロック)に再生して状態復元できる。
- **CRDT同期**: 他ノードと状態を交換する際はCRDT(例: Logoot、RGAなど)を用いて、同一ファイルへ複数編集者が同時に操作しても競合を自動解決し、終状態が収束する。
- **ローカル/リモート複製**: 編集ログはローカルストレージに永続化され、一定間隔でチェックポイント(スナップショット)を作成。必要に応じてリモートピアへ複製・マージできる。

## コンポーネント構成
1. **Filesystem Adapter**: libfuse等を使いOSからのシステムコールを受け、lit内部イベントに変換。
2. **Operation Logger**: ファイル操作を正規化し、順序付きログとして保存。操作単位で内容差分またはデータブロックを格納。
3. **Snapshot Manager**: 一定間隔または操作数でワーキングツリー全体/ディレクトリ単位のスナップショットを生成し、履歴の圧縮と高速復元を実現。
4. **State Replayer**: 過去の任意ポイントへロールバック/ロールフォワードするためのリプレイ機構。CRDTのロジカル時計とログシーケンス、スナップショットを併用して復元時間を短縮。
5. **CRDT Engine**: 編集操作をCRDT要素にエンコードし、ファイル内容(テキスト)、ファイルツリー構造(rename/move)、メタデータをそれぞれ型付きCRDT(例:文字列にはRGA/Logoot、ツリーにはWOOT/HTree)で管理。他ピアから受け取った操作をコミューテーション可能な形でマージ。
6. **Networking Layer / Relay**: ピア探索とイベント配布を担当。`lit relay`(Rust/gRPC)を経由してpush/pullする集中モードと、SSH+UNIXソケットで直接ピアに接続するP2Pモードを両立。
7. **Storage Layer**: ローカル`.lit`ディレクトリおよびリモートのオブジェクトストアを抽象化し、操作ログ/スナップショット/blob倉庫を分離保存。S3互換ストアやローカルFSへ切り替え可能。

## 主要フロー
### マウント
1. `lit on /path/to/workdir` を実行。
2. CLIが対象ディレクトリ配下のファイルを`lower`に移動し、`lower`をコピーした`upper`を作成する。`lit-fs`が`upper`をバックエンドとしてFUSEマウントする。
3. `watch.json`や`locks.json`などworkspaceメタデータを初期化し、初回スナップショット(ロジカルクロック0)を作成する。

### 編集追跡
1. ユーザがファイルを編集すると、システムコールがAdapterに渡る。
2. Operation Loggerが差分を記録し、テキストとblobを分類。テキストはCRDT Engineが位置ベースCRDTに変換し、blobは変更単位のオブジェクトを丸ごと新バージョンとして保存する。ディレクトリ操作はツリーCRDT、メタデータはLast-Writer-Winsレジスタを利用。
3. ローカルログに追記し、必要ならネットワーク層へブロードキャスト。マウント外で直接書き換えが発生した場合は inotify 等で検知し、FUSEロールバックまたは警告を行う。

## 編集単位とログ構造
1. **低レベルイベント(システムコール単位)**: `read/write/truncate/rename`などFUSEから受け取るすべてのイベントを即時記録。各イベントにはPID/UID/FD/タイムスタンプを付与し、障害復旧の最小データとして扱う。
2. **内部操作バッチ**: 同一PID+FDで閾値時間(例:50ms)以内に発生した低レベルイベントをまとめ、1つの「内部操作」に昇格させる。大量writeをバッチングし、CRDTやblobバージョン更新のトリガーとする。
3. **ユーザー向け編集ブロック**: テキストはCRDT操作(挿入/削除)を論理位置単位でまとめ、`lit log`で閲覧できる人間可読な差分として提示。blobは以下のトリガーで自動的に1バージョンとして確定し、バージョンIDで参照できる。
   - FDの`close(2)`発生時(最優先)
   - `fsync(2)`/`fdatasync(2)`/FUSE `flush`呼び出し時に、直近の書き込みサイズがしきい値を超えていれば「早期確定」
   - 連続書き込み中に一定時間(例:1秒) I/O が途切れた場合のアイドルタイムアウト
   - ユーザーが`lit blob finalize <path>`などの明示コマンドを発行した場合
   任意の範囲に名前を付けたい場合は`lit label`でタグ/コメントを付与する(コミット操作は存在しない)。
4. **区切りトリガー**: ファイルクローズ、一定アイドル時間経過、`lit save`など明示コマンドの実行で内部操作を確定させる。これにより「無意識の編集」も確実に履歴へ残しつつ、履歴の細分化を防ぐ。

### 時点復元
1. 利用者が`lit checkout --timestamp <t>`や`--op-id <id>`で復元ポイントを指定。
2. State Replayerが直近のスナップショットから指定ポイントまでログを再生するか、逆方向に差分を適用して状態を再構築。ロールバック時は未コミット操作を一時退避して再適用する仕組みを提供。

### マージ/同期
1. `lit sync --remote <url>`でgRPCベースの`lit relay`に接続し、操作ログ/スナップショット/ラベル情報をpush/pullする。Relayはステートレスに近く、実体データは背後のオブジェクトストアに配置。
2. P2Pモードでは`lit sync --peer <ssh://host>`としてSSHトンネル越しに相手デーモンへ直接接続し、差分ログを双方向交換する。
3. 受信した操作をCRDT Engineが統合。バージョンベクタやロジカルクロックで既適用操作を判定し、結果状態を再生してローカルツリーへ反映。同じ操作は冪等的に扱われる。

## CRDT設計要件
- **テキストファイル**: 文字列用CRDT(RGA/Logoot)を採用し、改行単位と文字単位の双方を選択できる。大きなファイルではチャンク化して挿入/削除コストを抑える。
- **ファイルツリー**: ディレクトリとrename/moveはトポロジー保持型CRDT(TreeDocなど)で表現し、同名衝突は決定的な命名規則(例:タイムスタンプ付与)で解決。
- **メタデータ**: chmod/chown/タイムスタンプ等はLWWレジスタまたはMin/Maxレジスタで管理し、CRDTが未対応のフィールドはログ順で決定する。
- **バイナリ/巨大ファイル(blob)**: デフォルトでは不可分のblobとして扱い、内容は差分ではなくバージョン単位で保存・取得する。CRDTはメタデータのみ同期し、内容は最新バージョンまたはユーザ指定バージョンを選択。必要ならプラグイン的にカスタムCRDTを差し込める拡張ポイントを提供。
 - **バイナリ/巨大ファイル(blob)**: デフォルトでは不可分のblobとして扱い、内容は差分ではなくバージョン単位で保存・取得する。バージョン確定トリガーは`close`/`fsync`/`flush`/アイドルタイムアウト/明示確定コマンドを組み合わせる。CRDTはメタデータのみ同期し、内容は最新バージョンまたはユーザ指定バージョンを選択。必要ならプラグイン的にカスタムCRDTを差し込める拡張ポイントを提供。

## チェックポイントとガーベジコレクション
- スナップショット生成ポリシー(時間間隔または操作件数閾値)を設定可能にし、復元時間を O(log n) 程度に抑える。
- 古いログは全ピア反映済みであることを確認した上でガーベジコレクションし、必要部分のみ保持。
- チェックポイントはメタデータと内容を分離保存し、部分リストア(特定ディレクトリ/ファイルのみ)にも対応する。
- ローカル`.lit`では「操作ログ(append-only segment)」「スナップショット」「blobオブジェクト」を別ディレクトリに分離し、S3互換ストレージ/MinIO等と同じフォーマットで保存。これによりオンライン/オフライン問わず同じデータ構造で同期可能。
- RelayサーバはPostgreSQL/SQLite等でメタデータ(バージョンベクタ、ラベル、インデックス)を保持し、内容本体はオブジェクトストアへ書き込む。抽象化レイヤによりローカルFS → S3 への移行を容易にする。

## ストレージ抽象とRustプロトタイピング
- Rustで`StorageBackend`トレイトを定義し、`put_object`, `get_object`, `list`, `delete`, `compose_snapshot`などの操作を共通化。実装例:
  - `FsBackend`: ローカル`.lit`配下に保存。POSIXロックで排他し、開発初期から利用。
  - `S3Backend`: AWS S3/MinIO互換APIを使用。`rusoto`/`aws-sdk-rust`で実装し、サーバ/クライアント双方から同一コードを利用。
  - `MemBackend`: テスト用のメモリ実装。CRDT単体テストやCI用に活用。
- 操作ログは`log/<segment-id>.wal`にappend-onlyで書き、スナップショットは`snaps/<snapshot-id>/metadata.json`とチャンクファイルで保存。blobは`objects/<hash-prefix>/<hash>`で内容アドレス化。
- 初期プロトタイプ手順:
  1. Rust crate `lit-storage`を作り、`StorageBackend`トレイトと3実装(Fs/S3/Mem)を追加。
  2. `lit relay`およびCLIがこのcrateを依存し、環境変数や設定でバックエンドを切り替えられるようにする。
  3. `cargo test -p lit-storage`でバックエンドごとの契約テストを実行。S3BackendはMinIOコンテナをCIで起動して統合テストを行う。
- これによりストレージ層を差し替えつつ仕様整合性を保ったまま実装を進められる。

## 非機能要件
- **堅牢性**: 不意のクラッシュ後でもログから復旧できるよう、操作記録はジャーナリングする。
- **性能**: 小さな操作単位でログ化するとI/O負荷が大きいため、バッチングや差分圧縮を行う。高頻度I/Oディレクトリはパススルーモードやライトバックキャッシュを選べるようにし、FUSE起因のレイテンシを抑える。
- **セキュリティ**: ログには機微情報を含むため、暗号化やアクセス制御を検討。
- **監査性**: すべての操作にUID/PID/ホストIDを紐付け、追跡可能にする。

## 今後の課題
- CRDTアルゴリズム選定とバイナリファイル編集への適用方法
- 巨大リポジトリでのログ管理(ガーベジコレクションやチェックポイント)
- ネットワークプロトコル仕様(認証、暗号化、遅延耐性)
