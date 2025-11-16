# lit 仕様書

## 目的
litはFUSE互換のユーザ空間ファイルシステムとして振る舞い、通常のディレクトリを透過的に監視・管理する。開発者は既存のツールチェーンを変更せずにlitをマウントしたディレクトリ上で作業を行い、全編集履歴を高精度で追跡・復元できる。

## コマンド体系
- すべてのCLIは`lit <subcommand>`形式で提供し、POSIX互換のサブコマンド構成にする。
- サブコマンド実装はRust製CLI(`clap`など)で用意し、常駐デーモンとはUNIXドメインソケット/gRPCで通信する。

| サブコマンド | 主用途 | 主要オプション | 備考 |
| --- | --- | --- | --- |
| `lit mount <dir>` | 指定ディレクトリにlit FSをマウント | `--readonly`, `--pass-through=<glob>` | マウント成功時にデーモンPIDとソケットパスを表示 |
| `lit unmount <dir>` | マウント解除 | `--force` | 事前に保留中ログをフラッシュ |
| `lit status` | 現在のマウント/未同期操作を確認 | `--json`, `--verbose` | 内部操作キューやCRDTレプリカのヘルス情報を表示 |
| `lit log` | ユーザー向け編集ブロック履歴を閲覧 | `--file <path>`, `--since <ts>`, `--op <id>` | テキストは差分、blobはバージョンIDを表示 |
| `lit checkout <selector>` | 任意時点へロールバック/フォワード | `--timestamp`, `--op-id`, `--snapshot` | ロールバック前に現在の内部操作を一時退避 |
| `lit snapshot create` | 即時スナップショット生成 | `--scope <path>`, `--tag <name>` | Snapshot Managerに明示指示 |
| `lit sync` | ピアとログ/スナップショットを同期 | `--remote <url>`, `--push`, `--pull` | CRDTエンジンを介して双方向マージ |
| `lit blob fetch <path> <version>` | blobの特定バージョン取得 | `--output <file>` | バージョンIDは`lit log`で確認 |
| `lit label <name>` | 任意の編集ブロック範囲にラベルを付ける | `--from <op-id>`, `--to <op-id>`, `--note <text>` | すべての変更は自動記録されるため「コミット」概念は持たず、ラベルのみで人間向け区切りを与える |
| `lit diff [<selector>]` | 任意2バージョンの差分を表示 | `--from`, `--to`, `--blob` | blobはハッシュ比較のみ |

- CLIは`$HOME/.lit`に設定・ソケット・キャッシュを保持し、`lit daemon`で明示起動/停止も可能にする。

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
- **マウントターゲット**: 任意の既存ディレクトリに`lit mount <path>`のような形でマウントし、アンマウント時もデータを失わない。
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
1. `lit mount /path/to/workdir` を実行。
2. Filesystem AdapterがFUSE経由でマウントポイントを作成。
3. 対象ディレクトリ構造を初期スナップショットとして取り込み、操作ログの起点(ロジカルクロック0)を作る。

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
