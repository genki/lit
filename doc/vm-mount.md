# lit VM Mount ガイド (Mac/Win 共有方針)

macOS / Windows で `lit on` を実行するには FUSE カーネル拡張が必要になる。再起動やセキュリティ例外を避けたい場合は、Linux VM (Vagrant/Hyper-V/Virtualization.framework 等) 内で lit を稼働させ、ホストからはネットワーク共有を介してディレクトリを操作する構成が有効。

## アーキテクチャ概要
1. Linux VM 上で lit リポジトリを配置 (`~/lit`) し、`lit on <path>` を VM 内で実行して FUSE マウントを完結させる。
2. VM 側でマウントされたパスを NFS/SMB などでエクスポートする。
3. ホスト (macOS/Windows) は NFS/SMB をマウントして通常のディレクトリとして扱い、エディタやビルドツールをそのまま利用する。
4. lit CLI を叩く必要がある場合は `ssh vagrant ...` のように VM 内の lit を呼び出すか、`scripts/lit-vm-mount.sh` を経由して操作する。

この方式ではホストに FUSE ドライバを入れる必要がなく、VM 内での lit-fs がすべてのファイル操作を捕捉する。

## 事前準備
- VM 側: Ubuntu 24.04 などで `nfs-kernel-server`, `libfuse3-dev`, `rustup`, `lit` を導入済みであること。
- ホスト側: `ssh` で VM へ接続可能であること。macOS では標準で NFS クライアントが入っている。Windows の場合は NFS Client 機能や `mount -o anon` を事前に有効化する。

## lit on --vm-config / scripts/lit-vm-mount.sh
lit CLI自体が `--vm-config <file>`（または環境変数`LIT_VM_CONFIG`）を指定することで、VM 上の lit ワークスペースを起動しつつ NFS マウントを自動実行できる。設定ファイルは JSON 形式で、最低限以下のキーを指定する。

```json
{
  "host": "vagrant",
  "workspace": "~/lit/tmp/vm-workspace",
  "lit_root": "~/lit",
  "export_file": "/etc/exports.d/lit-vm.exports",
  "mount_options": "vers=4",
  "install_nfs": true
}
```

- `host`: SSH で接続できる VM 名。公開鍵認証を推奨。
- `workspace`: VM 側で lit をマウントするパス。
- `lit_root`: VM にチェックアウトした lit リポジトリ。
- `export_file`: `/etc/exports` の保存先（root 権限が必要）。
- `mount_options`: ホストで `sudo mount` するときの NFS オプション。
- `install_nfs`: true の場合、`apt-get install -y nfs-kernel-server` を自動実行。

`lit on <path> --vm-config ~/.lit/vm-config.json` を実行すると、VM 側で `lit on` & NFS export → ホストで NFS マウント → `~/.lit/workspaces/<id>/vm.json` に情報を保存、という流れが自動的に行われる。`lit off <path>` は保存された `vm.json` を参照して逆手順を実行する。従来通り `scripts/lit-vm-mount.sh` を使って手動で制御することもできる。

ホスト側で `scripts/lit-vm-mount.sh` も用意しており、次のように手続きを段階的に実行できる。主な機能:

```
./scripts/lit-vm-mount.sh prepare   # VM で lit on + NFS export
./scripts/lit-vm-mount.sh mount     # NFS をホストにマウント (sudo 必須)
./scripts/lit-vm-mount.sh umount    # アンマウント
./scripts/lit-vm-mount.sh stop      # lit off + export 削除
./scripts/lit-vm-mount.sh status    # VM 側 lit 状態を表示
```

環境変数で接続先やマウント先を上書きできる:

| 変数 | 説明 | 既定値 |
| --- | --- | --- |
| `VM_HOST` | SSH 接続先 (例: `vagrant`) | `vagrant` |
| `VM_LIT_ROOT` | VM 内の lit リポジトリ | `~/lit` |
| `VM_WORKSPACE` | lit をマウントするパス | `~/lit/tmp/vm-workspace` |
| `HOST_MOUNT` | ホストのマウントポイント | `./tmp/vm-workspace` |
| `EXPORT_FILE` | VM 側 `/etc/exports` の保存先 | `/etc/exports.d/lit-vm.exports` |

### シーケンス例 (macOS)
1. **VM で lit + NFS をセットアップ**
   ```bash
   ./scripts/lit-vm-mount.sh prepare   # あるいは lit on --vm-config ~/.lit/vm-config.json
   ```
   - `nfs-kernel-server` をインストール
   - `lit on $VM_WORKSPACE`
   - `/etc/exports.d/lit-vm.exports` に `anonuid`/`anongid` 指定でエクスポート
2. **ホストでマウント**
   ```bash
   sudo ./scripts/lit-vm-mount.sh mount
   ls ./tmp/vm-workspace   # lit-fs の内容が見える
   ```
3. **通常通り編集**
   - エディタ等は `./tmp/vm-workspace` を直接操作
   - lit 関連操作が必要な場合は `ssh vagrant 'cd ~/lit && lit log'` のように VM で実行
4. **終了時**
   ```bash
   ./scripts/lit-vm-mount.sh umount
   ./scripts/lit-vm-mount.sh stop
   ```

### Windows での応用
- `VM_WORKSPACE` を NFS エクスポートしたうえで、Windows の「NFS クライアント」機能 (`Services for NFS`) で `mount \<vm-ip>
fsoot` のようにマウントするか、Samba を併用する。
- 共有ドライブ上で VSCode/IDE を使えば、lit 操作は VM 内で完結しつつホストからは通常のフォルダとして扱える。

## 注意点
- NFS は UID/GID でアクセス権を判断するため、ホストと VM のユーザーを揃えるか `all_squash` で `anonuid` を lit 用ユーザーに固定している (スクリプト内で自動設定)。
- `prepare` / `stop` は VM 上で `lit on/off` を実行するので、既存ワークスペースがある場合は `VM_WORKSPACE` を切り替えること。
- ネットワーク経由の I/O となるため、大規模ビルドでは遅延が発生する。必要に応じて `rsync` + `lit sync` を併用して差分を転送する。

## 今後の拡張
- Windows 向けには NFS ではなく Samba (SMB) の設定サンプルを追加する。
- `lit` CLI に SSH 経由で VM の `lit` を呼び出すサブコマンドを追加し、ホスト側でも同じ UX で `lit log` 等を使えるようにする。
