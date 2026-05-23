# 2025-11-17 lit-fs 完全移行メモ

## 実施内容
- `lit on` から `fuse-overlayfs` 依存チェックを削除し、`lit-fs` デーモンのみでマウントする実装に統一。
- `lit off` は `fusermount3` / `fusermount` / `umount` / `diskutil umount` の順で利用可能なコマンドを探索し、OS に応じて自動アンマウントできるようにした。
- マウント待機ロジックを `statfs` ベースに刷新し、Linux では FUSE_SUPER_MAGIC、macOS では `f_fstypename` に `fuse` を含むかで判定。ポーリング回数も 50 回に増やして立ち上がり遅延へ余裕を持たせた。
- README / doc/spec.md から `fuse-overlayfs` 記述を削除し、`lit-fs` + `fusermount3`/`umount` 前提の記述へ更新。

## 確認
- `cargo fmt`
- `cargo check -p lit-cli`

## メモ
- macOS 側では `umount` または `diskutil umount`、Linux 側では `fusermount3` が利用できれば `lit on/off` が完結する。`fuse-overlayfs` の導入は不要になった。
