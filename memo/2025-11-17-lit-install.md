# 2025-11-17 lit インストールメモ

## 実施内容
- `rustc 1.85.0` では `home v0.5.12` の要求を満たせず `cargo install` が失敗した。
- `rustup override set 1.90.0` で本リポジトリ直下に Rust 1.90.0 を適用した上で `make install` を実行。
- `lit`, `lit-relay`, `lit-fs` の3バイナリが `$HOME/.cargo/bin` に再インストールされ、`lit version` で `0.1.0` を確認。

## 実行コマンド
```bash
rustup override set 1.90.0
make install
lit version
```

## 補足
- ビルド成果物のキャッシュは `~/.cache/lit/target` を利用。
- 以降このディレクトリでは 1.90.0 ツールチェーンが固定されるため、他バージョンが必要な場合は `rustup override unset` を実行すること。
