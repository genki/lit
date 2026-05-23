# 2025-11-17 macFUSE インストール試行メモ

## 実施内容
- `brew install --cask macfuse` を試みたが、Sandboxによる Signal 9 で中断。
- 代替として最新リリース (macfuse-5.1.1) を GitHub から取得し、`/tmp/macfuse-5.1.1.dmg` を `hdiutil attach`。
- `sudo installer -pkg "/Volumes/macFUSE/Install macFUSE.pkg" -target /` を実行したが、sudo パスワード入力が必要で 120 秒でタイムアウトしインストールできなかった。

## 状態
- `/tmp/macfuse-5.1.1.dmg` を保持。
- `/Volumes/macFUSE` は都度 `hdiutil attach/detach` でマウント可能。
- `sudo installer -pkg "/Volumes/macFUSE/Install macFUSE.pkg" -target /` をパスワードなしで実行できないため、非対話のCLI環境ではインストールが完了しない。`sudo -n true` でもパスワード要求が返り、強制実行すると 120 秒タイムアウトとなる。
- ユーザー側でGUIインストーラを完了しても `lit on tmp/test` は `lit-fs` マウント待機のままタイムアウト（プロセスは起動するがマウント完了しない）。macOSの再起動や拡張機能の許可が必要な可能性が高い。

## 対応案
1. ユーザーが macOS 側で sudo パスワードを入力可能な状態で `sudo installer -pkg /Volumes/macFUSE/Install\ macFUSE.pkg -target /` を実行する。
2. あるいは GUI インストーラを開き手動で認証・再起動を実施する。
3. インストール完了後は `System Settings > Privacy & Security` で拡張機能の許可と再起動が必要な場合がある。
