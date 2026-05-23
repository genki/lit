# 2025-11-17 Vagrant 環境調査メモ

## 背景
- ../mba22/memo/reg-speedtest.md に記録された Vagrant (Ubuntu 24.04) ゲストと WinVR ホスト間のネットワーク計測結果を確認した。
- 目的: Vagrant 環境で発生していた `docker push reg.s21g.com` の遅延／失敗に関する要点を把握する。

## 把握した知見
1. **構成**: Vagrant は WinVR (Windows + Hyper-V) 上で動作する Ubuntu 24.04 ゲスト。`reg-speedtest` 系コンテナを用いてレジストリや Cloudflare エンドポイントへの帯域計測が行われている。
2. **帯域比較**:
   - Cloudflare ダウンロード計測では Vagrant 側で `time_total≈3.8s / speed_download≈25–26 MB/s`、WinVR 側で `time_total≈4.4s / speed_download≈22–23 MB/s` と大差なし。
   - しかし speedtest.net (サーバーID 60324) では Vagrant のアップロードが約 6 Mbps・パケットロス 0% 付近に対し、WinVR は 1 Mbps 前後でパケットロス 6〜14%（改善前）。
3. **MTU 調整**:
   - `ping -M do` / `ping -f -l` の結果から実効 MTU が約 1454 バイトと判明。
   - Vagrant 側では `sysctl net.ipv4.tcp_mtu_probing=1` でブラックホール検知を有効にしつつ、`ip link set dev eth0 mtu 1454` を適用。
   - WinVR 側も `netsh interface ipv4 set subinterface "vEthernet (External)" mtu=1454 store=persistent` や `EnablePMTUBHDetect=1` を設定。
4. **NIC オフロード無効化**:
   - `docker push` が 60〜120 秒で `Preparing` のまま固まる問題に対し、Hyper-V の `vEthernet (External)` で LSO/RSO を無効化し、Vagrant ゲストでは `ethtool -K eth0 tso off gso off gro off tx off rx off` を実行。
   - その後 Vagrant の 100MB レイヤー push は約 12 秒、WinVR は約 24 秒で完了。Vagrant 側では systemd サービスで offload 無効化を恒久化済み (`/etc/systemd/system/disable-offload.service`)。
5. **残課題**:
   - WinVR での speedtest Upload は MTU/オフロード調整後も 11 Mbps 程度までしか改善しておらず、Wi-Fi ドライバや外部要因の調査が推奨されている。
   - Vagrant はホストの制約を共有するため、今後 push 遅延が再発した場合はホスト/ゲスト両面のオフロード設定やセキュリティソフトを優先確認する方針。

## 参考ファイル
- ../mba22/memo/reg-speedtest.md
