# M5ClaudeUsageMonitor

[English](README.md) | **日本語**

M5Stack Core2でClaudeの利用状況を表示する小型モニターです。

ClaudeのOAuth tokenを使って、5時間枠と7日枠の使用率、リセットまでの残り時間、現在の状態を表示します。

## Hardware

- M5Stack Core2

## Build

PlatformIOでビルド、アップロードします。

```bash
pio run -e m5stack-core2
pio run -e m5stack-core2 -t upload
```

## Setup

初回起動時、または設定が保存されていない時は、M5Stack Core2が設定用WiFiを出します。

```text
SSID: ClaudeMonitor-XXXXXX
Password: claude1234
URL: http://192.168.4.1
```

PCまたはスマートフォンでこのWiFiに接続し、ブラウザで `http://192.168.4.1` を開きます。

設定画面で以下を入力します。

- WiFi SSID
- WiFi password
- Claude Code OAuth token
- Unlock用PIN

## Unlock

起動時にPIN入力画面が表示されます。

画面下の表示に合わせて、M5Stack Core2下部の物理ボタンで操作します。

- 左ボタン: 数字を下げる
- 中央ボタン: 次の桁へ進む
- 右ボタン: 数字を上げる

正しいPINを入力すると保存済みtokenが復号され、利用状況の表示を開始します。

## Controls

- A: 画面の明るさ切り替え
- B: 手動更新
- C長押し: 設定モード
- A+Bを押しながら起動: 保存設定を初期化

通常は約60秒ごとに利用状況を更新します。

## Security

WiFi設定とClaude OAuth tokenはM5Stack Core2本体に保存されます。

OAuth tokenはPINから作った鍵で暗号化して保存します。PINを忘れた場合は、A+Bを押しながら起動して設定を初期化し、もう一度セットアップしてください。

## Troubleshooting

### `No data`

利用状況を取得できていません。WiFi接続、token、Claude側の状態を確認してください。

### `auth_failed`

OAuth tokenが無効、またはコピー時に一部が欠けている可能性があります。設定モードでtokenを貼り直してください。

### `rate_limited`

Claude側がrate limitを返しています。しばらく待つと自動で再試行します。

## License

MIT Licenseです。詳細は [LICENSE](LICENSE) を参照してください。
