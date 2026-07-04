# M5ClaudeUsageMonitor

**English** | [日本語](README.ja.md)

A M5Stack Core2 monitor for Claude usage.

It uses a Claude OAuth token to show current usage, the 5-hour and 7-day usage windows, reset times, and the current rate-limit status.

## Hardware

- M5Stack Core2

## Build

Build and upload with PlatformIO.

```bash
pio run -e m5stack-core2
pio run -e m5stack-core2 -t upload
```

## Setup

On first boot, or when no settings are stored, the M5Stack Core2 starts a setup WiFi network.

```text
SSID: ClaudeMonitor-XXXXXX
Password: claude1234
URL: http://192.168.4.1
```

Connect to this WiFi network from your computer or phone, then open `http://192.168.4.1` in a browser.

Enter the following values on the setup page.

- WiFi SSID
- WiFi password
- Claude Code OAuth token
- Unlock PIN

## Unlock

The PIN unlock screen appears on boot.

Use the physical buttons below the M5Stack Core2 screen. The screen shows what each button does.

- Left button: decrease the digit
- Center button: move to the next digit
- Right button: increase the digit

After entering the correct PIN, the stored token is decrypted and the usage dashboard starts.

## Controls

- A: change screen brightness
- B: refresh manually
- Hold C: enter setup mode
- Hold A+B while booting: clear stored settings

Usage is normally refreshed about every 60 seconds.

## Security

WiFi settings and the Claude OAuth token are stored on the M5Stack Core2.

The OAuth token is encrypted using a key derived from the unlock PIN. If you forget the PIN, hold A+B while booting to clear the stored settings, then run setup again.

## Troubleshooting

### `No data`

Usage data could not be retrieved. Check the WiFi connection, token, and Claude service status.

### `auth_failed`

The OAuth token may be invalid or incomplete. Enter setup mode and paste the token again.

### `rate_limited`

Claude returned a rate-limit response. The device will retry automatically after a while.

## License

MIT License. See [LICENSE](LICENSE).
