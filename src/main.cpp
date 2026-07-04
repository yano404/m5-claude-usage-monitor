#include <Arduino.h>
#include <DNSServer.h>
#include <HTTPClient.h>
#include <M5Core2.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_system.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>

#include <vector>

static const char* PREF_NS = "claude";
static const char* API_URL = "https://api.anthropic.com/v1/messages";
static const char* ANTHROPIC_VERSION = "2023-06-01";
static const char* ANTHROPIC_BETA = "oauth-2025-04-20";
static const char* PROBE_MODEL = "claude-haiku-4-5-20251001";
static const uint32_t POLL_INTERVAL_MS = 60000;
static const uint32_t RATE_LIMIT_BACKOFF_MS = 15UL * 60UL * 1000UL;
static const uint32_t WIFI_TIMEOUT_MS = 25000;
static const long JST_OFFSET_SEC = 9L * 60L * 60L;
static const byte DNS_PORT = 53;

Preferences prefs;
WebServer server(80);
DNSServer dnsServer;
TFT_eSprite frame(&M5.Lcd);
TFT_eSPI* ui = &M5.Lcd;
bool frameReady = false;

struct UsageData {
  bool ok = false;
  float h5 = 0.0f;
  float d7 = 0.0f;
  uint32_t h5ResetEpoch = 0;
  uint32_t d7ResetEpoch = 0;
  String status = "unknown";
  String error;
  uint32_t updatedAt = 0;
};

String token;
UsageData usage;
uint32_t lastPollMs = 0;
uint32_t nextPollMs = 0;
uint8_t brightnessIndex = 1;
const uint8_t BRIGHTNESS_LEVELS[] = {35, 58, 82, 100};
uint32_t lastUiTickMs = 0;

TFT_eSPI& UI() {
  return *ui;
}

String htmlEscape(const String& value) {
  String out;
  out.reserve(value.length());
  for (size_t i = 0; i < value.length(); i++) {
    char c = value[i];
    if (c == '&') out += F("&amp;");
    else if (c == '<') out += F("&lt;");
    else if (c == '>') out += F("&gt;");
    else if (c == '"') out += F("&quot;");
    else out += c;
  }
  return out;
}

String deviceSuffix() {
  uint64_t mac = ESP.getEfuseMac();
  char buf[7];
  snprintf(buf, sizeof(buf), "%06X", (uint32_t)(mac & 0xFFFFFF));
  return String(buf);
}

void drawCentered(const String& text, int y, uint16_t color = TFT_WHITE, uint8_t size = 2) {
  UI().setTextSize(size);
  UI().setTextColor(color, TFT_BLACK);
  int x = (UI().width() - UI().textWidth(text)) / 2;
  UI().drawString(text, max(0, x), y);
}

void showMessage(const String& title, const String& body = "") {
  TFT_eSPI* previousUi = ui;
  ui = &M5.Lcd;
  if (frameReady) {
    frame.fillScreen(TFT_BLACK);
  }
  M5.Lcd.fillScreen(TFT_BLACK);
  drawCentered(title, 62, TFT_WHITE, 3);
  if (body.length()) {
    UI().setTextSize(2);
    UI().setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    UI().drawCentreString(body, UI().width() / 2, 112, 2);
  }
  ui = previousUi;
}

void setBrightness() {
  M5.Axp.ScreenBreath(BRIGHTNESS_LEVELS[brightnessIndex]);
}

void initDashboardFrame() {
  frame.setColorDepth(16);
  frameReady = frame.createSprite(320, 240) != nullptr;
  if (!frameReady) {
    Serial.println("[UI] Sprite allocation failed; drawing directly");
  }
}

void deriveKey(const String& pin, uint8_t key[32]) {
  uint64_t mac = ESP.getEfuseMac();
  char salt[18];
  snprintf(salt, sizeof(salt), "%04X%08X", (uint16_t)(mac >> 32), (uint32_t)mac);
  String material = pin + ":" + salt;
  mbedtls_sha256_ret((const unsigned char*)material.c_str(), material.length(), key, 0);
  for (int i = 1; i < 10000; i++) {
    mbedtls_sha256_ret(key, 32, key, 0);
  }
}

bool encryptAndStoreToken(const String& plainToken, const String& pin) {
  if (plainToken.length() == 0 || pin.length() < 4) return false;

  uint8_t key[32];
  uint8_t iv[12];
  uint8_t tag[16];
  deriveKey(pin, key);
  esp_fill_random(iv, sizeof(iv));

  std::vector<uint8_t> cipher(plainToken.length());
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(
      &gcm, MBEDTLS_GCM_ENCRYPT, plainToken.length(),
      iv, sizeof(iv), nullptr, 0,
      (const unsigned char*)plainToken.c_str(), cipher.data(),
      sizeof(tag), tag);
  }
  mbedtls_gcm_free(&gcm);
  if (rc != 0) return false;

  prefs.putBytes("tok", cipher.data(), cipher.size());
  prefs.putBytes("iv", iv, sizeof(iv));
  prefs.putBytes("tag", tag, sizeof(tag));
  return true;
}

bool decryptStoredToken(const String& pin, String& outToken) {
  size_t cipherLen = prefs.getBytesLength("tok");
  if (cipherLen == 0 || prefs.getBytesLength("iv") != 12 || prefs.getBytesLength("tag") != 16) {
    return false;
  }

  std::vector<uint8_t> cipher(cipherLen);
  std::vector<uint8_t> plain(cipherLen + 1, 0);
  uint8_t iv[12];
  uint8_t tag[16];
  prefs.getBytes("tok", cipher.data(), cipherLen);
  prefs.getBytes("iv", iv, sizeof(iv));
  prefs.getBytes("tag", tag, sizeof(tag));

  uint8_t key[32];
  deriveKey(pin, key);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_auth_decrypt(
      &gcm, cipherLen, iv, sizeof(iv), nullptr, 0,
      tag, sizeof(tag), cipher.data(), plain.data());
  }
  mbedtls_gcm_free(&gcm);
  if (rc != 0) return false;

  outToken = String((const char*)plain.data());
  return true;
}

String setupPage(const String& message = "") {
  String ssid = htmlEscape(prefs.getString("ssid", ""));
  String page = F(
    "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:24px;background:#111;color:#f5f5f5}"
    "main{max-width:520px;margin:auto}label{display:block;margin:16px 0 6px;color:#bbb}"
    "input,textarea{box-sizing:border-box;width:100%;padding:12px;border-radius:8px;border:1px solid #444;background:#1c1c1c;color:#fff}"
    "textarea{min-height:132px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}"
    ".field-row{display:flex;gap:8px}.field-row input{flex:1}.show-btn{width:auto;margin-top:0;padding:0 14px;background:#333;color:#fff;border:1px solid #555}"
    "button{margin-top:20px;width:100%;padding:13px;border:0;border-radius:8px;background:#31d0aa;color:#06120f;font-weight:700}"
    ".msg{padding:12px;border-radius:8px;background:#233;margin:16px 0}</style></head><body><main>"
    "<h1>Claude Monitor</h1>");
  if (message.length()) page += "<div class='msg'>" + htmlEscape(message) + "</div>";
  page += F(
    "<form method='post' action='/save'>"
    "<label>WiFi SSID</label><input name='ssid' value='");
  page += ssid;
  page += F(
    "' required><label>WiFi Password</label><div class='field-row'><input id='wifi-pass' name='pass' type='password'>"
    "<button class='show-btn' type='button' onclick=\"const p=document.getElementById('wifi-pass');p.type=p.type==='password'?'text':'password';this.textContent=p.type==='password'?'Show':'Hide'\">Show</button></div>"
    "<label>Claude Code OAuth Token</label><textarea name='token' spellcheck='false' autocomplete='off' required></textarea>"
    "<label>4+ digit PIN</label><input name='pin' inputmode='numeric' pattern='[0-9]{4,}' required>"
    "<button>Save & Reboot</button></form></main></body></html>");
  return page;
}

void startProvisioning() {
  String apName = "ClaudeMonitor-" + deviceSuffix();
  const char* apPass = "claude1234";

  WiFi.mode(WIFI_AP);
  WiFi.softAP(apName.c_str(), apPass);
  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());

  server.on("/", HTTP_GET, []() {
    server.send(200, "text/html", setupPage());
  });
  server.on("/save", HTTP_POST, []() {
    String ssid = server.arg("ssid");
    String pass = server.arg("pass");
    String newToken = server.arg("token");
    String pin = server.arg("pin");
    ssid.trim();
    newToken.trim();
    pin.trim();
    if (ssid.length() == 0 || newToken.length() == 0 || pin.length() < 4) {
      server.send(400, "text/html", setupPage("SSID, token, and a 4+ digit PIN are required."));
      return;
    }
    prefs.putString("ssid", ssid);
    prefs.putString("pass", pass);
    if (!encryptAndStoreToken(newToken, pin)) {
      server.send(500, "text/html", setupPage("Could not encrypt token."));
      return;
    }
    server.send(200, "text/html", setupPage("Saved. Rebooting..."));
    delay(1200);
    ESP.restart();
  });
  server.onNotFound([]() {
    server.sendHeader("Location", "/", true);
    server.send(302, "text/plain", "");
  });
  server.begin();

  UI().fillScreen(TFT_BLACK);
  drawCentered("Setup Mode", 36, TFT_WHITE, 3);
  UI().setTextSize(2);
  UI().setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  UI().drawCentreString(apName, UI().width() / 2, 88, 2);
  UI().drawCentreString(String("Pass: ") + apPass, UI().width() / 2, 116, 2);
  UI().drawCentreString("Open http://192.168.4.1", UI().width() / 2, 150, 2);

  while (true) {
    dnsServer.processNextRequest();
    server.handleClient();
    M5.update();
    delay(2);
  }
}

bool connectWifi() {
  String ssid = prefs.getString("ssid", "");
  String pass = prefs.getString("pass", "");
  if (ssid.length() == 0) return false;

  showMessage("Connecting", ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());

  uint32_t started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < WIFI_TIMEOUT_MS) {
    UI().fillCircle(96 + ((millis() / 300) % 5) * 32, 154, 4, TFT_CYAN);
    delay(250);
  }
  return WiFi.status() == WL_CONNECTED;
}

String readLine(WiFiClient& client, uint32_t timeoutMs = 8000) {
  String line;
  uint32_t started = millis();
  while (millis() - started < timeoutMs) {
    while (client.available()) {
      char c = client.read();
      if (c == '\n') return line;
      if (c != '\r') line += c;
    }
    delay(1);
  }
  return line;
}

uint32_t parseReset(const String& value) {
  if (value.length() == 0) return 0;
  return (uint32_t)value.toInt();
}

bool fetchUsage(UsageData& out) {
  Serial.println("[API] Fetching Claude usage");
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient https;
  const char* headers[] = {
    "anthropic-ratelimit-unified-5h-utilization",
    "anthropic-ratelimit-unified-5h-reset",
    "anthropic-ratelimit-unified-7d-utilization",
    "anthropic-ratelimit-unified-7d-reset",
    "anthropic-ratelimit-unified-status",
    "anthropic-ratelimit-unified-5h-status",
    "retry-after",
    "anthropic-ratelimit-requests-reset",
    "anthropic-ratelimit-tokens-reset",
    "anthropic-ratelimit-input-tokens-reset",
    "anthropic-ratelimit-output-tokens-reset",
  };

  if (!https.begin(client, API_URL)) {
    out.ok = false;
    out.error = "https_init";
    return false;
  }

  https.addHeader("Authorization", "Bearer " + token);
  https.addHeader("anthropic-version", ANTHROPIC_VERSION);
  https.addHeader("anthropic-beta", ANTHROPIC_BETA);
  https.addHeader("content-type", "application/json");
  https.addHeader("User-Agent", "claude-code/2.1.5");
  https.collectHeaders(headers, 11);
  https.setTimeout(15000);

  String body = String("{\"model\":\"") + PROBE_MODEL +
                "\",\"max_tokens\":1,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
  int code = https.POST(body);
  Serial.printf("[API] HTTP %d\n", code);
  if (code <= 0) {
    out.ok = false;
    out.error = "http_" + String(code);
    https.end();
    return false;
  }

  String h5 = https.header(headers[0]);
  String h5r = https.header(headers[1]);
  String d7 = https.header(headers[2]);
  String d7r = https.header(headers[3]);
  String status = https.header(headers[4]);
  String h5Status = https.header(headers[5]);
  String retryAfter = https.header(headers[6]);
  String requestsReset = https.header(headers[7]);
  String tokensReset = https.header(headers[8]);
  String inputReset = https.header(headers[9]);
  String outputReset = https.header(headers[10]);
  String responseBody = https.getString();
  Serial.printf("[API] 5h=%s 7d=%s\n", h5.c_str(), d7.c_str());
  Serial.printf("[API] retry-after=%s requests-reset=%s tokens-reset=%s input-reset=%s output-reset=%s\n",
                retryAfter.c_str(), requestsReset.c_str(), tokensReset.c_str(),
                inputReset.c_str(), outputReset.c_str());
  if (responseBody.length()) {
    Serial.printf("[API] body: %.180s\n", responseBody.c_str());
  }
  https.end();

  if (h5.length() == 0 && d7.length() == 0) {
    out.ok = false;
    if (code == 401) {
      out.error = "auth_failed";
    } else if (code == 429) {
      out.error = retryAfter.length() ? "rate_limited " + retryAfter + "s" : "rate_limited";
      uint32_t retryMs = retryAfter.length() ? (uint32_t)retryAfter.toInt() * 1000UL : RATE_LIMIT_BACKOFF_MS;
      nextPollMs = millis() + max(retryMs, RATE_LIMIT_BACKOFF_MS);
    } else {
      out.error = "no_usage_h_" + String(code);
    }
    Serial.printf("[API] error=%s\n", out.error.c_str());
    return false;
  }

  out.ok = true;
  out.h5 = h5.toFloat() * 100.0f;
  out.d7 = d7.toFloat() * 100.0f;
  out.h5ResetEpoch = parseReset(h5r);
  out.d7ResetEpoch = parseReset(d7r);
  out.status = status.length() ? status : h5Status;
  out.updatedAt = millis();
  out.error = "";
  nextPollMs = millis() + POLL_INTERVAL_MS;
  return true;
}

String countdown(uint32_t epoch) {
  if (epoch == 0) return "--:--";
  time_t now;
  time(&now);
  if (now < 1700000000) return "syncing";
  int32_t remaining = (int32_t)(epoch - now);
  if (remaining <= 0) return "now";
  uint32_t days = remaining / 86400;
  remaining %= 86400;
  uint32_t hours = remaining / 3600;
  uint32_t mins = (remaining % 3600) / 60;
  char buf[18];
  if (days > 0) snprintf(buf, sizeof(buf), "%ud %02uh", days, hours);
  else snprintf(buf, sizeof(buf), "%uh %02um", hours, mins);
  return String(buf);
}

uint16_t rgb(uint8_t r, uint8_t g, uint8_t b) {
  return UI().color565(r, g, b);
}

uint16_t usageColor(float pct) {
  if (pct >= 85.0f) return rgb(255, 84, 84);
  if (pct >= 65.0f) return rgb(242, 175, 78);
  return rgb(73, 213, 152);
}

void drawSoftFrame(int x, int y, int w, int h, uint16_t fill, uint16_t edge) {
  UI().fillRoundRect(x + 2, y + 3, w, h, 8, rgb(2, 3, 5));
  UI().fillRoundRect(x, y, w, h, 8, fill);
  UI().drawRoundRect(x, y, w, h, 8, edge);
}

void drawFineBar(int x, int y, int w, int h, float pct, uint16_t color) {
  uint16_t track = rgb(35, 39, 42);
  uint16_t tick = rgb(58, 63, 66);
  UI().fillRoundRect(x, y, w, h, h / 2, track);
  int fill = constrain((int)(w * pct / 100.0f), 0, w);
  if (fill > 0) UI().fillRoundRect(x, y, fill, h, h / 2, color);
  for (int i = 1; i < 4; i++) {
    int tx = x + (w * i) / 4;
    UI().drawFastVLine(tx, y + 2, h - 4, tick);
  }
}

void drawWifiIcon(int x, int y, int rssi, uint16_t fg, uint16_t muted) {
  int bars = 1;
  if (rssi > -58) bars = 4;
  else if (rssi > -67) bars = 3;
  else if (rssi > -76) bars = 2;

  for (int i = 0; i < 4; i++) {
    int bh = 4 + i * 3;
    int bx = x + i * 6;
    int by = y + 14 - bh;
    UI().fillRoundRect(bx, by, 4, bh, 2, i < bars ? fg : muted);
  }
}

void drawPill(int x, int y, const String& text, uint16_t fg, uint16_t bg) {
  UI().setTextSize(1);
  int w = UI().textWidth(text) + 18;
  UI().fillRoundRect(x, y, w, 18, 9, bg);
  UI().setTextColor(fg, bg);
  UI().drawString(text, x + 9, y + 5);
}

String updatedAgo() {
  if (usage.updatedAt == 0) return "--";
  uint32_t elapsed = (millis() - usage.updatedAt) / 1000;
  if (elapsed < 60) return String(elapsed) + "s";
  return String(elapsed / 60) + "m";
}

String clockText() {
  time_t now;
  time(&now);
  if (now < 1700000000) return "--:--";
  struct tm tm;
  localtime_r(&now, &tm);
  char buf[6];
  snprintf(buf, sizeof(buf), "%02d:%02d", tm.tm_hour, tm.tm_min);
  return String(buf);
}

void drawBatteryIcon(int x, int y, float pct, bool charging, uint16_t fg, uint16_t muted) {
  pct = constrain(pct, 0.0f, 100.0f);
  UI().drawRoundRect(x, y + 2, 24, 12, 3, muted);
  UI().fillRect(x + 25, y + 6, 2, 4, muted);
  int fill = (int)roundf(20.0f * pct / 100.0f);
  if (fill > 0) UI().fillRoundRect(x + 2, y + 4, fill, 8, 2, fg);
  if (charging) {
    UI().setTextSize(1);
    UI().setTextColor(rgb(7, 9, 10), fg);
    UI().drawString("+", x + 9, y + 4);
  }
}

void drawFooter(uint16_t bg) {
  uint16_t muted = rgb(75, 82, 84);
  UI().fillRect(0, 216, 320, 24, bg);
  UI().setTextSize(1);
  UI().setTextColor(muted, bg);
  UI().drawString("updated " + updatedAgo() + " ago", 16, 225);

  float battery = M5.Axp.GetBatteryLevel();
  bool charging = M5.Axp.isCharging();
  uint16_t batteryColor = battery <= 20.0f ? rgb(255, 84, 84) : rgb(106, 151, 138);
  drawBatteryIcon(238, 221, battery, charging, batteryColor, rgb(42, 48, 50));
  drawWifiIcon(282, 221, WiFi.RSSI(), rgb(106, 151, 138), rgb(42, 48, 50));
}

void drawHeader(uint16_t bg) {
  UI().fillRect(0, 0, 320, 42, bg);
  UI().setTextSize(1);
  UI().setTextColor(rgb(137, 145, 150), bg);
  UI().drawString("CLAUDE CODE", 16, 12);
  UI().setTextColor(rgb(237, 241, 238), bg);
  UI().drawString("usage", 16, 25);
  UI().setTextSize(2);
  UI().setTextColor(rgb(188, 196, 192), bg);
  UI().drawCentreString(clockText(), 160, 8, 2);
  UI().setTextSize(1);

  String status = usage.ok ? usage.status : "offline";
  if (!status.length()) status = "unknown";
  uint16_t pillBg = usage.ok ? rgb(18, 61, 47) : rgb(73, 44, 34);
  uint16_t pillFg = usage.ok ? rgb(105, 235, 179) : rgb(245, 163, 96);
  int pillW = UI().textWidth(status) + 18;
  drawPill(304 - pillW, 13, status, pillFg, pillBg);
}

void drawUsageCard(const char* label, const char* windowLabel, float pct, uint32_t resetEpoch,
                   int x, int y, int w, int h) {
  uint16_t panel = rgb(13, 16, 18);
  uint16_t edge = rgb(48, 53, 54);
  uint16_t muted = rgb(130, 137, 140);
  uint16_t accent = usageColor(pct);

  drawSoftFrame(x, y, w, h, panel, edge);

  UI().setTextSize(1);
  UI().setTextColor(muted, panel);
  UI().drawString(label, x + 16, y + 14);
  UI().drawRightString(windowLabel, x + w - 16, y + 14, 1);

  char pctText[8];
  snprintf(pctText, sizeof(pctText), "%02.0f", pct);
  UI().setTextSize(4);
  UI().setTextColor(rgb(244, 246, 242), panel);
  int pctX = x + 16;
  int pctY = y + 30;
  UI().drawString(pctText, pctX, pctY);
  int pctW = UI().textWidth(pctText);
  UI().setTextSize(2);
  UI().setTextColor(accent, panel);
  UI().drawString("%", pctX + pctW + 5, pctY + 11);

  UI().setTextSize(1);
  UI().setTextColor(muted, panel);
  UI().drawRightString("reset", x + w - 16, y + 33, 1);
  UI().setTextSize(2);
  UI().setTextColor(rgb(210, 215, 211), panel);
  UI().drawRightString(countdown(resetEpoch), x + w - 16, y + 45, 1);

  int barX = x + 16;
  int barY = y + h - 17;
  int barW = w - 32;
  drawFineBar(barX, barY, barW, 10, pct, accent);
}

void drawUsageCards() {
  drawUsageCard("CURRENT", "5 hour", usage.h5, usage.h5ResetEpoch, 12, 44, 296, 82);
  drawUsageCard("WEEK", "7 day", usage.d7, usage.d7ResetEpoch, 12, 132, 296, 82);
}

void drawErrorDashboard() {
  uint16_t bg = rgb(7, 9, 10);
  uint16_t panel = rgb(15, 14, 13);
  UI().fillScreen(bg);
  drawHeader(bg);
  drawSoftFrame(22, 70, 276, 106, panel, rgb(64, 48, 38));
  UI().setTextSize(3);
  UI().setTextColor(rgb(242, 175, 78), panel);
  UI().drawCentreString("No data", 160, 92, 2);
  UI().setTextSize(2);
  UI().setTextColor(rgb(194, 184, 171), panel);
  UI().drawCentreString(usage.error, 160, 132, 2);
}

void drawDashboard() {
  uint16_t bg = rgb(7, 9, 10);
  TFT_eSPI* previousUi = ui;
  if (frameReady) {
    ui = &frame;
  }

  UI().fillScreen(bg);
  drawHeader(bg);

  if (!usage.ok) {
    drawErrorDashboard();
  } else {
    drawUsageCards();
    drawFooter(bg);
  }

  if (frameReady) {
    frame.pushSprite(0, 0);
  }
  ui = previousUi;
  lastUiTickMs = millis();
}

String pinEntry() {
  String pin = "0000";
  int digit = 0;
  while (digit < 4) {
    M5.update();
    TFT_eSPI* previousUi = ui;
    if (frameReady) {
      ui = &frame;
    }

    uint16_t bg = rgb(7, 9, 10);
    uint16_t panel = rgb(13, 16, 18);
    uint16_t edge = rgb(48, 53, 54);
    uint16_t muted = rgb(130, 137, 140);
    uint16_t accent = rgb(73, 213, 152);

    UI().fillScreen(bg);
    UI().setTextSize(1);
    UI().setTextColor(muted, bg);
    UI().drawCentreString("CLAUDE TOKEN", 160, 34, 1);
    UI().setTextSize(2);
    UI().setTextColor(rgb(237, 241, 238), bg);
    UI().drawCentreString("Unlock", 160, 50, 2);

    drawSoftFrame(36, 86, 248, 58, panel, edge);
    UI().setTextSize(4);
    for (int i = 0; i < 4; i++) {
      int x = 74 + i * 45;
      uint16_t color = (i == digit) ? accent : rgb(237, 241, 238);
      UI().setTextColor(color, panel);
      UI().drawString(String(pin[i]), x, 100);
      if (i == digit) {
        UI().fillRoundRect(x - 2, 135, 24, 3, 2, accent);
      }
    }

    UI().drawFastHLine(32, 196, 256, rgb(34, 39, 41));
    UI().setTextSize(1);
    UI().setTextColor(rgb(73, 213, 152), bg);
    UI().drawCentreString("-", 61, 202, 4);
    UI().drawCentreString("+", 259, 202, 4);
    UI().drawCentreString(">", 160, 202, 4);
    UI().setTextSize(1);
    UI().setTextColor(rgb(130, 137, 140), bg);
    UI().drawCentreString("decrease", 61, 226, 1);
    UI().drawCentreString("next", 160, 226, 1);
    UI().drawCentreString("increase", 259, 226, 1);

    if (frameReady) {
      frame.pushSprite(0, 0);
    }
    ui = previousUi;

    while (true) {
      M5.update();
      if (M5.BtnA.wasPressed()) {
        pin[digit] = (pin[digit] == '0') ? '9' : pin[digit] - 1;
        break;
      }
      if (M5.BtnC.wasPressed()) {
        pin[digit] = (pin[digit] == '9') ? '0' : pin[digit] + 1;
        break;
      }
      if (M5.BtnB.wasPressed()) {
        digit++;
        break;
      }
      delay(20);
    }
  }
  return pin;
}

bool unlockToken() {
  for (int tries = 0; tries < 5; tries++) {
    String pin = pinEntry();
    if (decryptStoredToken(pin, token)) {
      token.trim();
      return true;
    }
    showMessage("Wrong PIN", "Try again");
    delay(1200);
  }
  return false;
}

void factoryReset() {
  showMessage("Resetting", "Clearing credentials");
  prefs.clear();
  delay(1200);
  ESP.restart();
}

void setup() {
  Serial.begin(115200);
  M5.begin(true, true, true, true);
  setBrightness();
  initDashboardFrame();
  prefs.begin(PREF_NS, false);

  M5.update();
  if (M5.BtnA.isPressed() && M5.BtnB.isPressed()) {
    factoryReset();
  }
  if (M5.BtnC.isPressed()) {
    startProvisioning();
  }

  bool configured = prefs.getString("ssid", "").length() > 0 && prefs.getBytesLength("tok") > 0;
  if (!configured) startProvisioning();

  if (!unlockToken()) {
    factoryReset();
  }

  if (!connectWifi()) {
    showMessage("WiFi failed", "Hold C on boot for setup");
    delay(3000);
    startProvisioning();
  }

  configTime(JST_OFFSET_SEC, 0, "pool.ntp.org", "time.nist.gov");
  showMessage("Fetching", "Claude usage");
  fetchUsage(usage);
  lastPollMs = millis();
  if (nextPollMs == 0) nextPollMs = lastPollMs + POLL_INTERVAL_MS;
  drawDashboard();
}

void loop() {
  M5.update();

  if (M5.BtnA.wasPressed()) {
    brightnessIndex = (brightnessIndex + 1) % (sizeof(BRIGHTNESS_LEVELS) / sizeof(BRIGHTNESS_LEVELS[0]));
    setBrightness();
    drawDashboard();
  }

  if (M5.BtnB.wasPressed()) {
    nextPollMs = 0;
    fetchUsage(usage);
    lastPollMs = millis();
    drawDashboard();
  }

  if (M5.BtnC.pressedFor(2500)) {
    startProvisioning();
  }

  if (WiFi.status() != WL_CONNECTED) {
    connectWifi();
    drawDashboard();
  }

  if (nextPollMs == 0 || (int32_t)(millis() - nextPollMs) >= 0) {
    fetchUsage(usage);
    lastPollMs = millis();
    if (nextPollMs == 0) nextPollMs = lastPollMs + POLL_INTERVAL_MS;
    drawDashboard();
  }

  if (usage.ok && millis() - lastUiTickMs >= 1000) {
    drawDashboard();
  }

  delay(30);
}
