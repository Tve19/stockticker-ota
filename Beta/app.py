print("APP.PY STARTED")

APP_VERSION = "1.1.9-beta"

import time
import ssl
import wifi
import socketpool
import board
import displayio
import framebufferio
import rgbmatrix
import adafruit_requests
import rtc
import adafruit_ntp
import terminalio
import gc
import json
import microcontroller
import os

from adafruit_display_text import label
from secrets import secrets
from adafruit_httpserver import Server, Request, Response


CONFIG_FILE = "/config.json"
SYMBOLS_FILE = "/symbols.txt"
WIFI_FILE = "/wifi_config.json"
HOLIDAYS_FILE = "/market_holidays.json"
DEVICE_FILE = "/device.json"

DEFAULT_CONFIG = {
    "brightness": 0.30,
    "scroll_speed_open": 1.0,
    "scroll_speed_closed": 0.6,
    "fetch_interval_open": 30,
    "fetch_interval_pre_after": 60,
    "fetch_interval_closed": 300,
    "alert_percent_move": 5.0,
    "block_gap": 12,
    "scroll_delay": 0.02,
    "admin_pin": "1234",
    "update_channel": "stable",
    "update_manifest_url": "https://stockticker-ota.pages.dev/manifest.json",
    "night_mode_enabled": True,
    "night_brightness": 0.08,
    "night_start_hour": 16,
    "night_end_hour": 7,
    "alert_enabled": True,
    "show_dollar_change": True,
    "show_percent_change": True,
    "after_hours_color": "purple",
    "stale_quote_minutes": 15,
    "show_stale_marker": True
}

DEFAULT_SYMBOLS = [
    "SOFI", "RKLB", "ONDS", "HIMS", "PLTR",
    "AMZN", "SPY", "OPEN", "EOSE"
]

DEFAULT_HOLIDAYS = {
    "closed": [
        "2026-01-01",
        "2026-01-19",
        "2026-02-16",
        "2026-04-03",
        "2026-05-25",
        "2026-06-19",
        "2026-07-03",
        "2026-09-07",
        "2026-11-26",
        "2026-12-25"
    ],
    "early_close": [
        "2026-11-27",
        "2026-12-24"
    ]
}

WATCHLISTS = {
    "growth": ["SOFI", "RKLB", "HIMS", "PLTR", "OPEN", "EOSE"],
    "indexes": ["SPY", "QQQ", "DIA", "IWM"],
    "mega": ["AAPL", "MSFT", "NVDA", "AMZN", "GOOGL", "META"],
    "custom": []
}

FINNHUB_URL = "https://finnhub.io/api/v1/quote?symbol={}&token={}"


def load_json_file(path, default_value):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default_value


def save_json_file(path, data):
    with open(path, "w") as f:
        json.dump(data, f)


def generate_device_id():
    uid = microcontroller.cpu.uid
    short_id = ""

    for b in uid[-3:]:
        short_id += "{:02X}".format(b)

    return "ST-" + short_id


def load_device_info():
    info = load_json_file(DEVICE_FILE, {})

    if "device_id" not in info:
        info["device_id"] = generate_device_id()
        info["created_version"] = APP_VERSION

        try:
            save_json_file(DEVICE_FILE, info)
        except OSError as e:
            print("Could not save device.json:", repr(e))
        except Exception as e:
            print("Device file save failed:", repr(e))

    return info


def load_config():
    cfg = load_json_file(CONFIG_FILE, {})

    for key in DEFAULT_CONFIG:
        if key not in cfg:
            cfg[key] = DEFAULT_CONFIG[key]

    return cfg


def save_config(cfg):
    save_json_file(CONFIG_FILE, cfg)


def load_holidays():
    h = load_json_file(HOLIDAYS_FILE, DEFAULT_HOLIDAYS)

    if "closed" not in h:
        h["closed"] = DEFAULT_HOLIDAYS["closed"]

    if "early_close" not in h:
        h["early_close"] = DEFAULT_HOLIDAYS["early_close"]

    return h


def save_holidays(h):
    save_json_file(HOLIDAYS_FILE, h)


def read_symbols_file():
    try:
        with open(SYMBOLS_FILE, "r") as f:
            return [line.strip().upper() for line in f.readlines() if line.strip()]
    except Exception:
        return []


def save_symbol_list(symbol_list):
    with open(SYMBOLS_FILE, "w") as f:
        f.write("\n".join(symbol_list) + "\n")


def url_decode(s):
    s = str(s).replace("+", " ")
    out = ""
    i = 0

    while i < len(s):
        if s[i] == "%" and i + 2 < len(s):
            try:
                out += chr(int(s[i + 1:i + 3], 16))
                i += 3
            except Exception:
                out += s[i]
                i += 1
        else:
            out += s[i]
            i += 1

    return out


def clean_symbol(raw):
    raw = url_decode(str(raw))
    raw = raw.strip().upper()
    raw = raw.replace("$", "")
    raw = raw.replace("SYMBOLS=", "")
    raw = raw.replace("SYMBOL=", "")

    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
    cleaned = ""

    for ch in raw:
        if ch in allowed:
            cleaned += ch

    return cleaned


def clean_date(raw):
    raw = url_decode(str(raw)).strip()
    allowed = "0123456789-"
    cleaned = ""

    for ch in raw:
        if ch in allowed:
            cleaned += ch

    return cleaned


def bool_from_form(value):
    value = str(value).lower()
    return value in ("1", "true", "yes", "on")


def clamp_float(value, low, high, default):
    try:
        n = float(url_decode(str(value)))
    except Exception:
        n = default

    if n < low:
        n = low
    if n > high:
        n = high

    return n


def clamp_int(value, low, high, default):
    try:
        n = int(float(url_decode(str(value))))
    except Exception:
        n = default

    if n < low:
        n = low
    if n > high:
        n = high

    return n


def selected(value, current):
    if str(value) == str(current):
        return "selected"
    return ""


APP_PATH = "/app.py"
BACKUP_APP_PATH = "/app_backup.py"


def file_exists(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


def copy_file_safe(src, dst):
    try:
        with open(src, "rb") as source:
            data = source.read()

        if not data:
            return False, "{} was empty.".format(src)

        with open(dst, "wb") as target:
            target.write(data)

        return True, "Copied {} to {}".format(src, dst)

    except Exception as e:
        return False, "Copy failed: {}".format(repr(e))


def backup_current_app():
    return copy_file_safe(APP_PATH, BACKUP_APP_PATH)


def rollback_to_backup():
    if not file_exists(BACKUP_APP_PATH):
        return False, "No app_backup.py found."

    return copy_file_safe(BACKUP_APP_PATH, APP_PATH)

config = load_config()

# DEV SAFE DEVICE ID
# This avoids OSError(30) when CIRCUITPY is mounted on your laptop.
try:
    device_info = load_device_info()
    DEVICE_ID = device_info["device_id"]
except Exception as e:
    print("Device ID disabled:", repr(e))
    DEVICE_ID = "DEV-MODE"

holidays = load_holidays()
SYMBOLS = read_symbols_file() or DEFAULT_SYMBOLS

BRIGHTNESS_TARGET = float(config["brightness"])
BRIGHTNESS_RAMP_STEP = 0.01
SCROLL_SPEED_OPEN = float(config["scroll_speed_open"])
SCROLL_SPEED_CLOSED = float(config["scroll_speed_closed"])
FETCH_INTERVAL_OPEN = int(config["fetch_interval_open"])
FETCH_INTERVAL_PRE_AFTER = int(config["fetch_interval_pre_after"])
FETCH_INTERVAL_CLOSED = int(config["fetch_interval_closed"])
ALERT_PERCENT_MOVE = float(config["alert_percent_move"])
ALERT_ENABLED = bool_from_form(config.get("alert_enabled", True))
BLOCK_GAP = int(config["block_gap"])
SCROLL_DELAY = float(config["scroll_delay"])

need_reload = False
refresh_requested = False
restart_requested = False
restart_time = 0
last_good = {}
last_update_text = "--:--"
ota_message = "No update checked yet."
ota_status_message = "Press Check OTA Status to verify manifest, channel, and backup."
last_web_message = "System ready."
last_error_message = "None yet."
test_quote_message = "No quote tested yet."
cloud_status_message = "Cloud status not checked yet."
alert_message = "No price alerts yet."
quote_freshness_message = "No quote freshness checked yet."
system_health_message = "Press Check System Health to refresh memory and disk stats."
time_sync_ok = False
boot_time = time.monotonic()
event_log = []
MAX_EVENT_LOG = 20

def safe_html(text):
    text = str(text)
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text


def add_event(message):
    try:
        stamp = format_12h(eastern_time_now())
    except Exception:
        stamp = str(int(time.monotonic())) + "s"

    entry = "{} - {}".format(stamp, str(message))
    event_log.append(entry[:160])

    while len(event_log) > MAX_EVENT_LOG:
        del event_log[0]


def build_event_log_html():
    if not event_log:
        return "No events yet."

    lines = []

    for item in reversed(event_log):
        lines.append(safe_html(item))

    return "<br>".join(lines)


def file_size_text(path):
    try:
        st = os.stat(path)
        return str(st[6]) + " bytes"
    except Exception:
        return "missing"


def build_system_health_html():
    try:
        gc.collect()
    except Exception:
        pass

    try:
        free_mem = gc.mem_free()
    except Exception:
        free_mem = "n/a"

    try:
        used_mem = gc.mem_alloc()
    except Exception:
        used_mem = "n/a"

    try:
        stat = os.statvfs("/")
        block_size = stat[0]
        total_disk = block_size * stat[2]
        free_disk = block_size * stat[3]
        disk_text = "{} free / {} total bytes".format(free_disk, total_disk)
    except Exception as e:
        disk_text = "unavailable: " + repr(e)

    uptime = int(time.monotonic() - boot_time)
    hours = uptime // 3600
    minutes = (uptime % 3600) // 60
    seconds = uptime % 60

    return (
        "Uptime: {}h {}m {}s<br>"
        "Free Memory: {} bytes<br>"
        "Used Memory: {} bytes<br>"
        "Disk: {}<br>"
        "app.py Size: {}<br>"
        "Backup Size: {}"
    ).format(
        hours,
        minutes,
        seconds,
        free_mem,
        used_mem,
        disk_text,
        file_size_text(APP_PATH),
        file_size_text(BACKUP_APP_PATH)
    )


def age_minutes(entry):
    try:
        updated = float(entry.get("updated_mono", 0))
        if updated <= 0:
            return 9999
        return int((time.monotonic() - updated) / 60)
    except Exception:
        return 9999


def quote_is_stale(entry):
    try:
        limit_minutes = int(config.get("stale_quote_minutes", 15))
    except Exception:
        limit_minutes = 15

    return bool(entry.get("stale", False)) or age_minutes(entry) >= limit_minutes


def cached_or_error_quote(sym, reason):
    if sym in last_good:
        old = last_good[sym]
        e = {}

        for key in old:
            e[key] = old[key]

        e["stale"] = True
        e["used_cached"] = True
        e["error_reason"] = reason

        if config.get("show_stale_marker", True):
            cl = str(e.get("change_line", ""))
            if "OLD" not in cl:
                if cl:
                    e["change_line"] = cl + " OLD"
                else:
                    e["change_line"] = "OLD"

        add_event("Using cached quote for {}: {}".format(sym, reason))
        return e

    add_event("No quote data for {}: {}".format(sym, reason))

    return {
        "symbol": sym,
        "price_line": "${} ERROR".format(sym),
        "change_line": "NO DATA",
        "color": 0xFF0000,
        "pct": 0,
        "updated_text": "never",
        "updated_mono": 0,
        "stale": True,
        "used_cached": False,
        "error_reason": reason
    }


def build_quote_freshness_html():
    if not SYMBOLS:
        return "No symbols saved."

    lines = []

    for sym in SYMBOLS:
        if sym not in last_good:
            lines.append("{}: No data yet".format(sym))
        else:
            e = last_good[sym]
            mins = age_minutes(e)
            state = "STALE" if quote_is_stale(e) else "OK"
            cached = " cached" if e.get("used_cached", False) else ""
            updated = e.get("updated_text", "unknown")
            lines.append("{}: {} - {} min old{} - {}".format(sym, state, mins, cached, updated))

    return "<br>".join(lines)


def set_web_message(message):
    global last_web_message
    last_web_message = message
    add_event(message)
    print("WEB STATUS:", message)


def set_error_message(message):
    global last_error_message
    last_error_message = message
    add_event("ERROR: " + str(message))
    print("WEB ERROR:", message)


add_event("Booted " + APP_VERSION)


def start_setup_mode(reason):
    print("SETUP MODE:", reason)

    setup_ssid = "StockTicker-Setup"
    setup_password = "12345678"

    wifi.radio.start_ap(setup_ssid, setup_password)
    setup_ip = str(wifi.radio.ipv4_address_ap)

    setup_pool = socketpool.SocketPool(wifi.radio)
    setup_server = Server(setup_pool, "/")

    setup_html = """\
<!DOCTYPE html>
<html>
<head>
<title>StockTicker Setup</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ background:#101018; color:white; font-family:Arial; padding:20px; }}
input {{ width:100%; box-sizing:border-box; padding:10px; margin:8px 0 14px; }}
button {{ padding:12px; }}
</style>
</head>
<body>
<h1>StockTicker Setup</h1>
<p>Enter your home WiFi information.</p>
<form method="POST" action="/save-wifi">
<label>WiFi Name</label>
<input name="ssid">
<label>Password</label>
<input name="password" type="password">
<button type="submit">Save WiFi</button>
</form>
</body>
</html>
"""
    @setup_server.route("/")
    def setup_index(request: Request):
        return Response(request, setup_html, content_type="text/html")

    @setup_server.route("/save-wifi", methods=["POST"])
    def save_wifi(request: Request):
        form = request.form_data
        ssid = url_decode(str(form.get("ssid", ""))).strip()
        password = url_decode(str(form.get("password", ""))).strip()

        save_json_file(WIFI_FILE, {
            "ssid": ssid,
            "password": password
        })

        return Response(
            request,
            "<html><body><h1>WiFi Saved</h1><p>Restarting...</p></body></html>",
            content_type="text/html"
        )

    setup_server.start(setup_ip, 80)

    print("Connect phone/laptop to WiFi:", setup_ssid)
    print("Password:", setup_password)
    print("Setup page: http://" + setup_ip + ":80/")

    saved_restart_time = 0

    while True:
        try:
            setup_server.poll()
        except Exception as e:
            print("Setup server error:", repr(e))

        if saved_restart_time == 0:
            try:
                wifi_cfg = load_json_file(WIFI_FILE, {})
                if wifi_cfg.get("ssid"):
                    saved_restart_time = time.monotonic() + 2
            except Exception:
                pass

        if saved_restart_time and time.monotonic() >= saved_restart_time:
            microcontroller.reset()

        time.sleep(0.05)


def get_wifi_credentials():
    wifi_cfg = load_json_file(WIFI_FILE, {})

    if wifi_cfg.get("ssid"):
        return wifi_cfg["ssid"], wifi_cfg.get("password", "")

    return secrets["ssid"], secrets["password"]


print("Connecting to Wi-Fi...")

try:
    ssid, password = get_wifi_credentials()
    wifi.radio.connect(ssid, password)
except Exception as e:
    start_setup_mode("WiFi failed: " + repr(e))

ip = str(wifi.radio.ipv4_address)
print("Connected:", ip)

pool = socketpool.SocketPool(wifi.radio)
requests = adafruit_requests.Session(pool, ssl.create_default_context())


def sync_time():
    global time_sync_ok

    try:
        ntp = adafruit_ntp.NTP(pool, server="pool.ntp.org", tz_offset=0)
        rtc.RTC().datetime = ntp.datetime
        time_sync_ok = True
        print("Time synced")
    except Exception as e:
        time_sync_ok = False
        print("NTP failed:", e)


def first_sunday(year, month):
    for day in range(1, 8):
        t = time.struct_time((year, month, day, 0, 0, 0, 0, -1, -1))
        if time.localtime(time.mktime(t)).tm_wday == 6:
            return day
    return 1


def second_sunday(year, month):
    return first_sunday(year, month) + 7


def is_us_eastern_dst_from_utc(utc_time):
    year = utc_time.tm_year
    month = utc_time.tm_mon
    day = utc_time.tm_mday

    if month < 3 or month > 11:
        return False
    if 3 < month < 11:
        return True
    if month == 3:
        return day >= second_sunday(year, 3)
    if month == 11:
        return day < first_sunday(year, 11)

    return False


def eastern_time_now():
    utc_now = time.localtime()
    utc_seconds = time.mktime(utc_now)
    offset = -4 if is_us_eastern_dst_from_utc(utc_now) else -5
    return time.localtime(utc_seconds + offset * 3600)


def date_string(t):
    return "{:04d}-{:02d}-{:02d}".format(t.tm_year, t.tm_mon, t.tm_mday)


def market_close_minutes(t):
    ds = date_string(t)

    if ds in holidays["early_close"]:
        return 13 * 60

    return 16 * 60


def get_market_status(t):
    ds = date_string(t)

    if t.tm_wday > 4:
        return "CLS"

    if ds in holidays["closed"]:
        return "HLD"

    minutes = t.tm_hour * 60 + t.tm_min
    open_min = 9 * 60 + 30
    close_min = market_close_minutes(t)

    if 4 * 60 <= minutes < open_min:
        return "PRE"

    if open_min <= minutes < close_min:
        return "OPN"

    if close_min <= minutes < 20 * 60:
        return "AFT"

    return "CLS"


def status_color(status):
    if status == "OPN":
        return 0x00FF00
    if status == "PRE":
        return 0x00AAFF
    if status == "AFT":
        return 0xFF9900
    if status == "HLD":
        return 0xFFFF00
    return 0xAA00FF


def format_12h(t):
    hour = t.tm_hour % 12
    hour = 12 if hour == 0 else hour
    ampm = "a" if t.tm_hour < 12 else "p"
    return "{}:{:02d}{}".format(hour, t.tm_min, ampm)


def night_mode_active(status):
    if not config.get("night_mode_enabled", True):
        return False

    et = eastern_time_now()
    hour = et.tm_hour
    start = int(config["night_start_hour"])
    end = int(config["night_end_hour"])

    if status == "OPN":
        return False

    if start > end:
        return hour >= start or hour < end

    return start <= hour < end


sync_time()
last_ntp_sync = time.monotonic()


server = Server(pool, "/")

HTML = """\
<!DOCTYPE html>
<html>
<head>
<title>StockTicker Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ background:#07111f; color:#eef6ff; font-family:Arial; padding:18px; margin:0; }}
.wrap {{ max-width:980px; margin:0 auto; }}
.hero {{ background:#101b2e; border:1px solid #243657; border-radius:18px; padding:18px; margin-bottom:14px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:14px; }}
.card {{ background:#101b2e; border:1px solid #243657; padding:16px; border-radius:18px; margin-bottom:14px; }}
.stat {{ background:#07111f; border:1px solid #243657; border-radius:12px; padding:10px; margin:6px 0; }}
label {{ color:#a9bddb; font-size:13px; font-weight:bold; }}
textarea, input, select {{ width:100%; box-sizing:border-box; margin:6px 0 12px; padding:10px; border-radius:10px; border:1px solid #33486d; background:#07111f; color:#eef6ff; }}
button {{ padding:10px 14px; border:0; border-radius:10px; background:#1f8cff; color:white; font-weight:bold; margin-top:6px; cursor:pointer; }}
.red {{ background:#cc3333; }}
.green {{ background:#22aa66; }}
.orange {{ background:#d97706; }}
.small {{ color:#a9bddb; font-size:13px; line-height:1.4; }}
.good {{ color:#55ff88; }}
.bad {{ color:#ff7777; }}
.warning {{ color:#ffd166; }}
h1 {{ margin:0 0 10px; }}
h2 {{ margin-top:0; }}
</style>
</head>
<body>
<div class="wrap">
<div class="hero">
<h1>StockTicker Dashboard</h1>
<div class="grid">
<div class="stat"><b>Version</b><br>{version}</div>
<div class="stat"><b>Device ID</b><br>{device_id}</div>
<div class="stat"><b>IP</b><br>{ip}</div>
<div class="stat"><b>Market</b><br>{market_status}</div>
<div class="stat"><b>Last Quote Update</b><br>{last_update}</div>
<div class="stat"><b>Update Channel</b><br>{update_channel}</div>
</div>
<p class="good">Status: {last_web_message}</p>
<p class="bad">Last Error: {last_error_message}</p>
</div>

<div class="grid">
<div class="card">
<h2>Quick Actions</h2>
<form method="POST" action="/refresh-now">
<button type="submit">Refresh Quotes Now</button>
</form>
<form method="POST" action="/check-cloud-status">
<button type="submit">Check Cloud Status</button>
</form>
<form method="POST" action="/check-ota-status">
<button type="submit">Check OTA Status</button>
</form>
<form method="POST" action="/restart">
<button class="red" type="submit">Restart Device</button>
</form>
</div>

<div class="card">
<h2>Price Alerts</h2>
<p>{alert_message}</p>
<p class="small">Alert triggers when a saved ticker moves more than your threshold from previous close.</p>
<form method="POST" action="/clear-alerts">
<button class="orange" type="submit">Clear Alert Message</button>
</form>
</div>
</div>

<div class="grid">
<div class="card">
<h2>Quote Freshness</h2>
<p>{quote_freshness_message}</p>
<p class="small">STALE means the panel is using old/cached data instead of a fresh quote.</p>
</div>

<div class="card">
<h2>Memory / Disk Health</h2>
<p>{system_health_message}</p>
<form method="POST" action="/check-system-health">
<button type="submit">Check System Health</button>
</form>
</div>
</div>

<div class="card">
<h2>Event Log</h2>
<p>{event_log_message}</p>
<form method="POST" action="/clear-event-log">
<button class="orange" type="submit">Clear Event Log</button>
</form>
<p class="small">This log is stored in memory and clears after a hard power cycle.</p>
</div>

<div class="card">
<h2>Tickers</h2>
<form method="POST" action="/save-symbols">
<textarea name="symbols" rows="8">{symbols}</textarea>
<button class="green" type="submit">Save Symbols</button>
</form>
</div>

<div class="grid">
<div class="card">
<h2>Test Quote</h2>
<p class="small">Check if a ticker works before saving it.</p>
<form method="POST" action="/test-quote">
<input name="test_symbol" placeholder="Example: ARM">
<button type="submit">Test Quote</button>
</form>
<p>{test_quote_message}</p>
<form method="POST" action="/validate-symbols">
<button class="green" type="submit">Validate All Saved Symbols</button>
</form>
</div>

<div class="card">
<h2>Watchlist Presets</h2>
<form method="POST" action="/apply-watchlist">
<select name="watchlist">
<option value="growth">Growth</option>
<option value="indexes">Indexes</option>
<option value="mega">Mega Cap</option>
</select>
<button type="submit">Apply Watchlist</button>
</form>
</div>
</div>

<div class="card">
<h2>Display Settings</h2>
<form method="POST" action="/save-config">
<div class="grid">
<div>
<label>Brightness 0.00-1.00</label>
<input name="brightness" value="{brightness}">
<label>Night Mode Enabled</label>
<select name="night_mode_enabled">
<option value="true" {night_true_selected}>True</option>
<option value="false" {night_false_selected}>False</option>
</select>
<label>Night Brightness</label>
<input name="night_brightness" value="{night_brightness}">
<label>Night Start Hour ET</label>
<input name="night_start_hour" value="{night_start_hour}">
<label>Night End Hour ET</label>
<input name="night_end_hour" value="{night_end_hour}">
</div>
<div>
<label>Scroll Speed Open</label>
<input name="scroll_speed_open" value="{scroll_speed_open}">
<label>Scroll Speed Closed</label>
<input name="scroll_speed_closed" value="{scroll_speed_closed}">
<label>Scroll Delay</label>
<input name="scroll_delay" value="{scroll_delay}">
<label>Block Gap</label>
<input name="block_gap" value="{block_gap}">
<label>After-Hours Color</label>
<select name="after_hours_color">
<option value="purple" {after_purple_selected}>Purple</option>
<option value="normal" {after_normal_selected}>Normal red/green</option>
</select>
</div>
<div>
<label>Open Refresh Seconds</label>
<input name="fetch_interval_open" value="{fetch_interval_open}">
<label>Pre/After Refresh Seconds</label>
<input name="fetch_interval_pre_after" value="{fetch_interval_pre_after}">
<label>Closed Refresh Seconds</label>
<input name="fetch_interval_closed" value="{fetch_interval_closed}">
<label>Price Alerts Enabled</label>
<select name="alert_enabled">
<option value="true" {alert_true_selected}>True</option>
<option value="false" {alert_false_selected}>False</option>
</select>
<label>Alert Percent Move</label>
<input name="alert_percent_move" value="{alert_percent_move}">
<label>Stale Quote Minutes</label>
<input name="stale_quote_minutes" value="{stale_quote_minutes}">
<label>Show Stale Marker</label>
<select name="show_stale_marker">
<option value="true" {stale_true_selected}>True</option>
<option value="false" {stale_false_selected}>False</option>
</select>
</div>
<div>
<label>Show Dollar Change</label>
<select name="show_dollar_change">
<option value="true" {dollar_true_selected}>True</option>
<option value="false" {dollar_false_selected}>False</option>
</select>
<label>Show Percent Change</label>
<select name="show_percent_change">
<option value="true" {percent_true_selected}>True</option>
<option value="false" {percent_false_selected}>False</option>
</select>
<label>Update Channel</label>
<select name="update_channel">
<option value="stable" {stable_selected}>Stable</option>
<option value="beta" {beta_selected}>Beta</option>
</select>
<label>Manifest URL</label>
<input name="update_manifest_url" value="{update_manifest_url}">
</div>
</div>
<button class="green" type="submit">Save Config</button>
</form>
</div>

<div class="grid">
<div class="card">
<h2>Cloud Status</h2>
<p>{cloud_status_message}</p>
<form method="POST" action="/check-cloud-status">
<button type="submit">Check Cloud Status</button>
</form>
</div>

<div class="card">
<h2>OTA Status / Health Check</h2>
<p>{ota_status_message}</p>
<form method="POST" action="/check-ota-status">
<button type="submit">Check OTA Status</button>
</form>
</div>
</div>

<div class="card">
<h2>Software Update</h2>
<p>{ota_message}</p>
<form method="POST" action="/check-update">
<button type="submit">Check for Update</button>
</form>
<br>
<form method="POST" action="/install-update">
<label>Admin PIN</label>
<input name="admin_pin" type="password" placeholder="Enter PIN">
<button class="green" type="submit">Install Update</button>
</form>
<br>
<form method="POST" action="/rollback" onsubmit="return confirm('Rollback to previous app_backup.py and restart?');">
<label>Admin PIN</label>
<input name="admin_pin" type="password" placeholder="Enter PIN">
<button class="red" type="submit">Rollback to Previous Version</button>
</form>
</div>

<div class="card">
<h2>Market Holidays</h2>
<p class="small">One date per line. Format: YYYY-MM-DD</p>
<form method="POST" action="/save-holidays">
<label>Full Market Closures</label>
<textarea name="closed" rows="7">{closed_dates}</textarea>
<label>Early Close Days</label>
<textarea name="early_close" rows="4">{early_close_dates}</textarea>
<button class="green" type="submit">Save Holidays</button>
</form>
</div>

<div class="card">
<h2>Factory Reset</h2>
<p class="small">Use only for testing setup mode or clearing saved settings.</p>
<form method="POST" action="/factory-reset">
<label>Admin PIN</label>
<input name="admin_pin" type="password" placeholder="Enter PIN">
<select name="reset_type">
<option value="wifi">Reset WiFi Only</option>
<option value="settings">Reset Settings Only</option>
<option value="symbols">Reset Symbols Only</option>
<option value="all">Reset Everything</option>
</select>
<button class="red" type="submit">Factory Reset</button>
</form>
</div>
</div>
</body>
</html>
"""


def clean_page(title, message):
    return (
        "<html><head><meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='refresh' content='1; url=/'>"
        "<style>body{{background:#101018;color:white;font-family:Arial;padding:20px;}}a{{color:#5aaaff;}}</style>"
        "</head><body><h1>{}</h1><p>{}</p><p>Returning to control panel...</p>"
        "<p><a href='/'>Back now</a></p></body></html>"
    ).format(title, message)


@server.route("/")
def index(request: Request):
    current_market_status = get_market_status(eastern_time_now())

    return Response(
        request,
        HTML.format(
            version=APP_VERSION,
            device_id=DEVICE_ID,
            ip=ip,
            market_status=current_market_status,
            update_channel=config["update_channel"],
            symbols="\n".join(SYMBOLS),
            brightness=config["brightness"],
            alert_percent_move=config["alert_percent_move"],
            stale_quote_minutes=config.get("stale_quote_minutes", 15),
            fetch_interval_open=config["fetch_interval_open"],
            fetch_interval_pre_after=config["fetch_interval_pre_after"],
            fetch_interval_closed=config["fetch_interval_closed"],
            scroll_speed_open=config["scroll_speed_open"],
            scroll_speed_closed=config["scroll_speed_closed"],
            scroll_delay=config["scroll_delay"],
            block_gap=config["block_gap"],
            ota_message=ota_message,
            ota_status_message=ota_status_message,
            alert_message=alert_message,
            quote_freshness_message=build_quote_freshness_html(),
            system_health_message=build_system_health_html(),
            event_log_message=build_event_log_html(),
            last_update=last_update_text,
            last_web_message=last_web_message,
            last_error_message=last_error_message,
            test_quote_message=test_quote_message,
            cloud_status_message=cloud_status_message,
            night_brightness=config["night_brightness"],
            night_start_hour=config["night_start_hour"],
            night_end_hour=config["night_end_hour"],
            update_manifest_url=config["update_manifest_url"],
            night_true_selected=selected("true", str(config.get("night_mode_enabled", True)).lower()),
            night_false_selected=selected("false", str(config.get("night_mode_enabled", True)).lower()),
            alert_true_selected=selected("true", str(config.get("alert_enabled", True)).lower()),
            alert_false_selected=selected("false", str(config.get("alert_enabled", True)).lower()),
            stale_true_selected=selected("true", str(config.get("show_stale_marker", True)).lower()),
            stale_false_selected=selected("false", str(config.get("show_stale_marker", True)).lower()),
            dollar_true_selected=selected("true", str(config.get("show_dollar_change", True)).lower()),
            dollar_false_selected=selected("false", str(config.get("show_dollar_change", True)).lower()),
            percent_true_selected=selected("true", str(config.get("show_percent_change", True)).lower()),
            percent_false_selected=selected("false", str(config.get("show_percent_change", True)).lower()),
            stable_selected=selected("stable", config.get("update_channel", "stable")),
            beta_selected=selected("beta", config.get("update_channel", "stable")),
            after_purple_selected=selected("purple", config.get("after_hours_color", "purple")),
            after_normal_selected=selected("normal", config.get("after_hours_color", "purple")),
            closed_dates="\n".join(holidays["closed"]),
            early_close_dates="\n".join(holidays["early_close"])
        ),
        content_type="text/html"
    )


@server.route("/test-quote", methods=["POST"])
def test_quote_route(request: Request):
    global test_quote_message

    sym = clean_symbol(request.form_data.get("test_symbol", ""))

    if not sym:
        test_quote_message = "Enter a symbol first."
        return Response(request, clean_page("Test Failed", test_quote_message), content_type="text/html")

    try:
        url = FINNHUB_URL.format(sym, secrets["finnhub_api_key"])
        r = requests.get(url)
        data = r.json()
        r.close()

        price = data.get("c", 0)
        prev = data.get("pc", 0)

        if not price:
            test_quote_message = "{} did not return a valid price.".format(sym)
            set_error_message(test_quote_message)
        else:
            pct = ((price - prev) / prev) * 100 if prev else 0
            test_quote_message = "{} works: ${:.2f} ({:+.2f}%)".format(sym, price, pct)
            set_web_message(test_quote_message)

    except Exception as e:
        test_quote_message = "Quote test failed for {}: {}".format(sym, repr(e))
        set_error_message(test_quote_message)

    return Response(request, clean_page("Quote Test Complete", test_quote_message), content_type="text/html")


@server.route("/validate-symbols", methods=["POST"])
def validate_symbols_route(request: Request):
    global test_quote_message

    valid = []
    invalid = []

    for sym in SYMBOLS:
        try:
            server.poll()
        except Exception:
            pass

        try:
            url = FINNHUB_URL.format(sym, secrets["finnhub_api_key"])
            r = requests.get(url)
            data = r.json()
            r.close()

            price = data.get("c", 0)

            if price:
                valid.append("{} ${:.2f}".format(sym, price))
            else:
                invalid.append(sym)

        except Exception:
            invalid.append(sym)

        gc.collect()

    if invalid:
        test_quote_message = "Invalid/no data: " + ", ".join(invalid)
        set_error_message(test_quote_message)
    else:
        test_quote_message = "All symbols valid: " + ", ".join(valid)
        set_web_message("All saved symbols validated successfully.")

    return Response(request, clean_page("Symbol Validation Complete", test_quote_message), content_type="text/html")


@server.route("/save-symbols", methods=["POST"])
def save_symbols(request: Request):
    global SYMBOLS, need_reload

    try:
        raw = request.form_data.get("symbols", "")
        raw = url_decode(raw)

        if raw.startswith("symbols="):
            raw = raw.replace("symbols=", "", 1)

        raw = url_decode(raw)

        new_symbols = []
        seen = set()

        for line in raw.replace(",", "\n").replace("\r", "\n").split("\n"):
            s = clean_symbol(line)
            if s and s not in seen:
                new_symbols.append(s)
                seen.add(s)

        if not new_symbols:
            new_symbols = DEFAULT_SYMBOLS

        SYMBOLS = new_symbols
        save_symbol_list(SYMBOLS)
        need_reload = True
        set_web_message("Symbols saved.")

        return Response(request, clean_page("Symbols Saved", "Your ticker list was saved."), content_type="text/html")

    except Exception as e:
        set_error_message("Save symbols failed: " + repr(e))
        return Response(request, clean_page("Save Failed", last_error_message), content_type="text/html")


@server.route("/apply-watchlist", methods=["POST"])
def apply_watchlist(request: Request):
    global SYMBOLS, need_reload

    preset = clean_symbol(request.form_data.get("watchlist", "growth")).lower()

    if preset not in WATCHLISTS:
        preset = "growth"

    SYMBOLS = WATCHLISTS[preset]
    save_symbol_list(SYMBOLS)
    need_reload = True
    set_web_message("Applied {} watchlist.".format(preset))

    return Response(request, clean_page("Watchlist Applied", "Applied {} watchlist.".format(preset)), content_type="text/html")


@server.route("/save-config", methods=["POST"])
def save_cfg(request: Request):
    global config
    global BRIGHTNESS_TARGET
    global ALERT_PERCENT_MOVE
    global ALERT_ENABLED
    global FETCH_INTERVAL_OPEN
    global FETCH_INTERVAL_PRE_AFTER
    global FETCH_INTERVAL_CLOSED
    global SCROLL_SPEED_OPEN
    global SCROLL_SPEED_CLOSED
    global BLOCK_GAP
    global SCROLL_DELAY
    global need_reload

    try:
        form = request.form_data

        config["brightness"] = clamp_float(form.get("brightness", config["brightness"]), 0.0, 1.0, DEFAULT_CONFIG["brightness"])
        config["night_brightness"] = clamp_float(form.get("night_brightness", config["night_brightness"]), 0.0, 1.0, DEFAULT_CONFIG["night_brightness"])
        config["alert_percent_move"] = clamp_float(form.get("alert_percent_move", config["alert_percent_move"]), 0.0, 100.0, DEFAULT_CONFIG["alert_percent_move"])
        config["stale_quote_minutes"] = clamp_int(form.get("stale_quote_minutes", config.get("stale_quote_minutes", 15)), 1, 1440, DEFAULT_CONFIG["stale_quote_minutes"])

        config["fetch_interval_open"] = clamp_int(form.get("fetch_interval_open", config["fetch_interval_open"]), 5, 3600, DEFAULT_CONFIG["fetch_interval_open"])
        config["fetch_interval_pre_after"] = clamp_int(form.get("fetch_interval_pre_after", config["fetch_interval_pre_after"]), 10, 3600, DEFAULT_CONFIG["fetch_interval_pre_after"])
        config["fetch_interval_closed"] = clamp_int(form.get("fetch_interval_closed", config["fetch_interval_closed"]), 30, 7200, DEFAULT_CONFIG["fetch_interval_closed"])
        config["night_start_hour"] = clamp_int(form.get("night_start_hour", config["night_start_hour"]), 0, 23, DEFAULT_CONFIG["night_start_hour"])
        config["night_end_hour"] = clamp_int(form.get("night_end_hour", config["night_end_hour"]), 0, 23, DEFAULT_CONFIG["night_end_hour"])
        config["block_gap"] = clamp_int(form.get("block_gap", config["block_gap"]), 0, 120, DEFAULT_CONFIG["block_gap"])

        config["scroll_speed_open"] = clamp_float(form.get("scroll_speed_open", config["scroll_speed_open"]), 0.1, 5.0, DEFAULT_CONFIG["scroll_speed_open"])
        config["scroll_speed_closed"] = clamp_float(form.get("scroll_speed_closed", config["scroll_speed_closed"]), 0.1, 5.0, DEFAULT_CONFIG["scroll_speed_closed"])
        config["scroll_delay"] = clamp_float(form.get("scroll_delay", config["scroll_delay"]), 0.005, 0.20, DEFAULT_CONFIG["scroll_delay"])

        config["night_mode_enabled"] = bool_from_form(form.get("night_mode_enabled", config["night_mode_enabled"]))
        config["alert_enabled"] = bool_from_form(form.get("alert_enabled", config.get("alert_enabled", True)))
        config["show_dollar_change"] = bool_from_form(form.get("show_dollar_change", config.get("show_dollar_change", True)))
        config["show_percent_change"] = bool_from_form(form.get("show_percent_change", config.get("show_percent_change", True)))
        config["show_stale_marker"] = bool_from_form(form.get("show_stale_marker", config.get("show_stale_marker", True)))

        channel = url_decode(str(form.get("update_channel", config["update_channel"]))).strip().lower()
        config["update_channel"] = channel if channel in ("stable", "beta") else "stable"

        after_color = url_decode(str(form.get("after_hours_color", config.get("after_hours_color", "purple")))).strip().lower()
        config["after_hours_color"] = after_color if after_color in ("purple", "normal") else "purple"

        config["update_manifest_url"] = url_decode(str(form.get("update_manifest_url", config["update_manifest_url"]))).strip()

        save_config(config)

        BRIGHTNESS_TARGET = float(config["brightness"])
        ALERT_PERCENT_MOVE = float(config["alert_percent_move"])
        ALERT_ENABLED = bool_from_form(config.get("alert_enabled", True))
        FETCH_INTERVAL_OPEN = int(config["fetch_interval_open"])
        FETCH_INTERVAL_PRE_AFTER = int(config["fetch_interval_pre_after"])
        FETCH_INTERVAL_CLOSED = int(config["fetch_interval_closed"])
        SCROLL_SPEED_OPEN = float(config["scroll_speed_open"])
        SCROLL_SPEED_CLOSED = float(config["scroll_speed_closed"])
        BLOCK_GAP = int(config["block_gap"])
        SCROLL_DELAY = float(config["scroll_delay"])

        need_reload = True
        set_web_message("Settings saved.")

        return Response(request, clean_page("Config Saved", "Your settings were saved."), content_type="text/html")

    except Exception as e:
        set_error_message("Save config failed: " + repr(e))
        return Response(request, clean_page("Save Failed", last_error_message), content_type="text/html")


@server.route("/save-holidays", methods=["POST"])
def save_holidays_route(request: Request):
    global holidays

    try:
        form = request.form_data
        closed_raw = url_decode(str(form.get("closed", "")))
        early_raw = url_decode(str(form.get("early_close", "")))

        closed = []
        early = []

        for line in closed_raw.replace(",", "\n").replace("\r", "\n").split("\n"):
            d = clean_date(line)
            if len(d) == 10 and d not in closed:
                closed.append(d)

        for line in early_raw.replace(",", "\n").replace("\r", "\n").split("\n"):
            d = clean_date(line)
            if len(d) == 10 and d not in early:
                early.append(d)

        holidays = {
            "closed": closed,
            "early_close": early
        }

        save_holidays(holidays)
        set_web_message("Market holidays saved.")

        return Response(request, clean_page("Holidays Saved", "Market holiday file was saved."), content_type="text/html")

    except Exception as e:
        set_error_message("Save holidays failed: " + repr(e))
        return Response(request, clean_page("Save Failed", last_error_message), content_type="text/html")


@server.route("/refresh-now", methods=["POST"])
def refresh_now(request: Request):
    global refresh_requested
    refresh_requested = True
    set_web_message("Manual quote refresh requested.")

    return Response(request, clean_page("Refresh Requested", "Quotes will refresh after the current scroll cycle."), content_type="text/html")


@server.route("/clear-alerts", methods=["POST"])
def clear_alerts(request: Request):
    global alert_message
    alert_message = "Alert message cleared."
    set_web_message("Price alert message cleared.")

    return Response(request, clean_page("Alerts Cleared", "Price alert message cleared."), content_type="text/html")


@server.route("/check-system-health", methods=["POST"])
def check_system_health(request: Request):
    global system_health_message
    system_health_message = build_system_health_html()
    set_web_message("System health checked.")

    return Response(request, clean_page("System Health Checked", "Memory and disk health updated."), content_type="text/html")


@server.route("/clear-event-log", methods=["POST"])
def clear_event_log(request: Request):
    while event_log:
        del event_log[0]

    set_web_message("Event log cleared.")

    return Response(request, clean_page("Event Log Cleared", "Event log cleared."), content_type="text/html")


def fetch_update_manifest():
    try:
        url = config["update_manifest_url"]
        print("Checking manifest:", url)

        r = requests.get(url)
        text = r.text
        r.close()

        preview = text[:80]
        print("Manifest preview:", preview)

        stripped = text.strip()

        if not stripped.startswith("{"):
            set_error_message("Manifest URL returned HTML/text, not JSON. Check URL: " + url)
            return None

        manifest = json.loads(stripped)

        if "stable" not in manifest and "beta" not in manifest:
            set_error_message("Manifest JSON loaded but missing stable/beta keys.")
            return None

        return manifest

    except Exception as e:
        set_error_message("Manifest fetch failed: " + repr(e))
        return None


def get_channel_info(manifest):
    channel = config["update_channel"]

    if channel not in manifest:
        channel = "stable"

    return manifest[channel]


def build_ota_status_summary(manifest=None):
    channel = config.get("update_channel", "stable")
    backup_state = "Found" if file_exists(BACKUP_APP_PATH) else "Missing"
    manifest_state = "Not checked"
    stable_version = "unknown"
    beta_version = "unknown"
    selected_version = "unknown"
    selected_url = "unknown"

    if manifest:
        manifest_state = "OK"

        if "stable" in manifest:
            stable_version = str(manifest["stable"].get("version", "unknown"))

        if "beta" in manifest:
            beta_version = str(manifest["beta"].get("version", "unknown"))

        info = get_channel_info(manifest)
        selected_version = str(info.get("version", "unknown"))
        selected_url = str(info.get("app_url", "unknown"))

    return (
        "Current Version: {}<br>"
        "Current Channel: {}<br>"
        "Manifest URL: {}<br>"
        "Manifest Status: {}<br>"
        "Stable Online: {}<br>"
        "Beta Online: {}<br>"
        "Selected Version: {}<br>"
        "Selected URL: {}<br>"
        "Backup File: {}<br>"
        "Last OTA Message: {}"
    ).format(
        APP_VERSION,
        channel,
        config.get("update_manifest_url", ""),
        manifest_state,
        stable_version,
        beta_version,
        selected_version,
        selected_url,
        backup_state,
        ota_message
    )

@server.route("/check-cloud-status", methods=["POST"])
def check_cloud_status(request: Request):
    global cloud_status_message

    ota_ok = False
    quote_ok = False
    calendar_ok = False
    wifi_ok = False

    try:
        wifi_ok = wifi.radio.connected
    except Exception:
        wifi_ok = False

    try:
        r = requests.get(config["update_manifest_url"])
        text = r.text
        r.close()

        if text.strip().startswith("{"):
            ota_ok = True
    except Exception as e:
        set_error_message("OTA status check failed: " + repr(e))

    try:
        url = FINNHUB_URL.format("AAPL", secrets["finnhub_api_key"])
        r = requests.get(url)
        data = r.json()
        r.close()

        if data.get("c", 0):
            quote_ok = True
    except Exception as e:
        set_error_message("Quote API status check failed: " + repr(e))

    try:
        if "closed" in holidays and "early_close" in holidays:
            calendar_ok = True
    except Exception:
        calendar_ok = False

    cloud_status_message = (
        "WiFi: {}<br>"
        "OTA Server: {}<br>"
        "Quote API: {}<br>"
        "Time Sync: {}<br>"
        "Market Calendar: {}"
    ).format(
        "OK" if wifi_ok else "ERROR",
        "OK" if ota_ok else "ERROR",
        "OK" if quote_ok else "ERROR",
        "OK" if time_sync_ok else "ERROR",
        "OK" if calendar_ok else "ERROR"
    )

    set_web_message("Cloud status checked.")

    return Response(
        request,
        clean_page("Cloud Status Checked", "Cloud status updated."),
        content_type="text/html"
    )


@server.route("/check-ota-status", methods=["POST"])
def check_ota_status(request: Request):
    global ota_status_message

    manifest = fetch_update_manifest()

    if manifest is None:
        ota_status_message = build_ota_status_summary(None)
    else:
        ota_status_message = build_ota_status_summary(manifest)

    set_web_message("OTA status checked.")

    return Response(request, clean_page("OTA Status Checked", "OTA status section updated."), content_type="text/html")


@server.route("/check-update", methods=["POST"])
def check_update(request: Request):
    global ota_message, ota_status_message

    manifest = fetch_update_manifest()

    if manifest is None:
        ota_message = "Could not check for updates. Confirm manifest URL opens raw JSON."
    else:
        info = get_channel_info(manifest)
        latest = str(info.get("version", "unknown"))
        notes = str(info.get("notes", ""))

        if latest != APP_VERSION:
            ota_message = "Update available: {}. {}".format(latest, notes)
        else:
            ota_message = "You are up to date."

    if manifest is None:
        ota_status_message = build_ota_status_summary(None)
    else:
        ota_status_message = build_ota_status_summary(manifest)

    set_web_message(ota_message)

    return Response(request, clean_page("Update Check Complete", ota_message), content_type="text/html")


@server.route("/install-update", methods=["POST"])
def install_update(request: Request):
    global restart_requested, restart_time, ota_message, ota_status_message

    form = request.form_data
    entered_pin = url_decode(str(form.get("admin_pin", "")))

    if entered_pin != str(config["admin_pin"]):
        ota_message = "Wrong admin PIN."
        set_error_message(ota_message)
        return Response(request, clean_page("Update Blocked", ota_message), content_type="text/html")

    manifest = fetch_update_manifest()

    if manifest is None:
        ota_message = "Could not download update manifest."
        return Response(request, clean_page("Update Failed", ota_message), content_type="text/html")

    info = get_channel_info(manifest)
    latest = str(info.get("version", ""))
    app_url = str(info.get("app_url", ""))

    if latest == APP_VERSION:
        ota_message = "Already up to date."
        return Response(request, clean_page("No Update Needed", ota_message), content_type="text/html")

    if not app_url.startswith("http"):
        ota_message = "Bad update file URL."
        set_error_message(ota_message)
        return Response(request, clean_page("Update Failed", ota_message), content_type="text/html")

    try:
        print("Downloading update:", app_url)

        r = requests.get(app_url)
        new_code = r.text
        r.close()

        if len(new_code) < 1000:
            ota_message = "Downloaded app.py was too small."
            set_error_message(ota_message)
            return Response(request, clean_page("Update Failed", ota_message), content_type="text/html")

        if "APP.PY STARTED" not in new_code:
            ota_message = "Downloaded file does not look like app.py."
            set_error_message(ota_message)
            return Response(request, clean_page("Update Failed", ota_message), content_type="text/html")

        backup_ok, backup_msg = backup_current_app()

        if not backup_ok:
            ota_message = "OTA stopped. Backup failed."
            set_error_message("OTA stopped. " + backup_msg)
            return Response(request, clean_page("Update Failed", last_error_message), content_type="text/html")

        print(backup_msg)

        with open(APP_PATH, "w") as app_file:
            app_file.write(new_code)

        ota_message = "Installed version {}. Restarting...".format(latest)
        ota_status_message = build_ota_status_summary(manifest)
        restart_requested = True
        restart_time = time.monotonic() + 2.0
        set_web_message(ota_message)

        return Response(request, clean_page("Update Installed", ota_message), content_type="text/html")

    except Exception as e:
        ota_message = "Update failed."
        set_error_message("OTA install error: " + repr(e))

        return Response(request, clean_page("Update Failed", last_error_message), content_type="text/html")



@server.route("/rollback", methods=["POST"])
def rollback_route(request: Request):
    global restart_requested, restart_time, ota_message, ota_status_message

    form = request.form_data
    entered_pin = url_decode(str(form.get("admin_pin", "")))

    if entered_pin != str(config["admin_pin"]):
        ota_message = "Rollback blocked: wrong admin PIN."
        set_error_message(ota_message)
        return Response(request, clean_page("Rollback Blocked", ota_message), content_type="text/html")

    ok, msg = rollback_to_backup()

    if not ok:
        ota_message = "Rollback failed."
        set_error_message(msg)
        return Response(request, clean_page("Rollback Failed", msg), content_type="text/html")

    ota_message = "Rollback complete. Restarting..."
    ota_status_message = build_ota_status_summary(None)
    set_web_message(msg)

    restart_requested = True
    restart_time = time.monotonic() + 2.0

    return Response(request, clean_page("Rollback Complete", ota_message), content_type="text/html")


@server.route("/factory-reset", methods=["POST"])
def factory_reset(request: Request):
    global restart_requested, restart_time

    try:
        form = request.form_data
        entered_pin = url_decode(str(form.get("admin_pin", "")))
        reset_type = url_decode(str(form.get("reset_type", "wifi")))

        if entered_pin != str(config["admin_pin"]):
            set_error_message("Factory reset blocked: wrong admin PIN.")
            return Response(request, clean_page("Reset Blocked", "Wrong admin PIN."), content_type="text/html")

        files_to_remove = []

        if reset_type == "wifi":
            files_to_remove = [WIFI_FILE]
        elif reset_type == "settings":
            files_to_remove = [CONFIG_FILE]
        elif reset_type == "symbols":
            files_to_remove = [SYMBOLS_FILE]
        elif reset_type == "all":
            files_to_remove = [WIFI_FILE, CONFIG_FILE, SYMBOLS_FILE, HOLIDAYS_FILE]

        for path in files_to_remove:
            try:
                import os
                os.remove(path)
                print("Removed", path)
            except Exception as e:
                print("Could not remove", path, repr(e))

        restart_requested = True
        restart_time = time.monotonic() + 2.0

        return Response(request, clean_page("Factory Reset Complete", "Device will restart."), content_type="text/html")

    except Exception as e:
        set_error_message("Factory reset failed: " + repr(e))
        return Response(request, clean_page("Reset Failed", last_error_message), content_type="text/html")


@server.route("/restart", methods=["POST"])
def restart(request: Request):
    global restart_requested, restart_time

    restart_requested = True
    restart_time = time.monotonic() + 1.5

    return Response(request, clean_page("Restarting", "Device will restart in about 1.5 seconds."), content_type="text/html")


server.start(ip, 80)
print("Panel: http://" + ip + ":80/")


displayio.release_displays()

matrix = rgbmatrix.RGBMatrix(
    width=320,
    height=64,
    bit_depth=4,
    rgb_pins=[
        board.MTX_R1, board.MTX_G1, board.MTX_B1,
        board.MTX_R2, board.MTX_G2, board.MTX_B2
    ],
    addr_pins=[
        board.MTX_ADDRA, board.MTX_ADDRB, board.MTX_ADDRC,
        board.MTX_ADDRD, board.MTX_ADDRE
    ],
    clock_pin=board.MTX_CLK,
    latch_pin=board.MTX_LAT,
    output_enable_pin=board.MTX_OE,
)

display = framebufferio.FramebufferDisplay(matrix, auto_refresh=True)
matrix.brightness = 0.0

root = displayio.Group()
display.root_group = root

status_label = label.Label(terminalio.FONT, text="", color=0x00FF00, scale=1)
status_label.y = 4
root.append(status_label)

clock_label = label.Label(terminalio.FONT, text="--:--", color=0xFFFFFF, scale=1)
clock_label.y = 4
root.append(clock_label)


def load_logos():
    logos = {}

    for sym in SYMBOLS:
        path = "/logos/{}.bmp".format(sym)
        try:
            bmp = displayio.OnDiskBitmap(open(path, "rb"))
            logos[sym] = bmp
            print("Loaded logo:", sym)
        except Exception:
            print("No logo:", sym)

    return logos


logos = load_logos()


def update_header():
    et_now = eastern_time_now()
    status = get_market_status(et_now)

    clock_label.text = format_12h(et_now)
    status_label.text = status
    status_label.color = status_color(status)

    _, _, wc, _ = clock_label.bounding_box
    clock_label.x = display.width - wc - 2

    _, _, ws, _ = status_label.bounding_box
    status_label.x = clock_label.x - ws - 6

    return status


def fetch_quote(sym):
    now_text = format_12h(eastern_time_now())
    now_mono = time.monotonic()

    try:
        url = FINNHUB_URL.format(sym, secrets["finnhub_api_key"])
        r = requests.get(url)
        data = r.json()
        r.close()

        price = data.get("c", 0)
        prev = data.get("pc", 0)

        if not price:
            set_error_message("{} returned no valid price.".format(sym))
            return cached_or_error_quote(sym, "no valid price")

        dollar_change = price - prev if prev else 0
        pct = ((price - prev) / prev) * 100 if prev else 0
        color = 0x00FF00 if dollar_change >= 0 else 0xFF0000
        sign = "+" if dollar_change >= 0 else "-"

        alert = ""
        if ALERT_ENABLED and ALERT_PERCENT_MOVE > 0 and abs(pct) >= ALERT_PERCENT_MOVE:
            alert = "*" if pct > 0 else "!"

        change_parts = []

        if config.get("show_dollar_change", True):
            change_parts.append("{}${:.2f}".format(sign, abs(dollar_change)))

        if config.get("show_percent_change", True):
            change_parts.append("({:+.2f}%{})".format(pct, alert))

        if not change_parts:
            change_parts.append("{:+.2f}%{}".format(pct, alert))

        return {
            "symbol": sym,
            "price_line": "${} ${:.2f}".format(sym, price),
            "change_line": " ".join(change_parts),
            "color": color,
            "pct": pct,
            "updated_text": now_text,
            "updated_mono": now_mono,
            "stale": False,
            "used_cached": False,
            "error_reason": ""
        }

    except Exception as e:
        reason = repr(e)
        set_error_message("Fetch error for {}: {}".format(sym, reason))
        return cached_or_error_quote(sym, "fetch error")

def fetch_entries():
    global last_update_text, alert_message, quote_freshness_message

    entries = []

    for sym in SYMBOLS:
        try:
            server.poll()
        except Exception:
            pass

        e = fetch_quote(sym)
        entries.append(e)
        last_good[sym] = e
        gc.collect()

    last_update_text = format_12h(eastern_time_now())

    triggered = []
    stale_symbols = []

    if ALERT_ENABLED and ALERT_PERCENT_MOVE > 0:
        for e in entries:
            pct = float(e.get("pct", 0))
            if abs(pct) >= ALERT_PERCENT_MOVE and not e.get("stale", False):
                direction = "UP" if pct >= 0 else "DOWN"
                triggered.append("{} {} {:+.2f}%".format(e["symbol"], direction, pct))

    for e in entries:
        if quote_is_stale(e):
            stale_symbols.append(e["symbol"])

    if triggered:
        new_alert = "Triggered at {}: {}".format(last_update_text, ", ".join(triggered))
        if new_alert != alert_message:
            add_event("Price alert: " + ", ".join(triggered))
        alert_message = new_alert
    else:
        alert_message = "No alerts at {}. Threshold: +/-{:.2f}%".format(last_update_text, ALERT_PERCENT_MOVE)

    if stale_symbols:
        set_error_message("Stale quotes: " + ", ".join(stale_symbols))
    else:
        set_web_message("Quotes refreshed at " + last_update_text)

    quote_freshness_message = build_quote_freshness_html()

    return entries

def display_change_color(entry, after_hours):
    if after_hours and config.get("after_hours_color", "purple") == "purple":
        return 0xAA00FF

    return entry["color"]


def create_block(entry, after_hours):
    sym = entry["symbol"]

    g = displayio.Group()
    x_offset = 0

    logo_bmp = logos.get(sym)

    if logo_bmp:
        logo_grid = displayio.TileGrid(logo_bmp, pixel_shader=logo_bmp.pixel_shader)
        logo_grid.x = 0
        logo_grid.y = 22
        g.append(logo_grid)
        x_offset = logo_bmp.width + 3

    color = display_change_color(entry, after_hours)

    top = label.Label(terminalio.FONT, text=entry["price_line"], color=0xFFFFFF, scale=1)
    top.x = x_offset
    top.y = 24

    bottom = label.Label(terminalio.FONT, text=entry["change_line"], color=color, scale=1)
    bottom.x = x_offset
    bottom.y = 42

    g.append(top)
    g.append(bottom)
    root.append(g)

    width = max(115, x_offset + max(top.bounding_box[2], bottom.bounding_box[2]) + 6)

    return {
        "group": g,
        "symbol": sym,
        "x": 0.0,
        "width": float(width),
        "price_label": top,
        "change_label": bottom
    }


def update_blocks_from_entries(blocks, entries, after_hours):
    n = min(len(blocks), len(entries))

    for i in range(n):
        entry = entries[i]
        block = blocks[i]

        color = display_change_color(entry, after_hours)

        if block["price_label"].text != entry["price_line"]:
            block["price_label"].text = entry["price_line"]

        if block["change_label"].text != entry["change_line"]:
            block["change_label"].text = entry["change_line"]

        if block["change_label"].color != color:
            block["change_label"].color = color


def remove_blocks(blocks):
    for b in blocks:
        try:
            root.remove(b["group"])
        except Exception:
            pass


def build_blocks(entries, after_hours):
    blocks = []
    x = display.width

    for e in entries:
        b = create_block(e, after_hours)
        b["x"] = x
        b["group"].x = int(x)
        blocks.append(b)
        x += b["width"] + BLOCK_GAP

    return blocks


status = update_header()
after_hours = status != "OPN"

entries = fetch_entries()
blocks = build_blocks(entries, after_hours)
last_quote_fetch = time.monotonic()

completed_loops = 0


while True:
    try:
        server.poll()
    except Exception:
        pass

    now = time.monotonic()

    if restart_requested and now >= restart_time:
        microcontroller.reset()

    if now - last_ntp_sync >= 21600:
        sync_time()
        last_ntp_sync = now

    status = update_header()
    after_hours = status != "OPN"

    scroll_speed = SCROLL_SPEED_OPEN if status == "OPN" else SCROLL_SPEED_CLOSED

    for b in blocks:
        b["x"] -= scroll_speed
        b["group"].x = int(b["x"])

    max_right = max((b["x"] + b["width"]) for b in blocks) if blocks else 0
    loop_completed = False

    for b in blocks:
        if b["x"] + b["width"] < 0:
            b["x"] = max_right + BLOCK_GAP
            b["group"].x = int(b["x"])
            max_right = b["x"] + b["width"]
            loop_completed = True

    if loop_completed:
        completed_loops += 1

    if status == "OPN":
        fetch_interval = FETCH_INTERVAL_OPEN
    elif status == "PRE" or status == "AFT":
        fetch_interval = FETCH_INTERVAL_PRE_AFTER
    else:
        fetch_interval = FETCH_INTERVAL_CLOSED

    time_for_quote_fetch = now - last_quote_fetch >= fetch_interval
    full_scroll_done = completed_loops >= len(blocks)

    if (refresh_requested or (time_for_quote_fetch and full_scroll_done)) and not need_reload:
        completed_loops = 0
        refresh_requested = False
        last_quote_fetch = now

        new_entries = fetch_entries()
        update_blocks_from_entries(blocks, new_entries, after_hours)

    if need_reload:
        need_reload = False
        completed_loops = 0
        remove_blocks(blocks)
        logos = load_logos()
        entries = fetch_entries()
        blocks = build_blocks(entries, after_hours)
        last_quote_fetch = now

    target_brightness = BRIGHTNESS_TARGET

    if night_mode_active(status):
        target_brightness = float(config["night_brightness"])

    if matrix.brightness < target_brightness:
        matrix.brightness = min(matrix.brightness + BRIGHTNESS_RAMP_STEP, target_brightness)
    elif matrix.brightness > target_brightness:
        matrix.brightness = max(matrix.brightness - BRIGHTNESS_RAMP_STEP, target_brightness)

    time.sleep(SCROLL_DELAY)
