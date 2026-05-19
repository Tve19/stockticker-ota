print("APP.PY STARTED")

APP_VERSION = "1.1.2"

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
    "night_end_hour": 7
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
        save_json_file(DEVICE_FILE, info)

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


config = load_config()
device_info = load_device_info()
DEVICE_ID = device_info["device_id"]

holidays = load_holidays()
SYMBOLS = read_symbols_file() or DEFAULT_SYMBOLS

BRIGHTNESS_TARGET = float(config["brightness"])
BRIGHTNESS_RAMP_STEP = 0.01
SCROLL_SPEED_OPEN = float(config["scroll_speed_open"])
SCROLL_SPEED_CLOSED = float(config["scroll_speed_closed"])
FETCH_INTERVAL_OPEN = int(config["fetch_interval_open"])
ALERT_PERCENT_MOVE = float(config["alert_percent_move"])
BLOCK_GAP = int(config["block_gap"])
SCROLL_DELAY = float(config["scroll_delay"])

need_reload = False
refresh_requested = False
restart_requested = False
restart_time = 0
last_good = {}
last_update_text = "--:--"
ota_message = "No update checked yet."
last_web_message = "System ready."
last_error_message = "None yet."
test_quote_message = "No quote tested yet."


def set_web_message(message):
    global last_web_message
    last_web_message = message
    print("WEB STATUS:", message)


def set_error_message(message):
    global last_error_message
    last_error_message = message
    print("WEB ERROR:", message)


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
    try:
        ntp = adafruit_ntp.NTP(pool, server="pool.ntp.org", tz_offset=0)
        rtc.RTC().datetime = ntp.datetime
        print("Time synced")
    except Exception as e:
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
<title>Stock Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ background:#101018; color:white; font-family:Arial; padding:20px; }}
.card {{ background:#1b1b2a; padding:16px; border-radius:12px; margin-bottom:16px; }}
textarea, input, select {{ width:100%; box-sizing:border-box; margin:8px 0 14px; padding:10px; border-radius:8px; border:1px solid #333; background:#080812; color:white; }}
button {{ padding:10px 14px; border:0; border-radius:8px; background:#1f8cff; color:white; font-weight:bold; margin-top:6px; }}
.red {{ background:#cc3333; }}
.green {{ background:#22aa66; }}
.small {{ color:#bbbbbb; font-size:13px; }}
.good {{ color:#55ff88; }}
.bad {{ color:#ff7777; }}
</style>
</head>
<body>
<h1>Stock Ticker Control Panel</h1>
<p>Version: {version}</p>
<p>Device ID: {device_id}</p>
<p>IP: {ip}</p>
<p>Last Quote Update: {last_update}</p>
<p class="good">Status: {last_web_message}</p>
<p class="bad">Last Error: {last_error_message}</p>

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
<h2>Tickers</h2>
<form method="POST" action="/save-symbols">
<textarea name="symbols">{symbols}</textarea>
<button class="green" type="submit">Save Symbols</button>
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

<div class="card">
<h2>Settings</h2>
<form method="POST" action="/save-config">
<label>Brightness</label>
<input name="brightness" value="{brightness}">
<label>Alert Percent Move</label>
<input name="alert_percent_move" value="{alert_percent_move}">
<label>Open Refresh Seconds</label>
<input name="fetch_interval_open" value="{fetch_interval_open}">
<label>Scroll Speed Open</label>
<input name="scroll_speed_open" value="{scroll_speed_open}">
<label>Scroll Speed Closed</label>
<input name="scroll_speed_closed" value="{scroll_speed_closed}">
<label>Block Gap</label>
<input name="block_gap" value="{block_gap}">
<label>Night Mode Enabled</label>
<select name="night_mode_enabled">
<option value="true">True</option>
<option value="false">False</option>
</select>
<label>Night Brightness</label>
<input name="night_brightness" value="{night_brightness}">
<label>Night Start Hour ET</label>
<input name="night_start_hour" value="{night_start_hour}">
<label>Night End Hour ET</label>
<input name="night_end_hour" value="{night_end_hour}">
<label>Update Channel</label>
<select name="update_channel">
<option value="stable">Stable</option>
<option value="beta">Beta</option>
</select>
<label>Manifest URL</label>
<input name="update_manifest_url" value="{update_manifest_url}">
<button class="green" type="submit">Save Config</button>
</form>
</div>

<div class="card">
<h2>Market Holidays</h2>
<p class="small">One date per line. Format: YYYY-MM-DD</p>
<form method="POST" action="/save-holidays">
<label>Full Market Closures</label>
<textarea name="closed">{closed_dates}</textarea>
<label>Early Close Days</label>
<textarea name="early_close">{early_close_dates}</textarea>
<button class="green" type="submit">Save Holidays</button>
</form>
</div>

<div class="card">
<h2>Refresh Quotes</h2>
<form method="POST" action="/refresh-now">
<button type="submit">Refresh Quotes Now</button>
</form>
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

<div class="card">
<h2>Restart</h2>
<form method="POST" action="/restart">
<button class="red" type="submit">Restart Device</button>
</form>
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
    return Response(
        request,
        HTML.format(
            version=APP_VERSION,
            device_id=DEVICE_ID,
            ip=ip,
            symbols="\n".join(SYMBOLS),
            brightness=config["brightness"],
            alert_percent_move=config["alert_percent_move"],
            fetch_interval_open=config["fetch_interval_open"],
            scroll_speed_open=config["scroll_speed_open"],
            scroll_speed_closed=config["scroll_speed_closed"],
            block_gap=config["block_gap"],
            ota_message=ota_message,
            last_update=last_update_text,
            last_web_message=last_web_message,
            last_error_message=last_error_message,
            test_quote_message=test_quote_message,
            night_brightness=config["night_brightness"],
            night_start_hour=config["night_start_hour"],
            night_end_hour=config["night_end_hour"],
            update_manifest_url=config["update_manifest_url"],
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
    global FETCH_INTERVAL_OPEN
    global SCROLL_SPEED_OPEN
    global SCROLL_SPEED_CLOSED
    global BLOCK_GAP
    global need_reload

    try:
        form = request.form_data

        config["brightness"] = float(url_decode(str(form.get("brightness", config["brightness"]))))
        config["alert_percent_move"] = float(url_decode(str(form.get("alert_percent_move", config["alert_percent_move"]))))
        config["fetch_interval_open"] = int(float(url_decode(str(form.get("fetch_interval_open", config["fetch_interval_open"])))))
        config["scroll_speed_open"] = float(url_decode(str(form.get("scroll_speed_open", config["scroll_speed_open"]))))
        config["scroll_speed_closed"] = float(url_decode(str(form.get("scroll_speed_closed", config["scroll_speed_closed"]))))
        config["block_gap"] = int(float(url_decode(str(form.get("block_gap", config["block_gap"])))))
        config["night_mode_enabled"] = bool_from_form(form.get("night_mode_enabled", config["night_mode_enabled"]))
        config["night_brightness"] = float(url_decode(str(form.get("night_brightness", config["night_brightness"]))))
        config["night_start_hour"] = int(float(url_decode(str(form.get("night_start_hour", config["night_start_hour"])))))
        config["night_end_hour"] = int(float(url_decode(str(form.get("night_end_hour", config["night_end_hour"])))))
        config["update_channel"] = url_decode(str(form.get("update_channel", config["update_channel"])))
        config["update_manifest_url"] = url_decode(str(form.get("update_manifest_url", config["update_manifest_url"]))).strip()

        if config["brightness"] < 0:
            config["brightness"] = 0
        if config["brightness"] > 1:
            config["brightness"] = 1

        if config["night_brightness"] < 0:
            config["night_brightness"] = 0
        if config["night_brightness"] > 1:
            config["night_brightness"] = 1

        save_config(config)

        BRIGHTNESS_TARGET = float(config["brightness"])
        ALERT_PERCENT_MOVE = float(config["alert_percent_move"])
        FETCH_INTERVAL_OPEN = int(config["fetch_interval_open"])
        SCROLL_SPEED_OPEN = float(config["scroll_speed_open"])
        SCROLL_SPEED_CLOSED = float(config["scroll_speed_closed"])
        BLOCK_GAP = int(config["block_gap"])

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


@server.route("/check-update", methods=["POST"])
def check_update(request: Request):
    global ota_message

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

    set_web_message(ota_message)

    return Response(request, clean_page("Update Check Complete", ota_message), content_type="text/html")


@server.route("/install-update", methods=["POST"])
def install_update(request: Request):
    global restart_requested, restart_time, ota_message

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

        try:
            with open("/app.py", "r") as old_file:
                old_code = old_file.read()

            with open("/app_backup.py", "w") as backup_file:
                backup_file.write(old_code)
        except Exception as e:
            print("Backup failed:", repr(e))

        with open("/app.py", "w") as app_file:
            app_file.write(new_code)

        ota_message = "Installed version {}. Restarting...".format(latest)
        restart_requested = True
        restart_time = time.monotonic() + 2.0
        set_web_message(ota_message)

        return Response(request, clean_page("Update Installed", ota_message), content_type="text/html")

    except Exception as e:
        ota_message = "Update failed."
        set_error_message("OTA install error: " + repr(e))

        return Response(request, clean_page("Update Failed", last_error_message), content_type="text/html")


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
    try:
        url = FINNHUB_URL.format(sym, secrets["finnhub_api_key"])
        r = requests.get(url)
        data = r.json()
        r.close()

        price = data.get("c", 0)
        prev = data.get("pc", 0)

        if not price:
            if sym in last_good:
                return last_good[sym]

            set_error_message("{} returned no valid price.".format(sym))

            return {
                "symbol": sym,
                "price_line": "${} ERROR".format(sym),
                "change_line": "",
                "color": 0xFF0000,
                "pct": 0
            }

        dollar_change = price - prev if prev else 0
        pct = ((price - prev) / prev) * 100 if prev else 0
        color = 0x00FF00 if dollar_change >= 0 else 0xFF0000
        sign = "+" if dollar_change >= 0 else "-"

        alert = ""
        if abs(pct) >= ALERT_PERCENT_MOVE:
            alert = "*" if pct > 0 else "!"

        return {
            "symbol": sym,
            "price_line": "${} ${:.2f}".format(sym, price),
            "change_line": "{}${:.2f} ({:+.2f}%{})".format(
                sign,
                abs(dollar_change),
                pct,
                alert
            ),
            "color": color,
            "pct": pct
        }

    except Exception as e:
        set_error_message("Fetch error for {}: {}".format(sym, repr(e)))

        if sym in last_good:
            return last_good[sym]

        return {
            "symbol": sym,
            "price_line": "${} ERROR".format(sym),
            "change_line": "",
            "color": 0xFF0000,
            "pct": 0
        }


def fetch_entries():
    global last_update_text

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

    return entries


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

    color = 0xAA00FF if after_hours else entry["color"]

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

        color = 0xAA00FF if after_hours else entry["color"]

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

    if (completed_loops >= len(blocks) or refresh_requested) and not need_reload:
        completed_loops = 0
        refresh_requested = False

        new_entries = fetch_entries()
        update_blocks_from_entries(blocks, new_entries, after_hours)

    if need_reload:
        need_reload = False
        completed_loops = 0
        remove_blocks(blocks)
        logos = load_logos()
        entries = fetch_entries()
        blocks = build_blocks(entries, after_hours)

    target_brightness = BRIGHTNESS_TARGET

    if night_mode_active(status):
        target_brightness = float(config["night_brightness"])

    if matrix.brightness < target_brightness:
        matrix.brightness = min(matrix.brightness + BRIGHTNESS_RAMP_STEP, target_brightness)
    elif matrix.brightness > target_brightness:
        matrix.brightness = max(matrix.brightness - BRIGHTNESS_RAMP_STEP, target_brightness)

    time.sleep(SCROLL_DELAY)
