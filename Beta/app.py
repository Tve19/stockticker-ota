print("APP.PY STARTED")

APP_VERSION = "1.1.22-bootstrap"
CONFIG_SCHEMA_VERSION = 2
PORTFOLIO_API_SCHEMA_SUPPORTED = 1
DEVICE_MODEL = "matrix_portal_s3"

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
try:
    import hashlib
except Exception:
    hashlib = None



# Software SHA-256 fallback for CircuitPython builds whose native hashlib
# module is present but does not expose the sha256 algorithm.
class _SoftwareSHA256:
    _K = (
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    )

    def __init__(self):
        self._state = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ]
        self._buffer = bytearray()
        self._length = 0
        self._finished = False

    @staticmethod
    def _ror(value, count):
        value &= 0xFFFFFFFF
        return (
            (value >> count)
            | ((value << (32 - count)) & 0xFFFFFFFF)
        ) & 0xFFFFFFFF

    def _process(self, block):
        words = [0] * 64

        for i in range(16):
            j = i * 4
            words[i] = (
                (block[j] << 24)
                | (block[j + 1] << 16)
                | (block[j + 2] << 8)
                | block[j + 3]
            )

        for i in range(16, 64):
            x = words[i - 15]
            y = words[i - 2]
            s0 = (
                self._ror(x, 7)
                ^ self._ror(x, 18)
                ^ (x >> 3)
            )
            s1 = (
                self._ror(y, 17)
                ^ self._ror(y, 19)
                ^ (y >> 10)
            )
            words[i] = (
                words[i - 16]
                + s0
                + words[i - 7]
                + s1
            ) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self._state

        for i in range(64):
            s1 = (
                self._ror(e, 6)
                ^ self._ror(e, 11)
                ^ self._ror(e, 25)
            )
            choose = (e & f) ^ ((~e) & g)
            t1 = (
                h
                + s1
                + choose
                + self._K[i]
                + words[i]
            ) & 0xFFFFFFFF
            s0 = (
                self._ror(a, 2)
                ^ self._ror(a, 13)
                ^ self._ror(a, 22)
            )
            majority = (a & b) ^ (a & c) ^ (b & c)
            t2 = (s0 + majority) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        values = (a, b, c, d, e, f, g, h)

        for i in range(8):
            self._state[i] = (
                self._state[i] + values[i]
            ) & 0xFFFFFFFF

    def update(self, data):
        if self._finished:
            raise ValueError("SHA-256 digest already finalized")

        if not data:
            return

        self._length += len(data)
        self._buffer.extend(data)

        while len(self._buffer) >= 64:
            block = self._buffer[:64]
            del self._buffer[:64]
            self._process(block)

    def digest(self):
        if not self._finished:
            bit_length = self._length * 8
            final_data = bytearray(self._buffer)
            final_data.append(0x80)

            while len(final_data) % 64 != 56:
                final_data.append(0)

            for shift in (56, 48, 40, 32, 24, 16, 8, 0):
                final_data.append((bit_length >> shift) & 0xFF)

            for start in range(0, len(final_data), 64):
                self._process(final_data[start:start + 64])

            self._finished = True
            self._buffer = bytearray()

        output = bytearray()

        for word in self._state:
            output.extend((
                (word >> 24) & 0xFF,
                (word >> 16) & 0xFF,
                (word >> 8) & 0xFF,
                word & 0xFF,
            ))

        return bytes(output)


def create_sha256_hasher():
    if hashlib is not None:
        try:
            return hashlib.new("sha256"), "native"
        except Exception as e:
            print(
                "Native SHA-256 unavailable; using software fallback:",
                repr(e)
            )

    return _SoftwareSHA256(), "software"


from adafruit_display_text import label
try:
    from secrets import secrets
except Exception:
    secrets = {
        "ssid": "",
        "password": "",
        "finnhub_api_key": ""
    }
from adafruit_httpserver import Server, Request, Response


CONFIG_FILE = "/config.json"
SYMBOLS_FILE = "/symbols.txt"
WIFI_FILE = "/wifi_config.json"
HOLIDAYS_FILE = "/market_holidays.json"
DEVICE_FILE = "/device.json"
CRASH_FILE = "/crash_count.json"

DEFAULT_CONFIG = {
    "config_schema_version": CONFIG_SCHEMA_VERSION,
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
    "show_stale_marker": True,
    "smooth_quote_refresh": True,
    "show_logos": True,
    "finnhub_api_key": "",
    "require_customer_api_key": True,
    "demo_mode": False,
    "device_name": "StockTicker",
    "customer_mode": "basic",
    "panel_sleep": False,
    "portfolio_mode": "off",
    "portfolio_bridge_url": "",
    "portfolio_bridge_key": "",
    "portfolio_prefer_api_v1": True,
    "portfolio_show_value": True,
    "portfolio_show_day_change": True,
    "portfolio_show_cash": True,
    "portfolio_show_buying_power": True,
    "portfolio_show_positions_count": True,
    "portfolio_show_largest_winner": True,
    "portfolio_show_largest_loser": True,
    "portfolio_privacy_mode": False,
    "portfolio_stale_minutes": 15,
    "portfolio_capabilities_refresh_minutes": 60
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
    changed = False

    for key in DEFAULT_CONFIG:
        if key not in cfg:
            cfg[key] = DEFAULT_CONFIG[key]
            changed = True

    try:
        current_schema = int(cfg.get("config_schema_version", 0) or 0)
    except Exception:
        current_schema = 0

    if current_schema < CONFIG_SCHEMA_VERSION:
        cfg["config_schema_version"] = CONFIG_SCHEMA_VERSION
        changed = True

    if changed:
        try:
            save_json_file(CONFIG_FILE, cfg)
            print("Config migrated to schema", CONFIG_SCHEMA_VERSION)
        except OSError as e:
            print("Config migration could not save:", repr(e))
        except Exception as e:
            print("Config migration failed:", repr(e))

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


def mask_secret(value):
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= 6:
        return "******"
    return value[:3] + "..." + value[-3:]


def customer_api_required():
    return bool_from_form(config.get("require_customer_api_key", True))


def get_saved_customer_api_key():
    try:
        return str(config.get("finnhub_api_key", "")).strip()
    except Exception:
        return ""


def get_finnhub_api_key():
    key = get_saved_customer_api_key()
    if key:
        return key

    if customer_api_required():
        return ""

    try:
        return str(secrets.get("finnhub_api_key", "")).strip()
    except Exception:
        return ""


def get_api_key_status():
    saved_key = get_saved_customer_api_key()
    if saved_key:
        return "Saved in device settings: " + mask_secret(saved_key)

    if customer_api_required():
        return "Required mode ON - missing customer API key. Quotes will not load until setup is completed."

    try:
        fallback_key = str(secrets.get("finnhub_api_key", "")).strip()
        if fallback_key:
            return "Fallback mode: loaded from secrets.py " + mask_secret(fallback_key)
    except Exception:
        pass

    return "Missing - enter a Finnhub API key in Customer Setup."


def mark_app_boot_success():
    try:
        save_json_file(CRASH_FILE, {"count": 0, "last_good_version": APP_VERSION})
    except Exception as e:
        print("Could not reset crash counter:", repr(e))


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
SMOOTH_QUOTE_REFRESH = bool_from_form(config.get("smooth_quote_refresh", True))

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
portfolio_test_message = "No portfolio bridge tested yet."
cloud_status_message = "Cloud status not checked yet."
alert_message = "No price alerts yet."
quote_freshness_message = "No quote freshness checked yet."
system_health_message = "Press Check System Health to refresh memory and disk stats."
release_notes_message = "Press Check Release Notes to load stable/beta notes from your OTA manifest."
auto_recovery_message = "Auto-recovery launcher not checked yet."
last_portfolio_entry = None
last_portfolio_capabilities = {}
last_portfolio_capabilities_check = 0
last_portfolio_api_status = {
    "mode": "not_checked",
    "api_version": "unknown",
    "schema_version": "unknown",
    "bridge_version": "unknown",
    "capabilities": False,
    "last_error": ""
}
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


def safe_attr(text):
    text = safe_html(text)
    text = text.replace('"', "&quot;")
    text = text.replace("'", "&#39;")
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
        "Backup Size: {}<br>"
        "Auto-Recovery Launcher: {}"
    ).format(
        hours,
        minutes,
        seconds,
        free_mem,
        used_mem,
        disk_text,
        file_size_text(APP_PATH),
        file_size_text(BACKUP_APP_PATH),
        launcher_status_text()
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


PORTFOLIO_SYMBOL = "__PORTFOLIO__"


def is_portfolio_enabled():
    return str(config.get("portfolio_mode", "off")).strip().lower() == "local_bridge"


def is_portfolio_entry(entry):
    try:
        return entry.get("symbol") == PORTFOLIO_SYMBOL or entry.get("entry_type") == "portfolio"
    except Exception:
        return False


def money_text(value):
    try:
        return "${:,.0f}".format(float(value))
    except Exception:
        return "$0"


def signed_money_text(value):
    try:
        v = float(value)
        sign = "+" if v >= 0 else "-"
        return "{}${:,.0f}".format(sign, abs(v))
    except Exception:
        return "+$0"


def portfolio_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def portfolio_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def append_bridge_key(url, key):
    url = str(url).strip()
    key = str(key).strip()

    if not url or not key:
        return url

    if "key=" in url:
        return url

    joiner = "&" if "?" in url else "?"
    return url + joiner + "key=" + key


def portfolio_bridge_base_url():
    url = str(config.get("portfolio_bridge_url", "")).strip()

    if not url:
        return ""

    url = url.split("#", 1)[0].split("?", 1)[0].rstrip("/")

    for suffix in (
        "/api/v1/portfolio",
        "/api/v1/capabilities",
        "/portfolio"
    ):
        if url.endswith(suffix):
            url = url[:-len(suffix)].rstrip("/")
            break

    return url


def portfolio_bridge_dashboard_url():
    base = portfolio_bridge_base_url()

    if not base:
        return ""

    return base + "/dashboard"


def portfolio_bridge_health_url():
    base = portfolio_bridge_base_url()

    if not base:
        return ""

    return base + "/health"


def build_portfolio_bridge_links_html():
    dashboard_url = portfolio_bridge_dashboard_url()
    health_url = portfolio_bridge_health_url()

    if not dashboard_url:
        return (
            "<span class='linkbtn disabled'>"
            "Save Bridge URL First"
            "</span>"
        )

    return (
        "<a class='linkbtn portfolio-link' "
        "href='{}' target='_blank' rel='noopener'>"
        "Open Portfolio Dashboard"
        "</a>"
        "<a class='linkbtn secondary-link' "
        "href='{}' target='_blank' rel='noopener'>"
        "Bridge Health"
        "</a>"
    ).format(
        safe_attr(dashboard_url),
        safe_attr(health_url)
    )


def portfolio_legacy_url():
    configured = str(config.get("portfolio_bridge_url", "")).strip()

    if configured:
        clean = configured.split("#", 1)[0].split("?", 1)[0].rstrip("/")
        if clean.endswith("/portfolio") and not clean.endswith("/api/v1/portfolio"):
            return clean

    base = portfolio_bridge_base_url()
    if not base:
        return ""

    return base + "/portfolio"


def portfolio_v1_url():
    base = portfolio_bridge_base_url()
    if not base:
        return ""

    return base + "/api/v1/portfolio"


def portfolio_capabilities_url():
    base = portfolio_bridge_base_url()
    if not base:
        return ""

    return base + "/api/v1/capabilities"


def bridge_request_json(url, key="", use_header=True):
    response = None

    try:
        if use_header and key:
            response = requests.get(
                url,
                headers={"X-Bridge-Key": key}
            )
        else:
            response = requests.get(
                append_bridge_key(url, key)
            )

        data = response.json()

        if not isinstance(data, dict):
            raise Exception("Bridge returned non-object JSON.")

        if data.get("error"):
            raise Exception(str(data.get("error")))

        return data

    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass


def record_portfolio_api_status(mode, data=None, error_text=""):
    global last_portfolio_api_status

    data = data if isinstance(data, dict) else {}

    last_portfolio_api_status = {
        "mode": str(mode),
        "api_version": str(data.get("api_version", "legacy" if mode == "legacy" else "unknown")),
        "schema_version": str(data.get("schema_version", "legacy" if mode == "legacy" else "unknown")),
        "bridge_version": str(data.get("bridge_version", "unknown")),
        "capabilities": bool(last_portfolio_capabilities.get("available", False)),
        "last_error": str(error_text)
    }


def fetch_bridge_capabilities(force=False):
    global last_portfolio_capabilities
    global last_portfolio_capabilities_check

    if not is_portfolio_enabled():
        return {}

    now = time.monotonic()

    try:
        refresh_seconds = int(
            config.get("portfolio_capabilities_refresh_minutes", 60)
        ) * 60
    except Exception:
        refresh_seconds = 3600

    if (
        not force
        and last_portfolio_capabilities
        and now - last_portfolio_capabilities_check < refresh_seconds
    ):
        return last_portfolio_capabilities

    url = portfolio_capabilities_url()
    key = str(config.get("portfolio_bridge_key", "")).strip()

    if not url:
        return {}

    try:
        data = bridge_request_json(url, key, True)
        schema = portfolio_int(data.get("schema_version", 0), 0)
        data["available"] = True
        data["compatible"] = (
            schema <= PORTFOLIO_API_SCHEMA_SUPPORTED
            if schema > 0 else True
        )

        last_portfolio_capabilities = data
        last_portfolio_capabilities_check = now
        add_event(
            "Bridge capabilities loaded: API {} schema {}.".format(
                data.get("api_version", "unknown"),
                data.get("schema_version", "unknown")
            )
        )
        return data

    except Exception as e:
        last_portfolio_capabilities = {
            "available": False,
            "compatible": True,
            "error": repr(e)
        }
        last_portfolio_capabilities_check = now
        add_event(
            "Bridge capabilities unavailable; legacy fallback remains enabled."
        )
        return last_portfolio_capabilities


def fetch_portfolio_payload():
    key = str(config.get("portfolio_bridge_key", "")).strip()
    prefer_v1 = bool_from_form(
        config.get("portfolio_prefer_api_v1", True)
    )

    v1_url = portfolio_v1_url()
    legacy_url = portfolio_legacy_url()
    attempts = []

    if prefer_v1:
        if v1_url:
            attempts.append(("v1", v1_url, True))
        if legacy_url:
            attempts.append(("legacy", legacy_url, True))
    else:
        if legacy_url:
            attempts.append(("legacy", legacy_url, True))
        if v1_url:
            attempts.append(("v1", v1_url, True))

    if not attempts:
        raise Exception("Missing portfolio bridge URL.")

    errors = []

    for mode, url, use_header in attempts:
        try:
            data = bridge_request_json(url, key, use_header)

            if mode == "v1":
                schema = portfolio_int(data.get("schema_version", 0), 0)

                if (
                    schema > 0
                    and schema > PORTFOLIO_API_SCHEMA_SUPPORTED
                ):
                    raise Exception(
                        "Unsupported bridge schema {}.".format(schema)
                    )

            record_portfolio_api_status(mode, data)
            return data, mode

        except Exception as e:
            errors.append("{}: {}".format(mode, repr(e)))

    record_portfolio_api_status(
        "failed",
        {},
        "; ".join(errors)
    )
    raise Exception("; ".join(errors))


def mover_text(value, prefix, privacy=False):
    if not isinstance(value, dict):
        return ""

    symbol = clean_symbol(value.get("symbol", ""))

    if not symbol:
        return ""

    if privacy:
        return "{} {}".format(prefix, symbol)

    change = portfolio_float(value.get("day_change", 0), 0)
    return "{} {} {}".format(
        prefix,
        symbol,
        signed_money_text(change)
    )


def make_portfolio_entry(data, stale_override=False, error_reason=""):
    privacy = bool_from_form(
        config.get("portfolio_privacy_mode", False)
    )
    show_value = bool_from_form(
        config.get("portfolio_show_value", True)
    ) and not privacy
    show_change = bool_from_form(
        config.get("portfolio_show_day_change", True)
    )
    show_cash = bool_from_form(
        config.get("portfolio_show_cash", True)
    ) and not privacy
    show_buying_power = bool_from_form(
        config.get("portfolio_show_buying_power", True)
    ) and not privacy
    show_positions = bool_from_form(
        config.get("portfolio_show_positions_count", True)
    )
    show_winner = bool_from_form(
        config.get("portfolio_show_largest_winner", True)
    )
    show_loser = bool_from_form(
        config.get("portfolio_show_largest_loser", True)
    )

    value = portfolio_float(data.get("portfolio_value", 0), 0)
    day_change = portfolio_float(data.get("day_change", 0), 0)
    day_percent = portfolio_float(data.get("day_percent", 0), 0)
    cash = portfolio_float(data.get("cash", 0), 0)
    buying_power = portfolio_float(data.get("buying_power", 0), 0)
    positions_count = portfolio_int(
        data.get("positions_count", 0),
        0
    )
    updated = str(
        data.get(
            "last_successful_sync",
            data.get("updated", "unknown")
        )
    )
    age_seconds = portfolio_int(data.get("age_seconds", 0), 0)

    try:
        stale_limit = int(
            config.get("portfolio_stale_minutes", 15)
        ) * 60
    except Exception:
        stale_limit = 900

    stale = (
        bool(data.get("stale", False))
        or bool(data.get("data_stale", False))
        or stale_override
        or age_seconds > stale_limit
    )
    color = 0x00FF00 if day_change >= 0 else 0xFF0000

    if privacy:
        top = "PORTFOLIO PRIVATE"
    elif show_value:
        top = "PORTFOLIO " + money_text(value)
    else:
        top = "PORTFOLIO"

    parts = []

    if privacy:
        if show_positions:
            parts.append("POS " + str(positions_count))
        parts.append("PRIVATE")
    else:
        if show_change:
            parts.append(
                "{} ({:+.2f}%)".format(
                    signed_money_text(day_change),
                    day_percent
                )
            )
        if show_cash:
            parts.append("CASH " + money_text(cash))
        if show_buying_power:
            parts.append("BP " + money_text(buying_power))
        if show_positions:
            parts.append("POS " + str(positions_count))
        if show_winner:
            winner_text = mover_text(
                data.get("largest_winner"),
                "WIN",
                False
            )
            if winner_text:
                parts.append(winner_text)
        if show_loser:
            loser_text = mover_text(
                data.get("largest_loser"),
                "LOSS",
                False
            )
            if loser_text:
                parts.append(loser_text)

    if not parts:
        parts.append("UPDATED " + updated)

    bottom = " ".join(parts)

    if stale:
        bottom = bottom + " OLD " + updated

    if error_reason:
        bottom = "OFFLINE OLD " + updated
        color = 0xFFAA00

    return {
        "symbol": PORTFOLIO_SYMBOL,
        "entry_type": "portfolio",
        "price_line": top,
        "change_line": bottom,
        "color": color,
        "pct": day_percent,
        "updated_text": updated,
        "updated_mono": time.monotonic(),
        "stale": stale,
        "used_cached": stale_override,
        "error_reason": error_reason,
        "bridge_api_mode": str(last_portfolio_api_status.get("mode", "unknown")),
        "bridge_api_version": str(last_portfolio_api_status.get("api_version", "unknown")),
        "bridge_schema_version": str(last_portfolio_api_status.get("schema_version", "unknown")),
        "bridge_version": str(last_portfolio_api_status.get("bridge_version", "unknown"))
    }


def fetch_portfolio_entry():
    global last_portfolio_entry

    if not is_portfolio_enabled():
        return None

    if not str(config.get("portfolio_bridge_url", "")).strip():
        return make_portfolio_entry(
            {"updated": "never"},
            True,
            "missing bridge url"
        )

    try:
        fetch_bridge_capabilities(False)
        data, mode = fetch_portfolio_payload()
        entry = make_portfolio_entry(data)
        last_portfolio_entry = entry
        add_event(
            "Portfolio bridge refreshed via {}.".format(mode)
        )
        return entry

    except Exception as e:
        reason = repr(e)
        set_error_message(
            "Portfolio bridge fetch failed: " + reason
        )

        if last_portfolio_entry:
            old = {}

            for key in last_portfolio_entry:
                old[key] = last_portfolio_entry[key]

            old["stale"] = True
            old["used_cached"] = True
            old["error_reason"] = reason

            old["change_line"] = (
                "OFFLINE OLD "
                + str(old.get("updated_text", "unknown"))
            )

            return old

        return make_portfolio_entry(
            {"updated": "never"},
            True,
            reason
        )


def portfolio_status_short():
    if not is_portfolio_enabled():
        return "Off"

    if last_portfolio_entry is None:
        return "Not loaded yet"

    if last_portfolio_entry.get("error_reason"):
        return "Offline/cached"

    if last_portfolio_entry.get("stale"):
        return "Stale"

    mode = str(
        last_portfolio_entry.get("bridge_api_mode", "")
    )

    if mode == "v1":
        return "OK API v1"
    if mode == "legacy":
        return "OK Legacy"

    return "OK " + str(
        last_portfolio_entry.get("updated_text", "")
    )


def portfolio_api_mode_short():
    mode = str(
        last_portfolio_api_status.get("mode", "not_checked")
    )

    if mode == "v1":
        return "API v1"
    if mode == "legacy":
        return "Legacy"
    if mode == "failed":
        return "Offline"

    return "Not checked"


def build_portfolio_api_status_html():
    status = last_portfolio_api_status

    lines = []
    lines.append(
        "Mode: " + safe_html(status.get("mode", "not_checked"))
    )
    lines.append(
        "API: " + safe_html(status.get("api_version", "unknown"))
    )
    lines.append(
        "Schema: " + safe_html(status.get("schema_version", "unknown"))
    )
    lines.append(
        "Bridge Version: "
        + safe_html(status.get("bridge_version", "unknown"))
    )
    lines.append(
        "Capabilities: "
        + ("Available" if status.get("capabilities") else "Not loaded")
    )

    error_text = str(status.get("last_error", "")).strip()

    if error_text:
        lines.append(
            "Last API Error: " + safe_html(error_text)
        )

    return "<br>".join(lines)


def build_portfolio_status_html():
    if not is_portfolio_enabled():
        return "Portfolio Module is off."

    if last_portfolio_entry is None:
        return (
            "Portfolio bridge not loaded yet. "
            "Press Test Portfolio Bridge or Refresh Quotes."
        )

    lines = []
    lines.append(
        "Status: " + safe_html(portfolio_status_short())
    )
    lines.append(
        "API Mode: "
        + safe_html(
            last_portfolio_entry.get(
                "bridge_api_mode",
                "unknown"
            )
        )
    )
    lines.append(
        "Bridge Version: "
        + safe_html(
            last_portfolio_entry.get(
                "bridge_version",
                "unknown"
            )
        )
    )
    lines.append(
        "Top Line: "
        + safe_html(
            last_portfolio_entry.get("price_line", "")
        )
    )
    lines.append(
        "Bottom Line: "
        + safe_html(
            last_portfolio_entry.get("change_line", "")
        )
    )

    err = last_portfolio_entry.get("error_reason", "")

    if err:
        lines.append("Last Error: " + safe_html(err))

    return "<br>".join(lines)

def logo_status_for_symbol(sym):
    path = "/logos/{}.bmp".format(sym)
    if file_exists(path):
        return "Found"
    return "Missing"


def build_logo_status_html():
    if not config.get("show_logos", True):
        return "Logos are currently disabled. The ticker is running in text-only mode."

    if not SYMBOLS:
        return "No symbols saved."

    lines = []
    found = 0
    missing = 0

    for sym in SYMBOLS:
        state = logo_status_for_symbol(sym)
        if state == "Found":
            found += 1
        else:
            missing += 1
            state = "Text fallback"
        lines.append("{}: {}".format(sym, state))

    summary = "{} found / {} text fallback".format(found, missing)
    return summary + "<br>" + "<br>".join(lines)


def launcher_status_text():
    try:
        with open("/code.py", "r") as f:
            text = f.read()
        if "AUTO_RECOVERY_LAUNCHER_V1" in text:
            return "Installed"
        return "Not installed or older launcher"
    except Exception:
        return "Unable to read code.py"


def build_release_notes_html(manifest=None):
    if manifest is None:
        manifest = fetch_update_manifest()

    if manifest is None:
        return "Could not load release notes. Check the manifest URL."

    lines = []
    for ch in ("stable", "beta"):
        if ch in manifest:
            info = manifest[ch]
            lines.append("<b>{}</b>: {}<br>{}".format(
                ch.upper(),
                safe_html(info.get("version", "unknown")),
                safe_html(info.get("notes", "No notes."))
            ))
        else:
            lines.append("<b>{}</b>: missing from manifest".format(ch.upper()))

    return "<br><br>".join(lines)



def friendly_error_text(message):
    raw = str(message)

    if "Customer API key required" in raw or "missing API key" in raw:
        return "Stock quotes are paused until a Finnhub API key is saved. Open Setup Wizard and enter the key."
    if "OSError(30" in raw or "read-only" in raw:
        return "Settings could not save because the device storage is read-only. Restart in normal app-write mode and try again."
    if "Manifest" in raw or "manifest" in raw:
        return "Software update server could not be reached or returned invalid data. Check WiFi and the manifest URL."
    if "Fetch error" in raw or "returned no valid price" in raw or "Quote" in raw:
        return "Stock quotes could not load. Check WiFi, ticker symbols, and the Finnhub API key."
    if "Wrong admin PIN" in raw or "wrong admin PIN" in raw:
        return "Action blocked because the admin PIN was incorrect."
    if "OTA install" in raw or "Update failed" in raw:
        return "Software update did not install. Check OTA Status and try again."
    return raw


def is_demo_mode():
    return bool_from_form(config.get("demo_mode", False))


def api_ready_for_quotes():
    if is_demo_mode():
        return True
    return bool(get_finnhub_api_key())


def count_missing_logos():
    missing = 0
    found = 0

    if not config.get("show_logos", True):
        return 0, 0

    for sym in SYMBOLS:
        if file_exists("/logos/{}.bmp".format(sym)):
            found += 1
        else:
            missing += 1

    return found, missing


def logo_summary_text():
    if not config.get("show_logos", True):
        return "Text-only mode"

    found, missing = count_missing_logos()

    if missing == 0:
        return "All logos found"

    return "{} text fallback".format(missing)


def setup_completion_counts():
    checks = []
    checks.append((True, "Device booted"))
    checks.append((wifi.radio.connected, "WiFi connected"))
    checks.append((api_ready_for_quotes(), "API key or demo mode ready"))
    checks.append((len(SYMBOLS) > 0, "Symbols saved"))
    if is_portfolio_enabled():
        checks.append((bool(str(config.get("portfolio_bridge_url", "")).strip()), "Portfolio bridge URL saved"))
        checks.append((bool(str(config.get("portfolio_bridge_key", "")).strip()), "Portfolio bridge key saved"))
    checks.append((str(config.get("admin_pin", "1234")) != "1234", "Admin PIN changed"))
    checks.append((file_exists(BACKUP_APP_PATH), "OTA backup available"))
    return checks


def setup_progress_text():
    checks = setup_completion_counts()
    done = 0

    for ok, label in checks:
        if ok:
            done += 1

    return "{}/{} complete".format(done, len(checks))


def setup_checklist_item(ok, label, hint=""):
    if ok:
        return "<div class='check ok'>OK - {}</div>".format(safe_html(label))
    if hint:
        return "<div class='check todo'>ACTION - {}<br><span>{}</span></div>".format(safe_html(label), safe_html(hint))
    return "<div class='check todo'>ACTION - {}</div>".format(safe_html(label))


def build_setup_checklist_html():
    items = []
    items.append(setup_checklist_item(wifi.radio.connected, "WiFi connected", "Use first-time setup mode or reset WiFi."))

    if is_demo_mode():
        items.append(setup_checklist_item(True, "Demo mode enabled", "Device is using sample prices."))
    else:
        items.append(setup_checklist_item(bool(get_saved_customer_api_key()), "Finnhub API key saved", "Open Setup Wizard and paste a Finnhub API key."))

    items.append(setup_checklist_item(len(SYMBOLS) > 0, "Stock symbols saved", "Add symbols in the Tickers section."))

    if is_portfolio_enabled():
        items.append(setup_checklist_item(bool(str(config.get("portfolio_bridge_url", "")).strip()), "Portfolio bridge URL saved", "Enter the Raspberry Pi bridge URL in Portfolio Module."))
        items.append(setup_checklist_item(bool(str(config.get("portfolio_bridge_key", "")).strip()), "Portfolio bridge key saved", "Enter the display key from the local bridge."))
        bridge_ready = bool(last_portfolio_entry and not last_portfolio_entry.get("error_reason"))
        items.append(setup_checklist_item(bridge_ready, "Portfolio bridge reachable", "Use Test Portfolio Bridge after saving the URL and key."))

    items.append(setup_checklist_item(str(config.get("admin_pin", "1234")) != "1234", "Admin PIN changed", "For sold units, change the default 1234 PIN."))
    items.append(setup_checklist_item(file_exists(BACKUP_APP_PATH), "Rollback backup available", "Install an OTA update once to create app_backup.py."))
    items.append(setup_checklist_item(launcher_status_text() == "Installed", "Auto-recovery launcher installed", "Install it from Software Update."))

    found, missing = count_missing_logos()
    if config.get("show_logos", True):
        if missing:
            items.append(setup_checklist_item(True, "Logo fallback active", "{} missing logo(s) will use text fallback.".format(missing)))
        else:
            items.append(setup_checklist_item(True, "Logo status checked", "All saved symbol logos found."))
    else:
        items.append(setup_checklist_item(True, "Text-only logo mode", "Logo display is turned off."))

    return "<p class='small'><b>Setup:</b> {}</p>".format(setup_progress_text()) + "".join(items)


def system_health_state():
    if not wifi.radio.connected:
        return "ERROR", "WiFi Offline", "badbadge"
    if not api_ready_for_quotes():
        return "SETUP", "Setup Needed", "warnbadge"
    if is_demo_mode():
        return "DEMO", "Demo Mode", "warnbadge"
    if bool_from_form(config.get("panel_sleep", False)):
        return "SLEEP", "Display Sleeping", "infobadge"

    if is_portfolio_enabled():
        if not str(config.get("portfolio_bridge_url", "")).strip():
            return "SETUP", "Bridge URL Needed", "warnbadge"
        if not str(config.get("portfolio_bridge_key", "")).strip():
            return "SETUP", "Bridge Key Needed", "warnbadge"
        if last_portfolio_entry and last_portfolio_entry.get("error_reason"):
            return "WARNING", "Bridge Offline", "warnbadge"
        if last_portfolio_entry and last_portfolio_entry.get("stale"):
            return "WARNING", "Portfolio Stale", "warnbadge"

    stale_count = 0
    for sym in SYMBOLS:
        if sym in last_good and quote_is_stale(last_good[sym]):
            stale_count += 1

    if stale_count:
        return "WARNING", "Stale Quotes", "warnbadge"
    if str(config.get("admin_pin", "1234")) == "1234":
        return "WARNING", "Default PIN", "warnbadge"
    if not file_exists(BACKUP_APP_PATH):
        return "WARNING", "No Backup", "warnbadge"
    return "OK", "System OK", "goodbadge"


def build_system_health_badge_html():
    code, label_text, class_name = system_health_state()
    return "<span class='badge {}'>{}</span>".format(class_name, safe_html(label_text))


def last_error_panel_html():
    msg = str(last_error_message)
    if not msg or msg.lower() in ("none", "none yet.", "none yet"):
        return "<div class='quiet-ok'>No active error message.</div>"
    return (
        "<div class='errorbox'><b>Last Error:</b> {}"
        "<form method='POST' action='/clear-last-error'>"
        "<button class='smallbtn' type='submit'>Clear Error</button>"
        "</form></div>"
    ).format(safe_html(msg))


def quote_status_short():
    if is_demo_mode():
        return "Demo Data"
    if not get_finnhub_api_key():
        return "API Key Needed"

    stale_count = 0
    no_data = 0
    for sym in SYMBOLS:
        if sym not in last_good:
            no_data += 1
        elif quote_is_stale(last_good[sym]):
            stale_count += 1

    if no_data == len(SYMBOLS):
        return "Waiting"
    if stale_count:
        return "{} Stale".format(stale_count)
    return "OK"


def panel_state_text():
    if bool_from_form(config.get("panel_sleep", False)):
        return "Sleeping"
    return "Awake"


def yes_no(value):
    return "Yes" if value else "No"


def setup_blocking_issues():
    issues = []

    try:
        if not wifi.radio.connected:
            issues.append("Connect the device to WiFi.")
    except Exception:
        issues.append("Connect the device to WiFi.")

    if not is_demo_mode() and not get_saved_customer_api_key():
        issues.append("Save a Finnhub API key or turn on Demo Mode.")

    if len(SYMBOLS) <= 0:
        issues.append("Add at least one stock symbol.")

    return issues


def setup_recommendations():
    items = []

    if str(config.get("admin_pin", "1234")) == "1234":
        items.append("Change the default admin PIN before selling or gifting this device.")

    if not file_exists(BACKUP_APP_PATH):
        items.append("Create an OTA backup by installing one known-good update before final use.")

    return items


def build_onboarding_message_html():
    blocking = setup_blocking_issues()

    if blocking:
        lis = ""
        for item in blocking:
            lis += "<li>{}</li>".format(safe_html(item))
        return (
            "<div class='onboard warn'><b>Setup Needed</b>"
            "<div class='small'>Finish these items before using live stock quotes:</div>"
            "<ul>{}</ul>"
            "<form method='GET' action='/setup-wizard'><button type='submit'>Open Setup Wizard</button></form>"
            "</div>"
        ).format(lis)

    recs = setup_recommendations()

    if recs:
        lis = ""
        for item in recs[:2]:
            lis += "<li>{}</li>".format(safe_html(item))
        return (
            "<div class='onboard'><b>Recommended Before Final Use</b>"
            "<ul>{}</ul>"
            "</div>"
        ).format(lis)

    return ""


def safe_config_export_dict():
    export_config = {}

    keys = []
    for key in DEFAULT_CONFIG:
        keys.append(key)

    for key in config:
        if key not in keys:
            keys.append(key)

    for key in keys:
        if key not in config:
            continue

        if key == "finnhub_api_key":
            if get_saved_customer_api_key():
                export_config[key] = "__SAVED_KEY_HIDDEN__"
            else:
                export_config[key] = ""
        elif key == "portfolio_bridge_key":
            if str(config.get("portfolio_bridge_key", "")).strip():
                export_config[key] = "__SAVED_KEY_HIDDEN__"
            else:
                export_config[key] = ""
        else:
            export_config[key] = config[key]

    return {
        "backup_type": "StockTicker safe config backup",
        "app_version": APP_VERSION,
        "device_id": DEVICE_ID,
        "ip": ip,
        "api_key_saved": bool(get_saved_customer_api_key()),
        "wifi_password_included": False,
        "symbols": SYMBOLS,
        "config": export_config
    }


def build_safe_config_backup_text():
    try:
        return json.dumps(safe_config_export_dict())
    except Exception as e:
        return "Config export failed: " + repr(e)


def build_symbols_backup_text():
    if not SYMBOLS:
        return "No symbols saved."

    return "\n".join(SYMBOLS) + "\n"


def build_support_report_text():
    found, missing = count_missing_logos()
    lines = []

    lines.append("StockTicker Support Report")
    lines.append("==========================")
    lines.append("Device Name: " + str(config.get("device_name", "StockTicker")))
    lines.append("Device ID: " + str(DEVICE_ID))
    lines.append("App Version: " + str(APP_VERSION))
    lines.append("Config Schema: " + str(config.get("config_schema_version", CONFIG_SCHEMA_VERSION)))
    lines.append("IP Address: " + str(ip))
    lines.append("System Health: " + system_health_state()[1])
    lines.append("Panel Display: " + panel_state_text())
    lines.append("Market Status: " + get_market_status(eastern_time_now()))
    lines.append("Quote Status: " + quote_status_short())
    lines.append("Portfolio Status: " + portfolio_status_short())
    lines.append("Portfolio Mode: " + str(config.get("portfolio_mode", "off")))
    lines.append("Portfolio API Preference: " + ("v1 first" if bool_from_form(config.get("portfolio_prefer_api_v1", True)) else "legacy first"))
    lines.append("Portfolio API Mode: " + str(last_portfolio_api_status.get("mode", "not_checked")))
    lines.append("Portfolio API Version: " + str(last_portfolio_api_status.get("api_version", "unknown")))
    lines.append("Portfolio Schema: " + str(last_portfolio_api_status.get("schema_version", "unknown")))
    lines.append("Bridge Version: " + str(last_portfolio_api_status.get("bridge_version", "unknown")))
    lines.append("Bridge Key Saved: " + yes_no(bool(str(config.get("portfolio_bridge_key", "")).strip())))
    lines.append("WiFi Connected: " + yes_no(wifi.radio.connected))
    lines.append("Time Sync OK: " + yes_no(time_sync_ok))
    lines.append("Demo Mode: " + yes_no(is_demo_mode()))
    lines.append("Customer API Key Required: " + yes_no(customer_api_required()))
    lines.append("API Key Saved: " + yes_no(bool(get_saved_customer_api_key())))
    lines.append("Admin PIN Changed: " + yes_no(str(config.get("admin_pin", "1234")) != "1234"))
    lines.append("Update Channel: " + str(config.get("update_channel", "stable")))
    lines.append("Manifest URL: " + str(config.get("update_manifest_url", "")))
    lines.append("Backup App Found: " + yes_no(file_exists(BACKUP_APP_PATH)))
    lines.append("Auto-Recovery Launcher: " + launcher_status_text())
    lines.append("Logos: {} found / {} text fallback".format(found, missing))
    lines.append("Brightness: " + str(config.get("brightness", "")))
    lines.append("Scroll Speed Open: " + str(config.get("scroll_speed_open", "")))
    lines.append("Scroll Speed Closed: " + str(config.get("scroll_speed_closed", "")))
    lines.append("Scroll Delay: " + str(config.get("scroll_delay", "")))
    lines.append("Block Gap: " + str(config.get("block_gap", "")))
    lines.append("Last Error: " + str(last_error_message))
    lines.append("")
    lines.append("Symbols")
    lines.append("-------")
    for sym in SYMBOLS:
        lines.append(sym + " - Logo: " + logo_status_for_symbol(sym))
    lines.append("")
    lines.append("Setup Progress")
    lines.append("--------------")
    for ok, label in setup_completion_counts():
        lines.append(("OK - " if ok else "ACTION - ") + label)
    lines.append("")
    lines.append("Event Log")
    lines.append("---------")
    if event_log:
        for item in event_log:
            lines.append(str(item))
    else:
        lines.append("No events yet.")

    return "\n".join(lines)


def export_page(title, body):
    return """\
<!DOCTYPE html>
<html>
<head>
<title>{}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ background:#07111f; color:#eef6ff; font-family:Arial; padding:18px; margin:0; }}
.wrap {{ max-width:920px; margin:0 auto; }}
.card {{ background:#101b2e; border:1px solid #243657; border-radius:18px; padding:18px; margin-bottom:14px; }}
pre {{ white-space:pre-wrap; word-break:break-word; background:#07111f; border:1px solid #243657; border-radius:12px; padding:12px; }}
a {{ color:#79c7ff; }}
.small {{ color:#a9bddb; font-size:13px; line-height:1.4; }}
</style>
</head>
<body>
<div class="wrap">
<div class="card"><h1>{}</h1><p class="small">This page is safe to screenshot or copy. API keys and WiFi passwords are not shown.</p><pre>{}</pre><p><a href="/">Back to Dashboard</a></p></div>
</div>
</body>
</html>
""".format(safe_html(title), safe_html(title), safe_html(body))


def demo_quote(sym):
    now_text = format_12h(eastern_time_now())
    now_mono = time.monotonic()
    seed = 0
    for ch in str(sym):
        seed += ord(ch)

    base = 10 + (seed % 90)
    wiggle = int(time.monotonic() / 15) % 10
    price = base + (wiggle / 10.0)
    pct = ((seed % 11) - 5) / 2.0
    dollar_change = price * pct / 100.0
    sign = "+" if dollar_change >= 0 else "-"
    color = 0x00FF00 if dollar_change >= 0 else 0xFF0000
    change_parts = []

    if config.get("show_dollar_change", True):
        change_parts.append("{}${:.2f}".format(sign, abs(dollar_change)))
    if config.get("show_percent_change", True):
        change_parts.append("({:+.2f}% DEMO)".format(pct))
    if not change_parts:
        change_parts.append("DEMO")

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
        "error_reason": "demo mode"
    }


def help_page():
    return """\
<!DOCTYPE html>
<html>
<head>
<title>StockTicker Help</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { background:#07111f; color:#eef6ff; font-family:Arial; padding:18px; margin:0; }
.wrap { max-width:820px; margin:0 auto; }
.card { background:#101b2e; border:1px solid #243657; border-radius:18px; padding:18px; margin-bottom:14px; }
a { color:#79c7ff; }
.small { color:#a9bddb; font-size:13px; line-height:1.5; }
h1 { margin-top:0; }
</style>
</head>
<body>
<div class="wrap">
<div class="card"><h1>StockTicker Help</h1><p class="small">Quick customer guide.</p></div>
<div class="card"><h2>First-time setup</h2><p>Connect to the setup WiFi, enter home WiFi, stock symbols, Finnhub API key, and admin PIN. After saving, the device restarts and joins the home network.</p></div>
<div class="card"><h2>Adding stocks</h2><p>Use the Tickers section. Enter one symbol per line, such as SOFI, RKLB, HIMS, SPY, or AAPL.</p></div>
<div class="card"><h2>API key</h2><p>Stock quotes require a Finnhub API key unless Demo Mode is enabled. The saved key is hidden for security.</p></div>
<div class="card"><h2>Demo Mode</h2><p>Demo Mode shows sample prices for display/testing. It is not real market data and should be turned off for normal use.</p></div>
<div class="card"><h2>Colors and labels</h2><p>Green means up, red means down, purple can indicate pre-market/after-hours. OLD means cached or stale data.</p></div>
<div class="card"><h2>Portfolio bridge</h2><p>Portfolio mode is optional. Enter the local Raspberry Pi bridge URL and display key, then use Test Portfolio Bridge. API v1 is preferred automatically and the legacy endpoint remains available as a fallback.</p></div>
<div class="card"><h2>Privacy mode</h2><p>Portfolio Privacy Mode hides portfolio value, daily money change, cash, buying power, and mover amounts from the LED display. It does not disconnect Schwab or delete data from the local bridge.</p></div>
<div class="card"><h2>Software updates</h2><p>Read Release Notes, then use Check for Update and Install Update. Rollback restores the previous app if an update has problems. WiFi, API keys, symbols, portfolio settings, and bridge keys remain in their separate settings files.</p></div>
<div class="card"><h2>Sleep Display</h2><p>Sleep Display blanks the LED panels without unplugging the device. The dashboard, WiFi, OTA, and settings continue to work.</p></div>
<div class="card"><h2>Logos</h2><p>BMP logos go in /logos/SYMBOL.bmp. Missing logos are harmless; the ticker automatically uses a clean text fallback.</p></div>
<p><a href="/">Back to Dashboard</a></p>
</div>
</body>
</html>
"""


def setup_wizard_page(message=""):
    return """\
<!DOCTYPE html>
<html>
<head>
<title>StockTicker Setup Wizard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ background:#07111f; color:#eef6ff; font-family:Arial; padding:18px; margin:0; }}
.wrap {{ max-width:760px; margin:0 auto; }}
.card {{ background:#101b2e; border:1px solid #243657; padding:16px; border-radius:18px; margin-bottom:14px; }}
textarea, input, select {{ width:100%; box-sizing:border-box; margin:6px 0 12px; padding:10px; border-radius:10px; border:1px solid #33486d; background:#07111f; color:#eef6ff; }}
button {{ padding:12px 16px; border:0; border-radius:10px; background:#22aa66; color:white; font-weight:bold; }}
.small {{ color:#a9bddb; font-size:13px; line-height:1.4; }}
a {{ color:#79c7ff; }}
</style>
</head>
<body>
<div class="wrap">
<div class="card">
<h1>StockTicker Setup Wizard</h1>
<p class="small">Use this page for first-time customer setup or to reconfigure the device.</p>
<p>{message}</p>
<form method="POST" action="/save-customer-setup">
<label>Device Name</label>
<input name="device_name" value="{device_name}">
<label>Stock Symbols</label>
<textarea name="symbols" rows="6">{symbols}</textarea>
<label>Finnhub API Key</label>
<input name="finnhub_api_key" type="password" value="" placeholder="{api_key_placeholder}">
<p class="small">API Key Status: {api_key_status}</p>
<p class="small">For security, the saved API key is hidden. Leave this blank to keep the saved key. Paste a new key only when changing it.</p>
<label>Require Customer API Key</label>
<select name="require_customer_api_key">
<option value="true" {require_key_true_selected}>True - customer must enter their own key</option>
<option value="false" {require_key_false_selected}>False - allow secrets.py fallback</option>
</select>
<label>Demo Mode</label>
<select name="demo_mode">
<option value="false" {demo_false_selected}>False - use live market data</option>
<option value="true" {demo_true_selected}>True - show sample demo prices</option>
</select>
<p class="small">Demo Mode is useful for product demos before an API key is entered. It is clearly marked as demo data.</p>
<label>New Admin PIN</label>
<input name="admin_pin" type="password" value="" placeholder="Leave blank to keep current PIN">
<p class="small">For sold units, change the default 1234 PIN. The saved PIN is hidden.</p>
<label>Brightness 0.00-1.00</label>
<input name="brightness" value="{brightness}">
<label>Update Channel</label>
<select name="update_channel">
<option value="stable" {stable_selected}>Stable</option>
<option value="beta" {beta_selected}>Beta</option>
</select>
<label>Show Logos</label>
<select name="show_logos">
<option value="true" {logos_true_selected}>True</option>
<option value="false" {logos_false_selected}>False</option>
</select>
<button type="submit">Save Setup</button>
</form>
<p><a href="/">Back to Dashboard</a></p>
</div>
</div>
</body>
</html>
""".format(
        message=message,
        device_name=safe_html(config.get("device_name", "StockTicker")),
        symbols=safe_html("\n".join(SYMBOLS)),
        api_key_placeholder="Saved key hidden. Leave blank to keep it." if get_saved_customer_api_key() else "Paste customer Finnhub API key here",
        api_key_status=safe_html(get_api_key_status()),
        require_key_true_selected=selected("true", str(config.get("require_customer_api_key", True)).lower()),
        require_key_false_selected=selected("false", str(config.get("require_customer_api_key", True)).lower()),
        demo_true_selected=selected("true", str(config.get("demo_mode", False)).lower()),
        demo_false_selected=selected("false", str(config.get("demo_mode", False)).lower()),
        admin_pin=safe_html(config.get("admin_pin", "1234")),
        brightness=safe_html(config.get("brightness", DEFAULT_CONFIG["brightness"])),
        stable_selected=selected("stable", config.get("update_channel", "stable")),
        beta_selected=selected("beta", config.get("update_channel", "stable")),
        logos_true_selected=selected("true", str(config.get("show_logos", True)).lower()),
        logos_false_selected=selected("false", str(config.get("show_logos", True)).lower())
    )


def set_web_message(message):
    global last_web_message
    last_web_message = message
    add_event(message)
    print("WEB STATUS:", message)


def set_error_message(message):
    global last_error_message
    friendly = friendly_error_text(message)
    last_error_message = friendly
    add_event("ERROR: " + str(friendly))
    print("WEB ERROR:", message)


add_event("Booted " + APP_VERSION)
mark_app_boot_success()


def start_setup_mode(reason):
    print("SETUP MODE:", reason)

    setup_suffix = str(DEVICE_ID).replace("ST-", "")[-6:]
    setup_ssid = "StockTicker-" + setup_suffix
    setup_password = "12345678"

    wifi.radio.start_ap(setup_ssid, setup_password)
    setup_ip = str(wifi.radio.ipv4_address_ap)

    setup_pool = socketpool.SocketPool(wifi.radio)
    setup_server = Server(setup_pool, "/")

    setup_html = """\
<!DOCTYPE html>
<html>
<head>
<title>StockTicker First-Time Setup</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { background:#07111f; color:#eef6ff; font-family:Arial; padding:18px; margin:0; }
.card {{ background:#101b2e; border:1px solid #243657; border-radius:18px; padding:18px; }}
textarea, input, select {{ width:100%; box-sizing:border-box; padding:10px; margin:8px 0 14px; border-radius:10px; border:1px solid #33486d; background:#07111f; color:#eef6ff; }}
button {{ padding:12px 16px; border:0; border-radius:10px; background:#22aa66; color:white; font-weight:bold; }}
.small {{ color:#a9bddb; font-size:13px; line-height:1.4; }}
</style>
</head>
<body>
<div class="card">
<h1>StockTicker First-Time Setup</h1>
<p class="small">Connect this device to WiFi and enter customer basics. This setup WiFi uses the device ID so customers can identify the correct unit. You can edit these later from the dashboard.</p>
<form method="POST" action="/save-wifi">
<label>Home WiFi Name</label>
<input name="ssid">
<label>Home WiFi Password</label>
<input name="password" type="password">
<label>Stock Symbols</label>
<textarea name="symbols" rows="6">SOFI
RKLB
ONDS
HIMS
PLTR
AMZN
SPY</textarea>
<label>Finnhub API Key</label>
<input name="finnhub_api_key" type="password" placeholder="Customer API key">
<p class="small">Required for live stock quotes. The key is saved on this device and hidden after setup.</p>
<label>Demo Mode</label>
<select name="demo_mode">
<option value="false">False - use live market data</option>
<option value="true">True - show sample demo prices</option>
</select>
<p class="small">Use Demo Mode only for testing or showing the display before entering an API key.</p>
<label>Admin PIN</label>
<input name="admin_pin" value="1234">
<label>Brightness 0.00-1.00</label>
<input name="brightness" value="0.30">
<label>Update Channel</label>
<select name="update_channel">
<option value="stable">Stable</option>
<option value="beta">Beta</option>
</select>
<button type="submit">Save Setup and Restart</button>
</form>
</div>
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

        setup_cfg = load_config()
        setup_cfg["finnhub_api_key"] = url_decode(str(form.get("finnhub_api_key", setup_cfg.get("finnhub_api_key", "")))).strip()
        setup_cfg["require_customer_api_key"] = True
        setup_cfg["demo_mode"] = bool_from_form(form.get("demo_mode", setup_cfg.get("demo_mode", False)))
        setup_cfg["admin_pin"] = url_decode(str(form.get("admin_pin", setup_cfg.get("admin_pin", "1234")))).strip() or "1234"
        setup_cfg["brightness"] = clamp_float(form.get("brightness", setup_cfg.get("brightness", 0.30)), 0.0, 1.0, 0.30)

        channel = url_decode(str(form.get("update_channel", setup_cfg.get("update_channel", "stable")))).strip().lower()
        setup_cfg["update_channel"] = channel if channel in ("stable", "beta") else "stable"

        save_config(setup_cfg)

        raw_symbols = url_decode(str(form.get("symbols", "")))
        new_symbols = []
        seen = set()
        for line in raw_symbols.replace(",", "\n").replace("\r", "\n").split("\n"):
            sym = clean_symbol(line)
            if sym and sym not in seen:
                new_symbols.append(sym)
                seen.add(sym)

        if new_symbols:
            save_symbol_list(new_symbols)

        return Response(
            request,
            "<html><body><h1>Setup Saved</h1><p>Restarting and connecting to WiFi...</p></body></html>",
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

    try:
        ssid = str(secrets.get("ssid", "")).strip()
        password = str(secrets.get("password", ""))
        if ssid:
            return ssid, password
    except Exception:
        pass

    start_setup_mode("WiFi is not configured.")


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
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:14px; }}
.card {{ background:#101b2e; border:1px solid #243657; padding:16px; border-radius:18px; margin-bottom:14px; }}
.stat {{ background:#07111f; border:1px solid #243657; border-radius:12px; padding:10px; margin:6px 0; }}
.stat b {{ color:#a9bddb; font-size:13px; }}
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
.topline {{ display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap; }}
.badge {{ display:inline-block; padding:8px 12px; border-radius:999px; font-weight:bold; font-size:13px; }}
.goodbadge {{ background:#123820; color:#74ff9e; border:1px solid #226d3d; }}
.warnbadge {{ background:#3a2c10; color:#ffd166; border:1px solid #7a5b17; }}
.badbadge {{ background:#3a1515; color:#ff8b8b; border:1px solid #733333; }}
.infobadge {{ background:#102c3a; color:#8edbff; border:1px solid #2a6683; }}
.onboard {{ background:#162640; border:1px solid #315888; border-radius:14px; padding:12px; margin:12px 0 0; }}
.onboard.warn {{ background:#33280f; border-color:#7a5b17; }}
.onboard b {{ display:block; margin-bottom:4px; }}
.onboard ul {{ margin:6px 0 10px 20px; padding:0; }}
.errorbox {{ background:#2b171b; border:1px solid #803d46; border-radius:12px; padding:10px; margin-top:10px; color:#ffd9df; }}
.quiet-ok {{ background:#102a1c; border:1px solid #226d3d; border-radius:12px; padding:10px; margin-top:10px; color:#92ffad; }}
.smallbtn {{ padding:6px 9px; font-size:12px; margin-top:8px; }}
.check {{ border:1px solid #273955; border-radius:10px; padding:8px; margin:7px 0; }}
.check.ok {{ background:#102316; color:#91ffaa; }}
.check.todo {{ background:#2c2312; color:#ffd166; }}
.check span {{ color:#d5c8a7; font-size:12px; }}
h1 {{ margin:0 0 6px; }}
h2 {{ margin-top:0; }}
summary {{ cursor:pointer; font-weight:bold; color:#79c7ff; margin:8px 0; }}
.button-row {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; }}
.button-row form {{ margin:0; }}
.slim {{ margin-bottom:10px; }}

/* Customer dashboard polish */
:root {{
  --bg:#06101d;
  --panel:#101d31;
  --panel2:#0a1627;
  --line:#263b5d;
  --text:#f4f8ff;
  --muted:#a9bddb;
  --blue:#3994ff;
  --green:#29bb73;
  --orange:#dc8b16;
  --red:#d34b4b;
}}
body {{
  background:
    radial-gradient(circle at top right, #132c4c 0, #07111f 38%, #050b14 100%);
  color:var(--text);
  min-height:100vh;
}}
.wrap {{ max-width:1080px; }}
.hero {{
  background:
    linear-gradient(135deg, rgba(31,140,255,.18), rgba(16,27,46,.96) 46%, rgba(11,22,39,.98));
  border-color:#31527f;
  box-shadow:0 18px 45px rgba(0,0,0,.28);
  padding:22px;
}}
.hero h1 {{ font-size:29px; letter-spacing:-.5px; }}
.eyebrow {{
  color:#79c7ff;
  font-size:12px;
  font-weight:bold;
  letter-spacing:1.4px;
  text-transform:uppercase;
  margin-bottom:7px;
}}
.hero-subtitle {{
  color:var(--muted);
  margin:0;
  line-height:1.5;
}}
.card {{
  background:linear-gradient(180deg, rgba(16,29,49,.98), rgba(12,23,40,.98));
  border-color:var(--line);
  box-shadow:0 10px 25px rgba(0,0,0,.16);
}}
.stat {{
  background:rgba(5,15,27,.72);
  border-color:#2a4166;
  min-height:48px;
}}
.stat-value {{
  font-size:17px;
  font-weight:bold;
  margin-top:4px;
}}
.quicknav {{
  position:sticky;
  top:8px;
  z-index:10;
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  padding:10px;
  margin:0 0 14px;
  border:1px solid var(--line);
  border-radius:15px;
  background:rgba(7,17,31,.94);
  backdrop-filter:blur(9px);
  box-shadow:0 8px 25px rgba(0,0,0,.22);
}}
.quicknav a {{
  color:#dcecff;
  text-decoration:none;
  font-size:13px;
  font-weight:bold;
  padding:8px 11px;
  border-radius:9px;
  background:#10233c;
  border:1px solid #284a72;
}}
.quicknav a:hover {{ background:#18365c; }}
.linkbtn {{
  display:inline-block;
  margin:7px 8px 0 0;
  padding:10px 13px;
  border-radius:10px;
  color:white;
  text-decoration:none;
  font-weight:bold;
  background:var(--blue);
  border:1px solid rgba(255,255,255,.12);
}}
.portfolio-link {{
  background:linear-gradient(135deg, #7a4cff, #2b8cff);
}}
.secondary-link {{ background:#1a334f; }}
.linkbtn.disabled {{
  background:#28374a;
  color:#9badc4;
  cursor:not-allowed;
}}
.feature-card {{
  position:relative;
  overflow:hidden;
}}
.feature-card:after {{
  content:"";
  position:absolute;
  width:130px;
  height:130px;
  border-radius:50%;
  right:-75px;
  top:-75px;
  background:rgba(57,148,255,.10);
}}
.card-kicker {{
  color:#79c7ff;
  font-size:11px;
  font-weight:bold;
  letter-spacing:1.1px;
  text-transform:uppercase;
  margin-bottom:7px;
}}
.status-line {{
  display:flex;
  justify-content:space-between;
  gap:12px;
  padding:9px 0;
  border-bottom:1px solid rgba(64,90,126,.45);
}}
.status-line:last-child {{ border-bottom:0; }}
.status-line span:first-child {{ color:var(--muted); }}
.status-line b {{ text-align:right; }}
.section-note {{
  border-left:3px solid #3994ff;
  padding:9px 11px;
  background:rgba(31,140,255,.08);
  border-radius:0 9px 9px 0;
  color:#bdd4ef;
  font-size:13px;
  line-height:1.45;
}}
summary {{
  padding:4px 0;
  font-size:16px;
}}
button, .linkbtn, .quicknav a {{
  transition:transform .12s ease, filter .12s ease;
}}
button:hover, .linkbtn:hover, .quicknav a:hover {{
  filter:brightness(1.1);
  transform:translateY(-1px);
}}
@media (max-width:620px) {{
  body {{ padding:10px; }}
  .hero {{ padding:17px; }}
  .hero h1 {{ font-size:24px; }}
  .quicknav {{ position:static; }}
  .grid {{ grid-template-columns:1fr; }}
}}
</style>
</head>
<body>
<div class="wrap">
<div class="hero" id="overview">
<div class="topline">
<div>
<div class="eyebrow">StockTicker Control Center</div>
<h1>{device_name}</h1>
<p class="hero-subtitle">Professional LED market display · {device_id}</p>
</div>
<div>{system_health_badge}</div>
</div>
<div class="grid">
<div class="stat"><b>Firmware</b><div class="stat-value">{version}</div></div>
<div class="stat"><b>Market</b><div class="stat-value">{market_status}</div></div>
<div class="stat"><b>Quotes</b><div class="stat-value">{quote_status_short}</div></div>
<div class="stat"><b>Portfolio</b><div class="stat-value">{portfolio_status_short}</div></div>
<div class="stat"><b>Panel</b><div class="stat-value">{panel_state}</div></div>
<div class="stat"><b>Setup</b><div class="stat-value">{setup_progress}</div></div>
<div class="stat"><b>Device IP</b><div class="stat-value">{ip}</div></div>
</div>
<p class="good"><b>Latest activity:</b> {last_web_message}</p>
{last_error_panel}
{onboarding_message}
</div>

<div class="quicknav">
<a href="#overview">Overview</a>
<a href="#portfolio">Portfolio</a>
<a href="#display-settings">Display</a>
<a href="#status-details">Status</a>
<a href="#diagnostics">Diagnostics</a>
<a href="#software-updates">Updates</a>
</div>

<div class="grid">
<div class="card feature-card">
<div class="card-kicker">Start Here</div>
<h2>Customer Setup</h2>
<p class="small">Configure the device name, stock list, market-data key, display preferences, PIN, and update channel.</p>
<div class="button-row">
<form method="GET" action="/setup-wizard"><button type="submit">Open Setup Wizard</button></form>
<form method="GET" action="/help"><button type="submit">Help / Quick Guide</button></form>
</div>
<p class="small">API Key Status: {api_key_status}</p>
<details class="slim"><summary>Setup Checklist</summary>{setup_checklist_message}</details>
</div>

<div class="card feature-card">
<div class="card-kicker">Daily Controls</div>
<h2>Quick Controls</h2>
<div class="status-line"><span>LED panel</span><b>{panel_state}</b></div>
<div class="button-row">
<form method="POST" action="/panel-sleep"><button class="orange" type="submit">Sleep Display</button></form>
<form method="POST" action="/panel-wake"><button class="green" type="submit">Wake Display</button></form>
</div>
<div class="button-row">
<form method="POST" action="/refresh-now"><button type="submit">Refresh Quotes</button></form>
<form method="POST" action="/restart"><button class="red" type="submit">Restart Device</button></form>
</div>
<p class="small">Sleep turns the LED panels black but keeps WiFi, dashboard, settings, and updates running.</p>
</div>

<div class="card feature-card" id="portfolio">
<div class="card-kicker">Private Local Integration</div>
<h2>Portfolio & Bridge</h2>
<div class="status-line"><span>Portfolio status</span><b>{portfolio_status_short}</b></div>
<div class="status-line"><span>Bridge API</span><b>{portfolio_api_mode_short}</b></div>
<p class="section-note">The Raspberry Pi keeps Schwab credentials local. The ticker receives only sanitized display data.</p>
<div>{portfolio_bridge_links_html}</div>
<div class="button-row">
<form method="POST" action="/test-portfolio"><button type="submit">Test Bridge</button></form>
<form method="POST" action="/refresh-now"><button class="green" type="submit">Refresh Display</button></form>
</div>
</div>
</div>

<details class="card" id="display-settings">
<summary>Display & Ticker Settings</summary>
<p class="small">Common customer-facing controls. Changes save to the device and update the board after the current scroll cycle.</p>
<div class="grid">
<div>
<h2>Tickers</h2>
<form method="POST" action="/save-symbols">
<textarea name="symbols" rows="8">{symbols}</textarea>
<button class="green" type="submit">Save Symbols</button>
</form>
</div>
<div>
<h2>Display</h2>
<form method="POST" action="/save-config">
<label>Brightness 0.00-1.00</label>
<input name="brightness" value="{brightness}">
<label>Scroll Speed When Market Open</label>
<input name="scroll_speed_open" value="{scroll_speed_open}">
<label>Scroll Speed When Market Closed</label>
<input name="scroll_speed_closed" value="{scroll_speed_closed}">
<label>Scroll Smoothness Delay</label>
<input name="scroll_delay" value="{scroll_delay}">
<label>Space Between Ticker Blocks</label>
<input name="block_gap" value="{block_gap}">
<label>Show Logos</label>
<select name="show_logos">
<option value="true" {logos_true_selected}>True</option>
<option value="false" {logos_false_selected}>False</option>
</select>
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
<button class="green" type="submit">Save Display Settings</button>
</form>
</div>
<div>
<h2>Night / Demo</h2>
<form method="POST" action="/save-config">
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
<label>Demo Mode</label>
<select name="demo_mode">
<option value="false" {demo_false_selected}>False</option>
<option value="true" {demo_true_selected}>True</option>
</select>
<p class="small">Demo Mode uses sample prices and clearly marks them as demo data.</p>
<button class="green" type="submit">Save Night / Demo Settings</button>
</form>
</div>
<div id="portfolio-settings">
<div class="card-kicker">Brokerage Display</div>
<h2>Portfolio Module</h2>
<p class="section-note">Configure what appears on the LED display. Portfolio values stay on your home network.</p>
<div>{portfolio_bridge_links_html}</div>
<form method="POST" action="/save-config">
<label>Portfolio Display</label>
<select name="portfolio_mode">
<option value="off" {portfolio_off_selected}>Off</option>
<option value="local_bridge" {portfolio_bridge_selected}>Local Bridge / Raspberry Pi</option>
</select>
<label>Bridge URL</label>
<input name="portfolio_bridge_url" value="{portfolio_bridge_url}" placeholder="http://192.168.2.85:8787">
<p class="small">You may enter the bridge base URL, the legacy /portfolio URL, or the API v1 URL. The ticker will normalize it automatically.</p>
<label>Bridge Display Key</label>
<input name="portfolio_bridge_key" type="password" value="" placeholder="{portfolio_bridge_key_placeholder}">
<p class="small">The saved bridge key is hidden. Leave blank to keep it. API v1 sends this key in a request header instead of the URL.</p>
<label>Prefer API v1</label>
<select name="portfolio_prefer_api_v1">
<option value="true" {portfolio_prefer_v1_true_selected}>True - API v1 with legacy fallback</option>
<option value="false" {portfolio_prefer_v1_false_selected}>False - legacy first</option>
</select>
<label>Privacy Mode</label>
<select name="portfolio_privacy_mode">
<option value="false" {portfolio_privacy_false_selected}>False - show enabled portfolio fields</option>
<option value="true" {portfolio_privacy_true_selected}>True - hide all monetary portfolio values</option>
</select>
<label>Show Portfolio Value</label>
<select name="portfolio_show_value">
<option value="true" {portfolio_value_true_selected}>True</option>
<option value="false" {portfolio_value_false_selected}>False</option>
</select>
<label>Show Day Change</label>
<select name="portfolio_show_day_change">
<option value="true" {portfolio_day_true_selected}>True</option>
<option value="false" {portfolio_day_false_selected}>False</option>
</select>
<label>Show Cash</label>
<select name="portfolio_show_cash">
<option value="true" {portfolio_cash_true_selected}>True</option>
<option value="false" {portfolio_cash_false_selected}>False</option>
</select>
<label>Show Buying Power</label>
<select name="portfolio_show_buying_power">
<option value="true" {portfolio_buying_power_true_selected}>True</option>
<option value="false" {portfolio_buying_power_false_selected}>False</option>
</select>
<label>Show Position Count</label>
<select name="portfolio_show_positions_count">
<option value="true" {portfolio_positions_true_selected}>True</option>
<option value="false" {portfolio_positions_false_selected}>False</option>
</select>
<label>Show Largest Winner</label>
<select name="portfolio_show_largest_winner">
<option value="true" {portfolio_winner_true_selected}>True</option>
<option value="false" {portfolio_winner_false_selected}>False</option>
</select>
<label>Show Largest Loser</label>
<select name="portfolio_show_largest_loser">
<option value="true" {portfolio_loser_true_selected}>True</option>
<option value="false" {portfolio_loser_false_selected}>False</option>
</select>
<label>Portfolio Stale Minutes</label>
<input name="portfolio_stale_minutes" value="{portfolio_stale_minutes}">
<label>Capabilities Refresh Minutes</label>
<input name="portfolio_capabilities_refresh_minutes" value="{portfolio_capabilities_refresh_minutes}">
<button class="green" type="submit">Save Portfolio Settings</button>
</form>
<form method="POST" action="/test-portfolio"><button type="submit">Test Portfolio Bridge</button></form>
<p>{portfolio_test_message}</p>
<p class="small"><b>Bridge API Status</b><br>{portfolio_api_status_message}</p>
</div>
</div>
</details>

<details class="card" id="status-details">
<summary>Status Details</summary>
<div class="grid">
<div class="card">
<h2>Price Alerts</h2>
<p>{alert_message}</p>
<form method="POST" action="/clear-alerts"><button class="orange" type="submit">Clear Alert Message</button></form>
</div>
<div class="card">
<h2>Quote Freshness</h2>
<p>{quote_freshness_message}</p>
<p class="small">STALE means the panel is using cached or older data.</p>
</div>
<div class="card">
<h2>Portfolio Status</h2>
<p>{portfolio_status_message}</p>
<form method="POST" action="/test-portfolio"><button type="submit">Test Portfolio Bridge</button></form>
</div>
<div class="card">
<h2>Logo Status</h2>
<p>{logo_status_message}</p>
<p class="small">Missing logos are harmless; the ticker uses text fallback.</p>
</div>
</div>
</details>

<details class="card" id="diagnostics">
<summary>Diagnostics & Maintenance</summary>
<div class="grid">
<div class="card">
<h2>Test Quote</h2>
<form method="POST" action="/test-quote">
<input name="test_symbol" placeholder="Example: ARM">
<button type="submit">Test Quote</button>
</form>
<p>{test_quote_message}</p>
<form method="POST" action="/validate-symbols"><button class="green" type="submit">Validate All Saved Symbols</button></form>
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
<h2>Cloud Status</h2>
<p>{cloud_status_message}</p>
<form method="POST" action="/check-cloud-status"><button type="submit">Check Cloud Status</button></form>
</div>
<div class="card">
<h2>Memory / Disk Health</h2>
<p>{system_health_message}</p>
<form method="POST" action="/check-system-health"><button type="submit">Check System Health</button></form>
</div>
<div class="card">
<h2>Backup / Export</h2>
<p class="small">Safe exports hide API keys and WiFi passwords. Use these for troubleshooting or saving a copy of the setup.</p>
<form method="GET" action="/support-report"><button type="submit">View Support Report</button></form>
<form method="GET" action="/config-backup"><button type="submit">View Config Backup</button></form>
<form method="GET" action="/symbols-backup"><button type="submit">View Symbols Backup</button></form>
</div>
<div class="card">
<h2>OTA Status</h2>
<p>{ota_status_message}</p>
<form method="POST" action="/check-ota-status"><button type="submit">Check OTA Status</button></form>
</div>
<div class="card">
<h2>Event Log</h2>
<p>{event_log_message}</p>
<form method="POST" action="/clear-event-log"><button class="orange" type="submit">Clear Event Log</button></form>
</div>
</div>
</details>

<details class="card">
<summary>Advanced Admin Settings</summary>
<p class="small">These are owner/admin controls. Most end users should not need this section.</p>
<form method="POST" action="/save-config">
<div class="grid">
<div>
<label>Open Refresh Seconds</label>
<input name="fetch_interval_open" value="{fetch_interval_open}">
<label>Pre/After Refresh Seconds</label>
<input name="fetch_interval_pre_after" value="{fetch_interval_pre_after}">
<label>Closed Refresh Seconds</label>
<input name="fetch_interval_closed" value="{fetch_interval_closed}">
<label>Smooth Quote Refresh</label>
<select name="smooth_quote_refresh">
<option value="true" {smooth_true_selected}>True</option>
<option value="false" {smooth_false_selected}>False</option>
</select>
<label>After-Hours Color</label>
<select name="after_hours_color">
<option value="purple" {after_purple_selected}>Purple</option>
<option value="normal" {after_normal_selected}>Normal red/green</option>
</select>
</div>
<div>
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
<label>Customer API Key Required</label>
<select name="require_customer_api_key">
<option value="true" {require_key_true_selected}>True</option>
<option value="false" {require_key_false_selected}>False / allow secrets.py fallback</option>
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
<button class="green" type="submit">Save Advanced Settings</button>
</form>
</details>

<details class="card" id="software-updates">
<summary>Software Update & Recovery</summary>
<div class="grid">
<div class="card">
<h2>Release Notes</h2>
<p>{release_notes_message}</p>
<form method="POST" action="/check-release-notes"><button type="submit">Check Release Notes</button></form>
</div>
<div class="card">
<h2>Software Update</h2>
<p>{ota_message}</p>
<form method="POST" action="/check-update"><button type="submit">Check for Update</button></form>
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
<br>
<p>{auto_recovery_message}</p>
<form method="POST" action="/install-auto-recovery" onsubmit="return confirm('Install auto-recovery launcher to code.py?');">
<label>Admin PIN</label>
<input name="admin_pin" type="password" placeholder="Enter PIN">
<button class="orange" type="submit">Install Auto-Recovery Launcher</button>
</form>
</div>
</div>
</details>

<details class="card">
<summary>Market Calendar & Factory Reset</summary>
<div class="grid">
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
</details>
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


@server.route("/help")
def help_route(request: Request):
    return Response(request, help_page(), content_type="text/html")


@server.route("/support-report")
def support_report_route(request: Request):
    return Response(request, export_page("Support Report", build_support_report_text()), content_type="text/html")


@server.route("/config-backup")
def config_backup_route(request: Request):
    return Response(request, export_page("Safe Config Backup", build_safe_config_backup_text()), content_type="text/html")


@server.route("/symbols-backup")
def symbols_backup_route(request: Request):
    return Response(request, export_page("Symbols Backup", build_symbols_backup_text()), content_type="text/html")


@server.route("/clear-last-error", methods=["POST"])
def clear_last_error_route(request: Request):
    global last_error_message
    last_error_message = "None"
    set_web_message("Last error cleared.")
    return Response(request, clean_page("Error Cleared", "Last error message cleared."), content_type="text/html")


@server.route("/setup-wizard")
def setup_wizard_route(request: Request):
    return Response(request, setup_wizard_page(), content_type="text/html")


@server.route("/save-customer-setup", methods=["POST"])
def save_customer_setup(request: Request):
    global SYMBOLS, need_reload, config, BRIGHTNESS_TARGET

    try:
        form = request.form_data

        config["device_name"] = url_decode(str(form.get("device_name", config.get("device_name", "StockTicker")))).strip() or "StockTicker"

        new_api_key = url_decode(str(form.get("finnhub_api_key", ""))).strip()
        if new_api_key:
            config["finnhub_api_key"] = new_api_key

        config["require_customer_api_key"] = bool_from_form(form.get("require_customer_api_key", config.get("require_customer_api_key", True)))
        config["demo_mode"] = bool_from_form(form.get("demo_mode", config.get("demo_mode", False)))

        new_admin_pin = url_decode(str(form.get("admin_pin", ""))).strip()
        if new_admin_pin:
            config["admin_pin"] = new_admin_pin

        config["brightness"] = clamp_float(form.get("brightness", config.get("brightness", 0.30)), 0.0, 1.0, DEFAULT_CONFIG["brightness"])
        config["show_logos"] = bool_from_form(form.get("show_logos", config.get("show_logos", True)))

        portfolio_mode = url_decode(str(form.get("portfolio_mode", config.get("portfolio_mode", "off")))).strip().lower()
        config["portfolio_mode"] = portfolio_mode if portfolio_mode in ("off", "local_bridge") else "off"
        config["portfolio_bridge_url"] = url_decode(str(form.get("portfolio_bridge_url", config.get("portfolio_bridge_url", "")))).strip()
        new_portfolio_key = url_decode(str(form.get("portfolio_bridge_key", ""))).strip()
        if new_portfolio_key:
            config["portfolio_bridge_key"] = new_portfolio_key
        config["portfolio_show_value"] = bool_from_form(form.get("portfolio_show_value", config.get("portfolio_show_value", True)))
        config["portfolio_show_day_change"] = bool_from_form(form.get("portfolio_show_day_change", config.get("portfolio_show_day_change", True)))
        config["portfolio_show_cash"] = bool_from_form(form.get("portfolio_show_cash", config.get("portfolio_show_cash", True)))
        config["portfolio_show_buying_power"] = bool_from_form(form.get("portfolio_show_buying_power", config.get("portfolio_show_buying_power", True)))
        config["portfolio_show_positions_count"] = bool_from_form(form.get("portfolio_show_positions_count", config.get("portfolio_show_positions_count", True)))
        config["portfolio_show_largest_winner"] = bool_from_form(form.get("portfolio_show_largest_winner", config.get("portfolio_show_largest_winner", True)))
        config["portfolio_show_largest_loser"] = bool_from_form(form.get("portfolio_show_largest_loser", config.get("portfolio_show_largest_loser", True)))
        config["portfolio_prefer_api_v1"] = bool_from_form(form.get("portfolio_prefer_api_v1", config.get("portfolio_prefer_api_v1", True)))
        config["portfolio_privacy_mode"] = bool_from_form(form.get("portfolio_privacy_mode", config.get("portfolio_privacy_mode", False)))
        config["portfolio_stale_minutes"] = clamp_int(form.get("portfolio_stale_minutes", config.get("portfolio_stale_minutes", 15)), 1, 1440, DEFAULT_CONFIG["portfolio_stale_minutes"])
        config["portfolio_capabilities_refresh_minutes"] = clamp_int(form.get("portfolio_capabilities_refresh_minutes", config.get("portfolio_capabilities_refresh_minutes", 60)), 5, 1440, DEFAULT_CONFIG["portfolio_capabilities_refresh_minutes"])

        channel = url_decode(str(form.get("update_channel", config.get("update_channel", "stable")))).strip().lower()
        config["update_channel"] = channel if channel in ("stable", "beta") else "stable"

        raw = url_decode(str(form.get("symbols", "")))
        new_symbols = []
        seen = set()
        for line in raw.replace(",", "\n").replace("\r", "\n").split("\n"):
            sym = clean_symbol(line)
            if sym and sym not in seen:
                new_symbols.append(sym)
                seen.add(sym)

        if new_symbols:
            SYMBOLS = new_symbols
            save_symbol_list(SYMBOLS)

        save_config(config)
        BRIGHTNESS_TARGET = float(config["brightness"])
        need_reload = True
        set_web_message("Customer setup saved.")

        return Response(request, clean_page("Setup Saved", "Customer setup was saved."), content_type="text/html")

    except Exception as e:
        set_error_message("Customer setup save failed: " + repr(e))
        return Response(request, clean_page("Setup Failed", last_error_message), content_type="text/html")


@server.route("/")
def index(request: Request):
    current_market_status = get_market_status(eastern_time_now())

    return Response(
        request,
        HTML.format(
            version=APP_VERSION,
            device_name=safe_html(config.get("device_name", "StockTicker Dashboard")),
            device_id=DEVICE_ID,
            ip=ip,
            market_status=current_market_status,
            update_channel=config["update_channel"],
            system_health_badge=build_system_health_badge_html(),
            setup_progress=setup_progress_text(),
            setup_checklist_message=build_setup_checklist_html(),
            quote_status_short=quote_status_short(),
            portfolio_status_short=portfolio_status_short(),
            panel_state=panel_state_text(),
            logo_summary_short=logo_summary_text(),
            last_error_panel=last_error_panel_html(),
            onboarding_message=build_onboarding_message_html(),
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
            portfolio_status_message=build_portfolio_status_html(),
            system_health_message=build_system_health_html(),
            event_log_message=build_event_log_html(),
            logo_status_message=build_logo_status_html(),
            release_notes_message=release_notes_message,
            auto_recovery_message=auto_recovery_message,
            api_key_status=safe_html(get_api_key_status()),
            last_update=last_update_text,
            last_web_message=last_web_message,
            last_error_message=last_error_message,
            test_quote_message=test_quote_message,
            portfolio_test_message=portfolio_test_message,
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
            smooth_true_selected=selected("true", str(config.get("smooth_quote_refresh", True)).lower()),
            smooth_false_selected=selected("false", str(config.get("smooth_quote_refresh", True)).lower()),
            dollar_true_selected=selected("true", str(config.get("show_dollar_change", True)).lower()),
            dollar_false_selected=selected("false", str(config.get("show_dollar_change", True)).lower()),
            percent_true_selected=selected("true", str(config.get("show_percent_change", True)).lower()),
            percent_false_selected=selected("false", str(config.get("show_percent_change", True)).lower()),
            logos_true_selected=selected("true", str(config.get("show_logos", True)).lower()),
            logos_false_selected=selected("false", str(config.get("show_logos", True)).lower()),
            require_key_true_selected=selected("true", str(config.get("require_customer_api_key", True)).lower()),
            require_key_false_selected=selected("false", str(config.get("require_customer_api_key", True)).lower()),
            demo_true_selected=selected("true", str(config.get("demo_mode", False)).lower()),
            demo_false_selected=selected("false", str(config.get("demo_mode", False)).lower()),
            stable_selected=selected("stable", config.get("update_channel", "stable")),
            beta_selected=selected("beta", config.get("update_channel", "stable")),
            after_purple_selected=selected("purple", config.get("after_hours_color", "purple")),
            after_normal_selected=selected("normal", config.get("after_hours_color", "purple")),
            portfolio_off_selected=selected("off", config.get("portfolio_mode", "off")),
            portfolio_bridge_selected=selected("local_bridge", config.get("portfolio_mode", "off")),
            portfolio_bridge_url=safe_html(config.get("portfolio_bridge_url", "")),
            portfolio_bridge_key_placeholder="Saved key hidden. Leave blank to keep it." if str(config.get("portfolio_bridge_key", "")).strip() else "Paste display key here",
            portfolio_prefer_v1_true_selected=selected("true", str(config.get("portfolio_prefer_api_v1", True)).lower()),
            portfolio_prefer_v1_false_selected=selected("false", str(config.get("portfolio_prefer_api_v1", True)).lower()),
            portfolio_privacy_true_selected=selected("true", str(config.get("portfolio_privacy_mode", False)).lower()),
            portfolio_privacy_false_selected=selected("false", str(config.get("portfolio_privacy_mode", False)).lower()),
            portfolio_value_true_selected=selected("true", str(config.get("portfolio_show_value", True)).lower()),
            portfolio_value_false_selected=selected("false", str(config.get("portfolio_show_value", True)).lower()),
            portfolio_day_true_selected=selected("true", str(config.get("portfolio_show_day_change", True)).lower()),
            portfolio_day_false_selected=selected("false", str(config.get("portfolio_show_day_change", True)).lower()),
            portfolio_cash_true_selected=selected("true", str(config.get("portfolio_show_cash", True)).lower()),
            portfolio_cash_false_selected=selected("false", str(config.get("portfolio_show_cash", True)).lower()),
            portfolio_buying_power_true_selected=selected("true", str(config.get("portfolio_show_buying_power", True)).lower()),
            portfolio_buying_power_false_selected=selected("false", str(config.get("portfolio_show_buying_power", True)).lower()),
            portfolio_positions_true_selected=selected("true", str(config.get("portfolio_show_positions_count", True)).lower()),
            portfolio_positions_false_selected=selected("false", str(config.get("portfolio_show_positions_count", True)).lower()),
            portfolio_winner_true_selected=selected("true", str(config.get("portfolio_show_largest_winner", True)).lower()),
            portfolio_winner_false_selected=selected("false", str(config.get("portfolio_show_largest_winner", True)).lower()),
            portfolio_loser_true_selected=selected("true", str(config.get("portfolio_show_largest_loser", True)).lower()),
            portfolio_loser_false_selected=selected("false", str(config.get("portfolio_show_largest_loser", True)).lower()),
            portfolio_stale_minutes=config.get("portfolio_stale_minutes", 15),
            portfolio_capabilities_refresh_minutes=config.get("portfolio_capabilities_refresh_minutes", 60),
            portfolio_api_status_message=build_portfolio_api_status_html(),
            portfolio_api_mode_short=portfolio_api_mode_short(),
            portfolio_bridge_links_html=build_portfolio_bridge_links_html(),
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
        if is_demo_mode():
            e = demo_quote(sym)
            test_quote_message = "{} demo works: {} {}".format(sym, e.get("price_line", ""), e.get("change_line", ""))
            set_web_message("Demo quote tested for {}.".format(sym))
            return Response(request, clean_page("Demo Quote Complete", test_quote_message), content_type="text/html")

        api_key = get_finnhub_api_key()
        if not api_key:
            test_quote_message = "Customer API key required. Open Setup Wizard and save a Finnhub API key."
            set_error_message(test_quote_message)
            return Response(request, clean_page("Test Failed", friendly_error_text(test_quote_message)), content_type="text/html")

        url = FINNHUB_URL.format(sym, api_key)
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


@server.route("/test-portfolio", methods=["POST"])
def test_portfolio_route(request: Request):
    global portfolio_test_message, last_portfolio_entry

    if not is_portfolio_enabled():
        portfolio_test_message = "Portfolio Module is off. Turn on Local Bridge and save settings first."
        set_web_message(portfolio_test_message)
        return Response(request, clean_page("Portfolio Test", portfolio_test_message), content_type="text/html")

    fetch_bridge_capabilities(True)
    entry = fetch_portfolio_entry()
    last_portfolio_entry = entry

    if entry and not entry.get("error_reason"):
        portfolio_test_message = (
            "Portfolio bridge works via {} (bridge {}). {} {}"
        ).format(
            entry.get("bridge_api_mode", "unknown"),
            entry.get("bridge_version", "unknown"),
            entry.get("price_line", ""),
            entry.get("change_line", "")
        )
        set_web_message("Portfolio bridge tested successfully.")
    else:
        portfolio_test_message = (
            "Portfolio bridge test failed or returned cached/offline data. "
            "Check Pi IP, bridge key, and bridge API status."
        )
        set_error_message(portfolio_test_message)

    return Response(request, clean_page("Portfolio Test Complete", portfolio_test_message), content_type="text/html")


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
            if is_demo_mode():
                valid.append("{} DEMO".format(sym))
                continue

            api_key = get_finnhub_api_key()
            if not api_key:
                invalid.append(sym)
                continue

            url = FINNHUB_URL.format(sym, api_key)
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
    global SMOOTH_QUOTE_REFRESH
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
        config["show_logos"] = bool_from_form(form.get("show_logos", config.get("show_logos", True)))
        config["require_customer_api_key"] = bool_from_form(form.get("require_customer_api_key", config.get("require_customer_api_key", True)))
        config["demo_mode"] = bool_from_form(form.get("demo_mode", config.get("demo_mode", False)))
        config["show_stale_marker"] = bool_from_form(form.get("show_stale_marker", config.get("show_stale_marker", True)))
        config["smooth_quote_refresh"] = bool_from_form(form.get("smooth_quote_refresh", config.get("smooth_quote_refresh", True)))

        portfolio_mode = url_decode(str(form.get("portfolio_mode", config.get("portfolio_mode", "off")))).strip().lower()
        config["portfolio_mode"] = portfolio_mode if portfolio_mode in ("off", "local_bridge") else "off"
        config["portfolio_bridge_url"] = url_decode(str(form.get("portfolio_bridge_url", config.get("portfolio_bridge_url", "")))).strip()
        new_portfolio_key = url_decode(str(form.get("portfolio_bridge_key", ""))).strip()
        if new_portfolio_key:
            config["portfolio_bridge_key"] = new_portfolio_key
        config["portfolio_show_value"] = bool_from_form(form.get("portfolio_show_value", config.get("portfolio_show_value", True)))
        config["portfolio_show_day_change"] = bool_from_form(form.get("portfolio_show_day_change", config.get("portfolio_show_day_change", True)))
        config["portfolio_show_cash"] = bool_from_form(form.get("portfolio_show_cash", config.get("portfolio_show_cash", True)))
        config["portfolio_show_buying_power"] = bool_from_form(form.get("portfolio_show_buying_power", config.get("portfolio_show_buying_power", True)))
        config["portfolio_show_positions_count"] = bool_from_form(form.get("portfolio_show_positions_count", config.get("portfolio_show_positions_count", True)))
        config["portfolio_show_largest_winner"] = bool_from_form(form.get("portfolio_show_largest_winner", config.get("portfolio_show_largest_winner", True)))
        config["portfolio_show_largest_loser"] = bool_from_form(form.get("portfolio_show_largest_loser", config.get("portfolio_show_largest_loser", True)))
        config["portfolio_prefer_api_v1"] = bool_from_form(form.get("portfolio_prefer_api_v1", config.get("portfolio_prefer_api_v1", True)))
        config["portfolio_privacy_mode"] = bool_from_form(form.get("portfolio_privacy_mode", config.get("portfolio_privacy_mode", False)))
        config["portfolio_stale_minutes"] = clamp_int(form.get("portfolio_stale_minutes", config.get("portfolio_stale_minutes", 15)), 1, 1440, DEFAULT_CONFIG["portfolio_stale_minutes"])
        config["portfolio_capabilities_refresh_minutes"] = clamp_int(form.get("portfolio_capabilities_refresh_minutes", config.get("portfolio_capabilities_refresh_minutes", 60)), 5, 1440, DEFAULT_CONFIG["portfolio_capabilities_refresh_minutes"])

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
        SMOOTH_QUOTE_REFRESH = bool_from_form(config.get("smooth_quote_refresh", True))

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
    if SMOOTH_QUOTE_REFRESH:
        set_web_message("Manual quote refresh queued for smooth update.")
    else:
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
    selected_hash = "not provided"
    selected_hardware = "not provided"

    if manifest:
        manifest_state = "OK"

        if "stable" in manifest:
            stable_version = str(manifest["stable"].get("version", "unknown"))

        if "beta" in manifest:
            beta_version = str(manifest["beta"].get("version", "unknown"))

        info = get_channel_info(manifest)
        selected_version = str(info.get("version", "unknown"))
        selected_url = str(info.get("app_url", "unknown"))

        if str(info.get("sha256", "")).strip():
            selected_hash = "provided"
        selected_hardware = str(info.get("hardware", "not provided"))

    return (
        "Current Version: {}<br>"
        "Device Model: {}<br>"
        "Config Schema: {}<br>"
        "Current Channel: {}<br>"
        "Manifest URL: {}<br>"
        "Manifest Status: {}<br>"
        "Stable Online: {}<br>"
        "Beta Online: {}<br>"
        "Selected Version: {}<br>"
        "Selected URL: {}<br>"
        "Selected Hardware: {}<br>"
        "SHA-256: {}<br>"
        "Backup File: {}<br>"
        "Protected Settings: config, WiFi, symbols, holidays, device ID<br>"
        "Last OTA Message: {}"
    ).format(
        APP_VERSION,
        DEVICE_MODEL,
        config.get("config_schema_version", CONFIG_SCHEMA_VERSION),
        channel,
        config.get("update_manifest_url", ""),
        manifest_state,
        stable_version,
        beta_version,
        selected_version,
        selected_url,
        selected_hardware,
        selected_hash,
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
    portfolio_ok = None

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
        api_key = get_finnhub_api_key()
        if not api_key:
            raise Exception("Missing Finnhub API key")

        url = FINNHUB_URL.format("AAPL", api_key)
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

    if is_portfolio_enabled():
        try:
            caps = fetch_bridge_capabilities(True)
            portfolio_ok = bool(caps.get("available", False))
        except Exception:
            portfolio_ok = False

    portfolio_text = "OFF"
    if portfolio_ok is True:
        portfolio_text = "OK"
    elif portfolio_ok is False:
        portfolio_text = "ERROR"

    cloud_status_message = (
        "WiFi: {}<br>"
        "OTA Server: {}<br>"
        "Quote API: {}<br>"
        "Portfolio Bridge: {}<br>"
        "Time Sync: {}<br>"
        "Market Calendar: {}"
    ).format(
        "OK" if wifi_ok else "ERROR",
        "OK" if ota_ok else "ERROR",
        "OK" if quote_ok else "ERROR",
        portfolio_text,
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


LAUNCHER_CODE = r'''# code.py - AUTO_RECOVERY_LAUNCHER_V1
# Safe launcher for StockTicker. It restores app_backup.py after repeated app.py crashes.

import time
import json
import microcontroller

CRASH_FILE = "/crash_count.json"
APP_PATH = "/app.py"
BACKUP_PATH = "/app_backup.py"
MAX_CRASHES = 3


def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception as e:
        print("Could not save", path, repr(e))


def exists(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


def copy_file(src, dst):
    with open(src, "rb") as source:
        data = source.read()
    with open(dst, "wb") as target:
        target.write(data)


def increment_crash_count(error_text):
    info = load_json(CRASH_FILE, {})
    count = int(info.get("count", 0)) + 1
    info["count"] = count
    info["last_error"] = str(error_text)[:180]
    save_json(CRASH_FILE, info)
    return count


def restore_backup_and_reset():
    print("AUTO RECOVERY: restoring app_backup.py to app.py")
    copy_file(BACKUP_PATH, APP_PATH)
    save_json(CRASH_FILE, {"count": 0, "restored_backup": True})
    time.sleep(1)
    microcontroller.reset()


try:
    import app

except Exception as e:
    print("APP CRASHED:", repr(e))

    try:
        import traceback
        traceback.print_exception(e)
    except Exception:
        pass

    crashes = increment_crash_count(repr(e))
    print("Crash count:", crashes)

    if crashes >= MAX_CRASHES and exists(BACKUP_PATH):
        try:
            restore_backup_and_reset()
        except Exception as restore_error:
            print("AUTO RECOVERY RESTORE FAILED:", repr(restore_error))

    try:
        import recovery
    except Exception as recovery_error:
        print("RECOVERY ALSO FAILED:", repr(recovery_error))
        while True:
            time.sleep(1)
'''

@server.route("/check-release-notes", methods=["POST"])
def check_release_notes(request: Request):
    global release_notes_message, ota_status_message

    manifest = fetch_update_manifest()
    release_notes_message = build_release_notes_html(manifest)
    ota_status_message = build_ota_status_summary(manifest)
    set_web_message("Release notes checked.")

    return Response(request, clean_page("Release Notes Checked", "Release notes updated."), content_type="text/html")


@server.route("/install-auto-recovery", methods=["POST"])
def install_auto_recovery(request: Request):
    global auto_recovery_message

    entered_pin = url_decode(str(request.form_data.get("admin_pin", "")))

    if entered_pin != str(config["admin_pin"]):
        auto_recovery_message = "Auto-recovery install blocked: wrong admin PIN."
        set_error_message(auto_recovery_message)
        return Response(request, clean_page("Install Blocked", auto_recovery_message), content_type="text/html")

    try:
        with open("/code.py", "w") as f:
            f.write(LAUNCHER_CODE)

        auto_recovery_message = "Auto-recovery launcher installed to code.py. It activates on the next restart."
        set_web_message(auto_recovery_message)

        return Response(request, clean_page("Auto-Recovery Installed", auto_recovery_message), content_type="text/html")

    except Exception as e:
        auto_recovery_message = "Auto-recovery install failed."
        set_error_message("Auto-recovery install failed: " + repr(e))
        return Response(request, clean_page("Install Failed", last_error_message), content_type="text/html")


def ota_protected_settings_snapshot():
    snapshot = {}

    for path in (
        CONFIG_FILE,
        WIFI_FILE,
        SYMBOLS_FILE,
        HOLIDAYS_FILE,
        DEVICE_FILE
    ):
        try:
            snapshot[path] = os.stat(path)[6]
        except Exception:
            snapshot[path] = None

    return snapshot


def verify_update_payload(new_code, info):
    if len(new_code) < 1000:
        return False, "Downloaded app.py was too small."

    if "APP.PY STARTED" not in new_code:
        return False, "Downloaded file does not look like app.py."

    latest = str(info.get("version", "")).strip()

    if not latest:
        return False, "Manifest is missing the update version."

    expected_version_line = 'APP_VERSION = "{}"'.format(latest)

    if expected_version_line not in new_code[:500]:
        return False, "Downloaded app.py version does not match the manifest."

    hardware = info.get("hardware", [])

    if isinstance(hardware, str):
        hardware = [hardware]

    if hardware and DEVICE_MODEL not in hardware:
        return False, "Update is not compatible with this hardware model."

    try:
        minimum_schema = int(info.get("minimum_config_schema", 0) or 0)
    except Exception:
        minimum_schema = 0

    if minimum_schema > CONFIG_SCHEMA_VERSION:
        return False, "Update requires a newer configuration schema."

    expected_size = info.get("size", None)
    expected_hash = str(info.get("sha256", "")).strip().lower()

    try:
        actual_size = 0
        hasher = None
        hash_mode = "not requested"

        if expected_hash:
            hasher, hash_mode = create_sha256_hasher()

        for start in range(0, len(new_code), 512):
            chunk = new_code[start:start + 512].encode("utf-8")
            actual_size += len(chunk)

            if hasher is not None:
                hasher.update(chunk)

        if expected_size is not None and actual_size != int(expected_size):
            return False, "Downloaded app.py size does not match the manifest."

        if hasher is not None:
            digest = hasher.digest()
            actual_hash = "".join(
                "{:02x}".format(byte)
                for byte in digest
            ).lower()

            if actual_hash != expected_hash:
                return False, "Downloaded app.py failed SHA-256 verification."

    except Exception as e:
        return False, "Update integrity verification failed: " + repr(e)

    return True, (
        "Update payload verified: version, hardware, schema, size, "
        "and SHA-256 ({}).".format(hash_mode)
    )


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

        response = requests.get(app_url)
        new_code = response.text
        response.close()

        payload_ok, payload_message = verify_update_payload(
            new_code,
            info
        )

        if not payload_ok:
            ota_message = payload_message
            set_error_message(payload_message)
            return Response(
                request,
                clean_page("Update Failed", payload_message),
                content_type="text/html"
            )

        protected_before = ota_protected_settings_snapshot()

        backup_ok, backup_msg = backup_current_app()

        if not backup_ok:
            ota_message = "OTA stopped. Backup failed."
            set_error_message("OTA stopped. " + backup_msg)
            return Response(request, clean_page("Update Failed", last_error_message), content_type="text/html")

        print(backup_msg)

        with open(APP_PATH, "w") as app_file:
            app_file.write(new_code)

        protected_after = ota_protected_settings_snapshot()

        if protected_after != protected_before:
            rollback_ok, rollback_msg = rollback_to_backup()
            ota_message = "OTA stopped because protected settings changed unexpectedly."
            set_error_message(
                ota_message + " " + str(rollback_msg)
            )
            return Response(
                request,
                clean_page("Update Reverted", last_error_message),
                content_type="text/html"
            )

        ota_message = "Installed version {}. Restarting...".format(latest)
        ota_status_message = build_ota_status_summary(manifest)
        restart_requested = True
        restart_time = time.monotonic() + 2.0
        set_web_message(
            ota_message + " " + payload_message
        )

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



@server.route("/panel-sleep", methods=["POST"])
def panel_sleep_route(request: Request):
    global config

    try:
        config["panel_sleep"] = True
        save_config(config)
        try:
            display.root_group = sleep_root
            matrix.brightness = 0.0
        except Exception:
            pass
        set_web_message("Panel display is sleeping. Dashboard and updates still work.")
        return Response(request, clean_page("Display Sleeping", "The LED panels are now blanked. Use Wake Display to turn them back on."), content_type="text/html")

    except Exception as e:
        set_error_message("Panel sleep failed: " + repr(e))
        return Response(request, clean_page("Sleep Failed", last_error_message), content_type="text/html")


@server.route("/panel-wake", methods=["POST"])
def panel_wake_route(request: Request):
    global config

    try:
        config["panel_sleep"] = False
        save_config(config)
        try:
            display.root_group = root
        except Exception:
            pass
        set_web_message("Panel display is awake.")
        return Response(request, clean_page("Display Awake", "The LED panels are waking up."), content_type="text/html")

    except Exception as e:
        set_error_message("Panel wake failed: " + repr(e))
        return Response(request, clean_page("Wake Failed", last_error_message), content_type="text/html")


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
sleep_root = displayio.Group()
display.root_group = root
panel_sleep_applied = False

status_label = label.Label(terminalio.FONT, text="", color=0x00FF00, scale=1)
status_label.y = 4
root.append(status_label)

clock_label = label.Label(terminalio.FONT, text="--:--", color=0xFFFFFF, scale=1)
clock_label.y = 4
root.append(clock_label)


def load_logos():
    logos = {}

    if not config.get("show_logos", True):
        print("Logos disabled by setting.")
        return logos

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

    if is_demo_mode():
        return demo_quote(sym)

    api_key = get_finnhub_api_key()

    if not api_key:
        set_error_message("Customer API key required. Open Setup Wizard and save a Finnhub API key.")
        return cached_or_error_quote(sym, "missing API key")

    try:
        url = FINNHUB_URL.format(sym, api_key)
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

def finalize_quote_batch(entries, success_message):
    global last_update_text, alert_message, quote_freshness_message

    last_update_text = format_12h(eastern_time_now())

    triggered = []
    stale_symbols = []

    if ALERT_ENABLED and ALERT_PERCENT_MOVE > 0:
        for e in entries:
            if is_portfolio_entry(e):
                continue
            pct = float(e.get("pct", 0))
            if abs(pct) >= ALERT_PERCENT_MOVE and not e.get("stale", False):
                direction = "UP" if pct >= 0 else "DOWN"
                triggered.append("{} {} {:+.2f}%".format(e["symbol"], direction, pct))

    for e in entries:
        if is_portfolio_entry(e):
            continue
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
        set_web_message(success_message + " at " + last_update_text)

    quote_freshness_message = build_quote_freshness_html()


def fetch_entries():
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

    portfolio_entry = fetch_portfolio_entry()
    if portfolio_entry:
        entries.append(portfolio_entry)

    finalize_quote_batch(entries, "Quotes refreshed")

    return entries


def start_smooth_quote_refresh(reason):
    global smooth_refresh_active, smooth_refresh_index, refresh_requested

    smooth_refresh_active = True
    smooth_refresh_index = 0
    refresh_requested = False
    add_event("Smooth quote refresh started: " + reason)


def smooth_quote_refresh_step():
    global smooth_refresh_active, smooth_refresh_index, pending_entries

    if not smooth_refresh_active:
        return

    if smooth_refresh_index >= len(SYMBOLS):
        p_entry = fetch_portfolio_entry()
        if p_entry:
            replace_entry_for_symbol(pending_entries, p_entry)
        smooth_refresh_active = False
        finalize_quote_batch(pending_entries, "Smooth quotes refreshed")
        return

    sym = SYMBOLS[smooth_refresh_index]

    try:
        server.poll()
    except Exception:
        pass

    e = fetch_quote(sym)
    last_good[sym] = e
    replace_entry_for_symbol(pending_entries, e)

    smooth_refresh_index += 1

    if smooth_refresh_index >= len(SYMBOLS):
        p_entry = fetch_portfolio_entry()
        if p_entry:
            replace_entry_for_symbol(pending_entries, p_entry)
        smooth_refresh_active = False
        finalize_quote_batch(pending_entries, "Smooth quotes refreshed")

    gc.collect()


def display_change_color(entry, after_hours):
    if is_portfolio_entry(entry):
        return entry["color"]

    if after_hours and config.get("after_hours_color", "purple") == "purple":
        return 0xAA00FF

    return entry["color"]


def create_block(entry, after_hours):
    sym = entry["symbol"]

    g = displayio.Group()
    x_offset = 0

    logo_bmp = None if sym == PORTFOLIO_SYMBOL else logos.get(sym)

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
        "x_offset": x_offset,
        "price_label": top,
        "change_label": bottom
    }


def apply_entry_to_block(block, entry, after_hours):
    color = display_change_color(entry, after_hours)

    changed = False

    if block["price_label"].text != entry["price_line"]:
        block["price_label"].text = entry["price_line"]
        changed = True

    if block["change_label"].text != entry["change_line"]:
        block["change_label"].text = entry["change_line"]
        changed = True

    if block["change_label"].color != color:
        block["change_label"].color = color

    if changed:
        try:
            x_offset = int(block.get("x_offset", 0))
            block["width"] = float(max(115, x_offset + max(block["price_label"].bounding_box[2], block["change_label"].bounding_box[2]) + 6))
        except Exception:
            pass


def get_entry_for_symbol(entry_list, sym):
    for e in entry_list:
        try:
            if e.get("symbol") == sym:
                return e
        except Exception:
            pass
    return None


def replace_entry_for_symbol(entry_list, new_entry):
    sym = new_entry.get("symbol", "")

    for i in range(len(entry_list)):
        try:
            if entry_list[i].get("symbol") == sym:
                entry_list[i] = new_entry
                return
        except Exception:
            pass

    entry_list.append(new_entry)


def update_blocks_from_entries(blocks, entries, after_hours):
    for block in blocks:
        entry = get_entry_for_symbol(entries, block["symbol"])
        if entry:
            apply_entry_to_block(block, entry, after_hours)


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
pending_entries = entries[:]
blocks = build_blocks(entries, after_hours)
last_quote_fetch = time.monotonic()
smooth_refresh_active = False
smooth_refresh_index = 0

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
            if SMOOTH_QUOTE_REFRESH:
                pe = get_entry_for_symbol(pending_entries, b["symbol"])
                if pe:
                    apply_entry_to_block(b, pe, after_hours)

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

    if SMOOTH_QUOTE_REFRESH:
        if smooth_refresh_active and loop_completed:
            smooth_quote_refresh_step()

        if (refresh_requested or time_for_quote_fetch) and full_scroll_done and not need_reload and not smooth_refresh_active:
            completed_loops = 0
            last_quote_fetch = now

            if refresh_requested:
                start_smooth_quote_refresh("manual request")
            else:
                start_smooth_quote_refresh("scheduled refresh")

    else:
        if (refresh_requested or (time_for_quote_fetch and full_scroll_done)) and not need_reload:
            completed_loops = 0
            refresh_requested = False
            last_quote_fetch = now

            new_entries = fetch_entries()
            pending_entries = new_entries[:]
            update_blocks_from_entries(blocks, new_entries, after_hours)

    if need_reload:
        need_reload = False
        completed_loops = 0
        remove_blocks(blocks)
        logos = load_logos()
        entries = fetch_entries()
        pending_entries = entries[:]
        smooth_refresh_active = False
        smooth_refresh_index = 0
        blocks = build_blocks(entries, after_hours)
        last_quote_fetch = now

    panel_sleeping_now = bool_from_form(config.get("panel_sleep", False))

    if panel_sleeping_now:
        if not panel_sleep_applied:
            try:
                display.root_group = sleep_root
            except Exception:
                pass
            panel_sleep_applied = True
        matrix.brightness = 0.0
    else:
        if panel_sleep_applied:
            try:
                display.root_group = root
            except Exception:
                pass
            panel_sleep_applied = False

        target_brightness = BRIGHTNESS_TARGET

        if night_mode_active(status):
            target_brightness = float(config["night_brightness"])

        if matrix.brightness < target_brightness:
            matrix.brightness = min(matrix.brightness + BRIGHTNESS_RAMP_STEP, target_brightness)
        elif matrix.brightness > target_brightness:
            matrix.brightness = max(matrix.brightness - BRIGHTNESS_RAMP_STEP, target_brightness)

    time.sleep(SCROLL_DELAY)
