#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Region Spoof Applet — системный регион-спуфинг через связку
ProxyBroker2 (авто-подбор публичных прокси выбранной страны) + один из
способов маршрутизации (системный прокси Windows / sing-box / mihomo).

Возможности:
- Трей-иконка со световой индикацией статусов и всплывающей подписью региона.
- Окно с кнопками: Старт/Стоп, Проверить регион, рубильник зоны (РФ / зарубежье),
  выбор региона и способа связки, журнал событий.
- Автопереключение на другую связку, если текущая не смогла запуститься,
  и запоминание последней рабочей связки (включается при старте).
"""

from __future__ import annotations

import ctypes
import datetime
import glob
import json
import logging
import logging.handlers
import os
import shutil
import socket
import subprocess
import sys
import threading
import queue
import re
import time
import winreg
from pathlib import Path
from typing import Optional

import requests

if getattr(sys, "frozen", False):
    BASE = Path(sys.executable).resolve().parent
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "RegionSpoof"
else:
    BASE = Path(__file__).resolve().parent
    DATA_DIR = BASE

CONFIG_PATH = DATA_DIR / "config.json"
RUN_DIR = DATA_DIR / "run"
LOG_DIR = DATA_DIR / "logs"
PID_DIR = DATA_DIR / "logs"

STRATEGIES = ["system", "singbox", "mihomo"]
STRATEGY_NAMES = {
    "system": "Системный прокси Windows",
    "singbox": "sing-box (TUN)",
    "mihomo": "mihomo (TUN)",
}
TUN_STRATEGIES = ["singbox", "mihomo"]

APP_VERSION = "1.2-alpha"

PROXY_PORT_DEFAULT = 8888
DEFAULT_SPARE_PORTS = [8889, 8890, 8891, 8892]
DEFAULT_PB2_START_TIMEOUT_SEC = 10
IS_PROXY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

LOG_Q = queue.Queue()


def log(msg: str, level: str = "INFO"):
    LOG_Q.put((level, msg))
    now = time.strftime("%H:%M:%S")
    rec = f"[{now}] [{level}] {msg}"
    try:
        logging.getLogger("applet").log(
            {"DEBUG": logging.DEBUG, "INFO": logging.INFO,
             "WARNING": logging.WARNING, "ERROR": logging.ERROR}.get(level, logging.INFO),
            msg,
        )
    except Exception:
        pass
    print(rec, flush=True)


def log_action(msg: str):
    """Логирование действий пользователя с маркером [action] (Р7.3)."""
    log(f"[action] {msg}")


# ------------------------------------------------------------------- logging
class _IsoTimeFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.datetime.fromtimestamp(record.created).astimezone()
        return dt.isoformat(timespec="seconds")


class _AppletRotatingHandler(logging.handlers.RotatingFileHandler):
    def rotation_filename(self, default_name):
        if default_name == self.baseFilename:
            return default_name
        stem = os.path.splitext(self.baseFilename)[0]
        m = re.match(r"^" + re.escape(self.baseFilename) + r"\.(\d+)$", default_name)
        if m:
            return f"{stem}.{m.group(1)}.log"
        return default_name


def setup_logging():
    """Р7.3: инициализация логирования в logs/applet.log с ротацией."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    handler = _AppletRotatingHandler(
        str(LOG_DIR / "applet.log"),
        maxBytes=2 * 1024 * 1024,
        backupCount=1,
        encoding="utf-8",
    )
    handler.setFormatter(_IsoTimeFormatter("%(asctime)s %(levelname)s %(message)s"))
    root.addHandler(handler)
    root.propagate = False


# ------------------------------------------------------------------- ports
def is_port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Р7.4: проверка, свободен ли порт (попытка привязки)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, int(port)))
        finally:
            s.close()
        return True
    except OSError:
        return False


def wait_port_ready(port: int, timeout: float = 10, host: str = "127.0.0.1") -> bool:
    """Р7.2: ожидание готовности порта (TCP-коннект) в течение timeout."""
    deadline = time.monotonic() + timeout
    while True:
        if is_port_open(host, int(port)):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def parse_int_list(text: str) -> list:
    """Разбор строки вида «8889, 8890, 8891» в список int."""
    result = []
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        v = int(part)
        if not (1 <= v <= 65535):
            raise ValueError(f"Порт вне диапазона 1-65535: {v}")
        result.append(v)
    return result


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
            cfg["regions"] = cfg.get(
                "regions",
                [{"code": "DE", "name": "Германия"}],
            )
            if "strategies" not in cfg:
                cfg["strategies"] = list(STRATEGIES)
            cfg.setdefault("spare_ports", DEFAULT_SPARE_PORTS)
            cfg.setdefault("pb2_start_timeout_sec", DEFAULT_PB2_START_TIMEOUT_SEC)
            return cfg
        except Exception as e:
            log(f"Не удалось прочитать config.json: {e}", "WARNING")
    return {
        "region": "DE",
        "regions": [{"code": "DE", "name": "Германия"}],
        "strategy": "system",
        "strategies": list(STRATEGIES),
        "last_working": "system",
        "zone": "foreign",
        "proxy_port": PROXY_PORT_DEFAULT,
        "spare_ports": DEFAULT_SPARE_PORTS,
        "pb2_start_timeout_sec": DEFAULT_PB2_START_TIMEOUT_SEC,
        "check_interval_sec": 45,
        "verify_timeout_sec": 18,
        "failover_threshold": 3,
        "auto_start": True,
    }


def save_config(cfg: dict):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log(f"Не удалось сохранить config.json: {e}", "ERROR")


def find_pb2() -> Optional[str]:
    for base in app_dirs():
        for p in (base / "pb2.exe", base / "proxybroker2.exe"):
            if p.is_file():
                return str(p)
    for name in ("pb2", "proxybroker2"):
        p = shutil.which(name)
        if p:
            return p
    return None


def ensure_data_dirs() -> None:
    """Готовит рабочую папку данных: копирует заводской config.json, если его нет."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    if not CONFIG_PATH.exists():
        for base in app_dirs():
            try:
                shutil.copy(base / "config.json", CONFIG_PATH)
                break
            except Exception:
                continue


def is_first_launch() -> bool:
    return not (DATA_DIR / "first_run.done").exists()


def mark_first_launch_done():
    try:
        (DATA_DIR / "first_run.done").write_text("1", encoding="utf-8")
    except Exception:
        pass


def app_dirs() -> list:
    dirs = [BASE]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(Path(meipass))
    return dirs


def find_binary(subdir: str, name_part: str) -> Optional[str]:
    for base in app_dirs():
        for f in (base / "bin" / subdir).glob("**/*.exe"):
            if name_part in f.name.lower():
                return str(f)
    return None


def find_wintun() -> Optional[str]:
    for base in app_dirs():
        for p in (base / "bin" / "wintun" / "bin" / "amd64" / "wintun.dll",
                  base / "bin" / "wintun.dll"):
            if p.is_file():
                return str(p)
        for f in (base / "bin" / "wintun").glob("**/wintun.dll"):
            return str(f)
    return None


# ---------------------------------------------------------------- системный прокси
def _notify_internet_settings():
    try:
        SETTINGS_CHANGED = 39
        REFRESH = 37
        ctypes.windll.wininet.InternetSetOptionW(0, SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, REFRESH, 0, 0)
    except Exception:
        pass


def set_system_proxy(host: str, port: int, use_socks: bool = False):
    cs = "socks=" if use_socks else ""
    server = f"{cs}{host}:{port}"
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, IS_PROXY_KEY, 0, winreg.KEY_SET_VALUE
    ) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
        winreg.SetValueEx(
            k,
            "ProxyOverride",
            0,
            winreg.REG_SZ,
            "localhost;<local>;127.*;10.*;172.16.*;172.17.*;172.18.*;"
            "172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;"
            "172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;"
            "192.168.*",
        )
    _notify_internet_settings()


def clear_system_proxy():
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, IS_PROXY_KEY, 0, winreg.KEY_SET_VALUE
        ) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        _notify_internet_settings()
    except Exception as e:
        log(f"Не удалось выключить системный прокси: {e}", "WARNING")


def is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------- проверка региона
GEO_SERVICES = [
    {
        "name": "ipapi",
        "url": "https://ipapi.co/json/",
        "parse": lambda d: {
            "code": d.get("country_code"),
            "name": d.get("country_name"),
            "ip": d.get("ip"),
        },
    },
    {
        "name": "ipinfo",
        "url": "https://ipinfo.io/json",
        "parse": lambda d: {
            "code": d.get("country"),
            "name": d.get("region"),
            "ip": d.get("ip"),
        },
    },
    {
        "name": "ip-api",
        "url": "http://ip-api.com/json",
        "parse": lambda d: {
            "code": d.get("countryCode"),
            "name": d.get("country"),
            "ip": d.get("query"),
        },
    },
]


def verify_region(proxy: Optional[str] = None, timeout: int = 18) -> Optional[dict]:
    px = {"http": proxy, "https": proxy} if proxy else None
    session = requests.Session()
    for svc in GEO_SERVICES:
        try:
            r = session.get(
                svc["url"],
                proxies=px,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            if r.status_code == 200:
                d = svc["parse"](r.json())
                if d.get("code"):
                    d["source"] = svc["name"]
                    return d
        except Exception:
            continue
    return None


def region_name(cfg: dict, code: str) -> str:
    for r in cfg.get("regions", []):
        if r["code"].upper() == code.upper():
            return r["name"]
    return code


# ---------------------------------------------------------------- генераторы конфигов TUN
def write_singbox_config(port: int, logfile: Path) -> Path:
    cfg_path = RUN_DIR / "singbox.json"
    cfg = {
        "log": {"level": "info", "timestamp": True, "output": str(logfile)},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "RegionalTun",
                "address": ["172.19.0.1/30"],
                "mtu": 1500,
                "auto_route": True,
                "strict_route": False,
                "stack": "gvisor",
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "pb2",
                "server": "127.0.0.1",
                "server_port": port,
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {
                    "ip_cidr": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "169.254.0.0/16",
                        "fd00::/8",
                        "fe80::/10",
                    ],
                    "outbound": "direct",
                }
            ],
            "auto_detect_interface": True,
            "final": "pb2",
        },
    }
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg_path


def write_mihomo_config(port: int) -> Path:
    cfg_path = RUN_DIR / "mihomo.yaml"
    cfg = f"""mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
tun:
  enable: true
  stack: mixed
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
proxies:
  - name: pb2
    type: socks5
    server: 127.0.0.1
    port: {port}
    skip-cert-verify: true
proxy-groups:
  - name: AI
    type: select
    proxies:
      - pb2
      - DIRECT
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - MATCH,AI
"""
    cfg_path.write_text(cfg, encoding="utf-8")
    return cfg_path


class RegionSpoof:
    """Логика работы: запуск/останов процессов, маршрутизация, проверка, failover."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()

        self.enabled = False
        self.zone = cfg.get("zone", "foreign")
        self.region = cfg.get("region", "DE")
        self.strategy = cfg.get("last_working") or cfg.get("strategy", "system")
        self.status = "off"  # off | starting | on | error
        self.geo = None
        self.last_check_text = ""

        self.pb2_proc: Optional[subprocess.Popen] = None
        self.tun_proc: Optional[subprocess.Popen] = None

        self._stop_event = threading.Event()
        self._engine_thread: Optional[threading.Thread] = None
        self._failures = 0
        self._pb2_cache: Optional[dict] = None
        self._pb2_mtime: float = 0.0

        # Р7.4/Р7.5: активный порт, запасной, извещения о смене порта
        self.active_port: Optional[int] = int(cfg.get("proxy_port", PROXY_PORT_DEFAULT))
        self.spare_port: Optional[int] = None
        self.port_notice: Optional[dict] = None
        self.user_error: Optional[str] = None
        self._scan_done = threading.Event()

    # ------------------------------------------------------------------ состояние
    def snapshot(self) -> dict:
        with self.lock:
            return {
                "enabled": self.enabled,
                "zone": self.zone,
                "region": self.region,
                "strategy": self.strategy,
                "status": self.status,
                "geo": dict(self.geo) if self.geo else None,
                "last_check": self.last_check_text,
                "pb2_alive": self.pb2_alive(),
                "proxy_port": int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT)),
                "spare_port": self.cfg.get("spare_port"),
                "notice": dict(self.port_notice) if self.port_notice else None,
                "user_error": self.user_error,
            }

    def pb2_alive(self) -> bool:
        p = self.pb2_proc
        return bool(p) and p.poll() is None

    # ------------------------------------------------------------------ подбор прокси: статистика из лога
    PB2_TAIL = 500000
    PB2_ROTATE_AT = 3 * 1024 * 1024

    def pb2_stats(self) -> dict:
        """Парсит лог pb2 (DEBUG) и возвращает прокси и их источники.
        При большом размере файл усекается (ротация хвоста)."""
        logfile = LOG_DIR / "pb2.log"
        try:
            st = logfile.stat()
            if self._pb2_mtime and st.st_mtime == self._pb2_mtime:
                return self._pb2_cache
            if st.st_size > self.PB2_ROTATE_AT:
                try:
                    with open(logfile, "rb") as f:
                        f.seek(-self.PB2_TAIL, 2)
                        tail = f.read()
                    logfile.write_bytes(tail)
                    st = logfile.stat()
                except OSError:
                    pass
        except OSError:
            return {"sources": [], "proxies": [], "working": 0, "total": 0}

        data = ""
        try:
            if st.st_size <= self.PB2_TAIL:
                data = logfile.read_text(encoding="utf-8", errors="replace")
            else:
                with open(logfile, "rb") as f:
                    f.seek(-self.PB2_TAIL, 2)
                    data = f.read().decode("utf-8", "replace")
        except OSError:
            data = ""

        sources: dict = {}
        proxies: list = []
        total = 0
        for line in data.splitlines():
            m = re.search(r"(\d+)\((\d+)\) proxies added\(received\) from (\S+)", line)
            if m:
                url = m.group(3)
                src = sources.setdefault(url, {"url": url, "added": 0, "received": 0})
                src["added"] += int(m.group(1))
                src["received"] = int(m.group(2)) or src["received"]
                continue
            m = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+) \[([A-Za-z0-9:]+)\]: Get: (success|failed)",
                line,
            )
            if m:
                proxies.append(
                    {
                        "host": m.group(1),
                        "port": int(m.group(2)),
                        "type": m.group(3),
                        "ok": m.group(4) == "success",
                        "time": time.strftime("%H:%M:%S"),
                    }
                )
                continue
            m = re.search(r"Total found proxies: (\d+)", line)
            if m:
                total = int(m.group(1))

        proxies = proxies[-300:]
        self._pb2_mtime = st.st_mtime
        self._pb2_cache = {
            "sources": sorted(sources.values(), key=lambda x: -x["received"]),
            "proxies": list(reversed(proxies)),
            "working": sum(1 for p in proxies if p["ok"]),
            "total": total,
        }
        return self._pb2_cache

    # ------------------------------------------------------------------ порты Р7.4/Р7.5
    def port_scan_list(self) -> list:
        """Полный список портов для сканирования: config scan_ports либо
        основной (proxy_port) + запасные (spare_ports)."""
        explicit = self.cfg.get("scan_ports")
        if explicit:
            return parse_int_list(", ".join(str(p) for p in explicit))
        primary = int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT))
        spares = self.cfg.get("spare_ports", DEFAULT_SPARE_PORTS)
        return parse_int_list(", ".join(str(p) for p in [primary] + list(spares)))

    def scan_free_ports(self):
        """Р7.4: первые два свободных порта из списка сканирования (основной + запасной)."""
        free = [p for p in self.port_scan_list() if is_port_free(p)]
        if len(free) >= 2:
            return free[0], free[1]
        if free:
            return free[0], None
        return None, None

    def scan_ports_init(self):
        """Фоновый автоскан портов при старте приложения (Р7.4)."""
        try:
            main, spare = self.scan_free_ports()
            with self.lock:
                old_main = int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT))
                if main:
                    self.cfg["proxy_port"] = main
                    self.active_port = main
                if spare:
                    self.cfg["spare_port"] = spare
                else:
                    self.cfg["spare_port"] = None
            if main:
                if old_main != main:
                    log(f"Порт {old_main} занят — новый основной порт {main} (автоскан)", "WARNING")
                log(f"Автоскан портов: основной {main}, запасной {spare or 'не найден'}")
            else:
                log("Автоскан портов: нет свободных портов из списка сканирования", "WARNING")
            save_config(self.cfg)
        finally:
            self._scan_done.set()

    def wait_scan(self, timeout: float = 5.0) -> bool:
        """Ожидание завершения фонового автоскана портов."""
        return self._scan_done.wait(timeout)

    def _rescan_spare(self):
        """Р7.4: повторное сканирование для выбора нового запасного порта."""
        main = int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT))
        spare = None
        for p in self.port_scan_list():
            if p == main or not is_port_free(p):
                continue
            spare = p
            break
        with self.lock:
            self.cfg["spare_port"] = spare
        if spare:
            log(f"Запасной порт: {spare} (повторное сканирование)")
        else:
            log("Запасной порт не найден (повторное сканирование)", "WARNING")

    def _warn_port_restart(self, old, new, reason: str):
        """Р7.5: предупреждение о перезапуске при смене порта (до перезапуска)."""
        self.port_notice = {
            "title": f"Порт изменился: {old} → {new}",
            "text": reason,
            "ts": time.monotonic(),
            "expires_after": 30,
            "active_restart": True,
        }

    def _announce_port_change(self, old, new, reason: Optional[str], elapsed: float):
        """Р7.5: итоговое уведомление о перезапуске с указанием времени."""
        self.port_notice = {
            "title": f"Порт изменился: {old} → {new}",
            "text": f"Перезапуск прокси-сервера занял {elapsed:.1f} с"
                    + (f" · {reason}" if reason else ""),
            "ts": time.monotonic(),
            "expires_after": 12,
            "active_restart": False,
        }

    def rescan_ports_now(self):
        """Ручное пересканирование портов (кнопка в GUI), при изменении — перезапуск."""
        with self.lock:
            was_running = self.enabled and self.zone == "foreign"
            old_main = int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT))
        main, spare = self.scan_free_ports()
        if not main:
            log("Пересканирование портов: свободных портов не найдено", "WARNING")
            with self.lock:
                self.user_error = "Нет свободных портов из списка сканирования."
            return
        with self.lock:
            self.cfg["proxy_port"] = main
            self.cfg["spare_port"] = spare
            self.active_port = main
        save_config(self.cfg)
        log(f"Пересканирование портов: основной {main}, запасной {spare or '—'}")
        if main != old_main:
            log(f"Порт изменён: {old_main} -> {main}", "WARNING")
            if was_running:
                self._warn_port_restart(old_main, main, "Смена порта — перезапуск прокси-сервера…")
                self._stop_pb2()
                self.active_port = None
                self._start_pb2()
        elif was_running:
            log("Пересканирование портов: порты не изменились")

    def apply_network_settings(self, main_port: int, spare_ports: list,
                               scan_ports: Optional[list], check_timeout: int):
        """Р7.1/Р7.5: применение сетевых настроек из GUI, при смене порта — перезапуск."""
        with self.lock:
            was_running = self.enabled and self.zone == "foreign"
            old_main = int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT))
            self.cfg["proxy_port"] = int(main_port)
            self.cfg["spare_ports"] = list(spare_ports)
            if scan_ports:
                self.cfg["scan_ports"] = list(scan_ports)
            else:
                self.cfg.pop("scan_ports", None)
            self.cfg["pb2_start_timeout_sec"] = int(check_timeout)
        save_config(self.cfg)
        log(f"Настройки сети сохранены: основной {main_port}, запасные {spare_ports}, "
            f"таймаут проверки {check_timeout} с")
        self._rescan_spare()
        if was_running and main_port != old_main:
            log(f"Смена порта: {old_main} -> {main_port}, перезапуск ProxyBroker2…", "WARNING")
            self._warn_port_restart(old_main, main_port, "Смена порта — перезапуск прокси-сервера…")
            self._stop_pb2()
            self.active_port = None
            self._start_pb2()

    def clear_user_error(self):
        with self.lock:
            self.user_error = None

    # ------------------------------------------------------------------ pb2
    def _start_pb2(self) -> bool:
        """Запуск pb2 с проверкой подъёма и авто-фолбэком (Р7.2, Р7.4).

        Попытки: основной порт, затем запасной. Каждая логируется; если основная
        не поднялась — выполняется перезапуск на запасном с проверкой результата.
        """
        if self.pb2_alive():
            return True
        exe = find_pb2()
        if not exe:
            log("Утилита ProxyBroker2 (pb2) не найдена. Установите: pip install proxybroker2", "ERROR")
            self._set_pb2_failed("ProxyBroker2 (pb2.exe) не найден в приложении.")
            return False

        with self.lock:
            attempts = [int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT))]
            spare = self.cfg.get("spare_port")
            if spare and int(spare) not in attempts:
                attempts.append(int(spare))
        check_timeout = float(self.cfg.get("pb2_start_timeout_sec", DEFAULT_PB2_START_TIMEOUT_SEC))

        for i, port in enumerate(attempts):
            if i >= 1:
                # Р7.5: предупреждение до перезапуска на запасном порту
                with self.lock:
                    old_p = getattr(self, "active_port", None) or attempts[0]
                self._warn_port_restart(old_p, port, "Проверка основного порта не прошла — перезапуск прокси-сервера…")
            started = time.monotonic()
            if not self._launch_pb2(exe, port):
                continue
            if wait_port_ready(port, timeout=check_timeout):
                elapsed = time.monotonic() - started
                with self.lock:
                    old = self.active_port
                    self.cfg["proxy_port"] = port
                    self.active_port = port
                self._rescan_spare()
                save_config(self.cfg)
                pn = self.port_notice
                if pn and pn.get("active_restart"):
                    pn["text"] = pn.get("text", "").replace(
                        "…", f" — перезапуск занял {elapsed:.1f} с")
                    pn["expires_after"] = 12
                    pn["active_restart"] = False
                elif old and old != port:
                    self._announce_port_change(old, port, "фолбэк на свободный порт", elapsed)
                    log(f"Фолбэк: порт {old} -> {port}, перезапуск занял {elapsed:.1f} с", "WARNING")
                else:
                    log(f"ProxyBroker2 поднят: 127.0.0.1:{port} (запуск занял {elapsed:.1f} с)")
                with self.lock:
                    self.status = "starting"
                return True
            log(
                f"Проверка порта {port} не прошла за {check_timeout:.0f} с "
                f"(попытка {i + 1} из {len(attempts)})",
                "WARNING",
            )
            self._stop_pb2()

        self._set_pb2_failed(
            "Не удалось запустить ProxyBroker2: проверка не прошла на основном и "
            "запасном портах. См. подробности в журнале."
        )
        return False

    def _launch_pb2(self, exe: str, port: int):
        """Запуск процесса pb2 на указанном порту."""
        args = [
            exe,
            "--timeout", str(self.cfg.get("pb2_timeout_sec", 10)),
            "--log", "DEBUG",
            "serve",
            "--host", "127.0.0.1",
            "--port", str(port),
            "--types", "HTTPS", "SOCKS5",
            "--countries", self.region.upper(),
            "--lvl", "High",
            "--limit", str(self.cfg.get("pb2_limit", 40)),
        ]
        LOG_DIR.mkdir(exist_ok=True)
        err = open(LOG_DIR / "pb2.log", "wb")
        out = open(LOG_DIR / "pb2.out.log", "wb")
        try:
            self.pb2_proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                creationflags=0x08000000,
            )
            log(f"Запуск подбора прокси: страна {self.region.upper()}, порт {port}")
            return self.pb2_proc
        except Exception as e:
            log(f"Не удалось запустить ProxyBroker2: {e}", "ERROR")
            self._set_pb2_failed(f"Ошибка запуска ProxyBroker2: {e}")
            return None

    def _set_pb2_failed(self, text: str):
        with self.lock:
            self.status = "error"
            self.user_error = text
        log(text, "ERROR")

    def _stop_pb2(self):
        p = self.pb2_proc
        if p and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        self.pb2_proc = None

    # ------------------------------------------------------------------ связки
    def _start_strategy(self, strat: str):
        port = self.cfg.get("proxy_port", PROXY_PORT_DEFAULT)

        if strat == "system":
            set_system_proxy("127.0.0.1", port)
            log(f"Связка «{STRATEGY_NAMES[strat]}» включена (системный прокси 127.0.0.1:{port})")
            self.status = "starting"
            return

        LOG_DIR.mkdir(exist_ok=True)
        if strat == "singbox":
            exe = find_binary("singbox", "sing-box")
            if not exe:
                log("sing-box.exe не найден в bin\\singbox", "ERROR")
                self._mark_strategy_failed()
                return
            cfgp = write_singbox_config(port, LOG_DIR / "singbox.log")
            self._start_tun([exe, "run", "-D", str(RUN_DIR), "-c", str(cfgp)],
                            LOG_DIR / "singbox.log", "sing-box", dll=find_wintun())
            return

        if strat == "mihomo":
            exe = find_binary("mihomo", "mihomo")
            if not exe:
                log("mihomo.exe не найден в bin\\mihomo", "ERROR")
                self._mark_strategy_failed()
                return
            cfgp = write_mihomo_config(port)
            self._start_tun([exe, "-d", str(RUN_DIR), "-f", str(cfgp)],
                            LOG_DIR / "mihomo.log", "mihomo", dll=find_wintun())
            return

    def _start_tun(self, cmd, logfile: Path, name: str, dll: Optional[str] = None):
        exe = cmd[0]
        if dll:
            try:
                shutil.copy(dll, os.path.join(os.path.dirname(exe), "wintun.dll"))
            except Exception as e:
                log(f"Не удалось скопировать wintun.dll: {e}", "WARNING")
        RUN_DIR.mkdir(exist_ok=True)
        err = open(logfile, "ab")
        try:
            self.tun_proc = subprocess.Popen(
                cmd,
                cwd=str(RUN_DIR),
                stdin=subprocess.DEVNULL,
                stdout=err,
                stderr=subprocess.STDOUT,
                creationflags=0x08000000,
            )
            log(f"Запущена связка «{STRATEGY_NAMES[self.strategy]}» ({name})")
            self.status = "starting"
            time.sleep(3)
            if self.tun_proc.poll() is not None:
                log(
                    f"Связка {name} сразу завершилась. Проверьте лог {logfile.name}. "
                    "Для TUN нужны права администратора и wintun.dll в папке ядра.",
                    "ERROR",
                )
                self._mark_strategy_failed()
        except Exception as e:
            log(f"Не удалось запустить {name}: {e}", "ERROR")
            self._mark_strategy_failed()

    def _stop_strategy(self, strat: Optional[str] = None):
        strat = strat or self.strategy
        if strat == "system":
            clear_system_proxy()
            log("Системный прокси Windows выключен")
        p = self.tun_proc
        if p and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                p.wait(timeout=6)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        self.tun_proc = None

    def _mark_strategy_failed(self):
        with self.lock:
            self.status = "error"
            self._failures += 1

    # ------------------------------------------------------------------ switch
    def switch_strategy(self, new_strat: str):
        old = self.strategy
        if new_strat == old:
            return
        with self.lock:
            self.strategy = new_strat
        log(f"Переключение связки: «{STRATEGY_NAMES.get(old, old)}» -> «{STRATEGY_NAMES.get(new_strat, new_strat)}»", "WARNING")
        self._stop_strategy(old)
        if self.enabled and self.zone == "foreign":
            self._start_strategy(new_strat)
        self._save_working()

    def _save_working(self):
        with self.lock:
            self.cfg["last_working"] = self.strategy
            self.cfg["region"] = self.region
            self.cfg["zone"] = self.zone
        save_config(self.cfg)

    # ------------------------------------------------------------------ START / STOP
    def start(self):
        with self.lock:
            if self.enabled:
                return
            self.enabled = True
            self._failures = 0
            self.status = "starting"
        log("Старт. Зона: " + ("зарубежье" if self.zone == "foreign" else "РФ"))
        if self.zone == "foreign":
            self._start_pb2()
            self._start_strategy(self.strategy)
        else:
            self._stop_strategy()
            self._stop_pb2()
            self.status = "off"
        self._save_working()

    def stop(self):
        with self.lock:
            if not self.enabled:
                return
            self.enabled = False
        log("Стоп: отключаю все соединения")
        self._stop_strategy()
        self._stop_pb2()
        with self.lock:
            self.status = "off"
            self.geo = None

    def set_zone(self, zone: str):
        if zone == self.zone:
            return
        with self.lock:
            self.zone = zone
        if not self.enabled:
            self._save_working()
            return
        log("Рубильник зоны -> " + ("зарубежье" if zone == "foreign" else "РФ"))
        if zone == "ru":
            self._stop_strategy()
            self._stop_pb2()
            with self.lock:
                self.status = "off"
                self.geo = None
        else:
            self.status = "starting"
            self._start_pb2()
            self._start_strategy(self.strategy)
        self._save_working()

    def set_region(self, code: str):
        if code.upper() == self.region.upper():
            return
        with self.lock:
            self.region = code.upper()
        log(f"Регион выбран: {self.region}")
        if self.enabled and self.zone == "foreign":
            self._stop_pb2()
            self._start_pb2()
            self.status = "starting"
        self._save_working()

    # ------------------------------------------------------------------ engine
    def start_engine(self):
        if self._engine_thread and self._engine_thread.is_alive():
            return
        self._engine_thread = threading.Thread(target=self._engine_loop, daemon=True)
        self._engine_thread.start()

    def _engine_loop(self):
        interval = max(10, int(self.cfg.get("check_interval_sec", 45)))
        verify_timeout = int(self.cfg.get("verify_timeout_sec", 18))
        threshold = max(1, int(self.cfg.get("failover_threshold", 3)))

        while not self._stop_event.wait(interval):
            try:
                with self.lock:
                    enabled = self.enabled
                    zone = self.zone
                    strat = self.strategy
                    # актуальный порт (мог смениться фолбэком/автосканом)
                    proxy = f"http://127.0.0.1:{self.cfg.get('proxy_port', PROXY_PORT_DEFAULT)}"
                if not enabled:
                    continue

                if zone != "foreign":
                    continue

                if not self.pb2_alive():
                    log("Процесс подбора прокси не активен — перезапуск", "WARNING")
                    self._start_pb2()
                    time.sleep(2)
                    if not self.pb2_alive():
                        with self.lock:
                            self.status = "error"
                        continue

                active = self._strategy_active(strat)
                if not active:
                    log(f"Связка «{STRATEGY_NAMES.get(strat, strat)}» не активна", "ERROR")
                    self._failover()
                    continue

                info = verify_region(proxy=proxy, timeout=verify_timeout)
                if info:
                    self._failures = 0
                    with self.lock:
                        self.status = "on"
                        self.geo = info
                    expected = self.region.upper()
                    actual = (info.get("code") or "").upper()
                    mark = "совпадает" if actual == expected else "ОТЛИЧАЕТСЯ"
                    self.last_check_text = (
                        f"{info.get('name')} ({info.get('code')}) IP {info.get('ip')} — {mark}"
                    )
                    log(f"Проверка региона: {self.last_check_text}")
                    if self.cfg.get("last_working") != strat:
                        self.cfg["last_working"] = strat
                        save_config(self.cfg)
                else:
                    self._failures += 1
                    with self.lock:
                        if not self.status == "on":
                            self.status = "starting"
                    remaining = threshold - self._failures
                    if remaining <= 0:
                        self._failures = 0
                        with self.lock:
                            self.status = "error"
                            self.geo = None
                        log("Связка не даёт внешний регион (прокси ещё не подобраны или недоступны)", "WARNING")
                        self._failover()
                    else:
                        self.last_check_text = f"Проверка не прошла (попытка {self._failures}/{threshold})"
                        log(self.last_check_text, "WARNING")
            except Exception as e:
                log(f"Ошибка в цикле движка: {e}", "ERROR")

    def _failover(self):
        """Переключение на следующую связку при невозможности текущей."""
        with self.lock:
            cur = self.strategy
            order = self.cfg.get("strategies", list(STRATEGIES))
            base = self.cfg.get("strategy", "system")
        chain = [s for s in order if s != cur]
        if not chain:
            chain = list(order)
        nxt = chain[0] if chain else base
        log(f"Переключение на резервную связку: «{STRATEGY_NAMES.get(nxt, nxt)}»", "WARNING")
        self.switch_strategy(nxt)
        self.status = "starting"

    def _strategy_active(self, strat: str) -> bool:
        if strat == "system":
            return is_port_open("127.0.0.1", int(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT)))
        p = self.tun_proc
        return bool(p) and p.poll() is None

    def check_now(self):
        """Немедленная проверка региона (синхронно, вызывается из GUI/трея)."""
        with self.lock:
            enabled = self.enabled
            zone = self.zone
        proxy = f"http://127.0.0.1:{self.cfg.get('proxy_port', PROXY_PORT_DEFAULT)}"
        if enabled and zone == "foreign":
            info = verify_region(
                proxy=proxy, timeout=int(self.cfg.get("verify_timeout_sec", 18))
            )
        else:
            info = verify_region(proxy=None, timeout=int(self.cfg.get("verify_timeout_sec", 18)))
        if info:
            with self.lock:
                self.status = "on" if enabled else self.status
                self.geo = info
            self.last_check_text = (
                f"{info.get('name')} ({info.get('code')}) IP {info.get('ip')}"
            )
            log(f"Регион определён: {self.last_check_text}")
        else:
            self.last_check_text = "Регион не удалось определить"
            log(self.last_check_text, "WARNING")
        return info

    def verify_now(self):
        return self.check_now()

    def shutdown(self):
        self._stop_event.set()
        self.stop()
        log("Приложение завершено")


# ------------------------------------------------------------------ иконки/трей
try:
    import pystray
    from PIL import Image, ImageDraw
    HAVE_TRAY = True
except Exception:
    pystray = None
    HAVE_TRAY = False

STATUS_COLORS = {
    "off": "#8a8a8a",
    "starting": "#ffc107",
    "on": "#35c44e",
    "error": "#e5484d",
}


def make_tray_icon(status: str):
    color = STATUS_COLORS.get(status, STATUS_COLORS["off"])
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([4, 4, 60, 60], fill=color, outline="#ffffff", width=3)
    return img


def tray_title(cfg: dict, st: dict) -> str:
    zone = st.get("zone", "foreign")
    if zone != "foreign":
        return "Region Spoof: РФ (локально)"
    reg_code = st.get("region", "DE")
    reg = region_name(cfg, reg_code)
    if st.get("status") == "on" and st.get("geo"):
        g = st["geo"]
        return (
            f"Region Spoof: {reg} -> {g.get('name')} ({g.get('code')}), "
            f"IP {g.get('ip')}"
        )
    status_text = {
        "off": "выключено",
        "starting": "подключение…",
        "error": "ошибка",
        "on": "подключено",
    }.get(st.get("status"), st.get("status"))
    return f"Region Spoof: {reg} ({reg_code}), {status_text}"


def system_tray(cfg: dict, ctl: 'RegionSpoof', root):
    """Создаёт и запускает иконку в трее. Возвращает объект Icon."""

    def build_menu():
        st = ctl.snapshot()
        zone = st.get("zone")
        status = st.get("status")
        cur_strat = st.get("strategy")

        def act_start(_i, _it):
            log_action("Трей: «Старт»")
            ctl.start()
            refresh()

        def act_stop(_i, _it):
            log_action("Трей: «Стоп»")
            ctl.stop()
            refresh()

        def act_check(_i, _it):
            log_action("Трей: «Проверить регион»")
            threading.Thread(target=ctl.verify_now, daemon=True).start()

        def act_exit(_i, _it):
            log_action("Трей: «Выход»")
            ctl.shutdown()
            icon.stop()
            root.after(0, lambda: (root.quit(), root.destroy()))

        def act_zone_to(chosen):
            def fn(_i=None, _it=None):
                log_action("Трей: зона -> " + ("зарубежье" if chosen == "foreign" else "РФ"))
                ctl.set_zone(chosen)
                refresh()
            return fn

        def act_region_to(code):
            def fn(_i=None, _it=None):
                log_action(f"Трей: выбран регион {code}")
                ctl.set_region(code)
                refresh()
            return fn

        def act_strat_to(s):
            def fn(_i=None, _it=None):
                log_action(f"Трей: выбрана связка {STRATEGY_NAMES.get(s, s)}")
                ctl.switch_strategy(s)
                refresh()
            return fn

        menu_items = [
            pystray.MenuItem(
                text=tray_title(cfg, st), action=None, enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Старт", act_start, enabled=not st.get("enabled")
            ),
            pystray.MenuItem(
                "Стоп", act_stop, enabled=st.get("enabled")
            ),
            pystray.MenuItem("Проверить регион", act_check),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Зона", pystray.Menu(
                pystray.MenuItem(
                    "РФ (локально)",
                    act_zone_to("ru"),
                    checked=lambda _i: zone == "ru",
                ),
                pystray.MenuItem(
                    "Зарубежный регион",
                    act_zone_to("foreign"),
                    checked=lambda _i: zone == "foreign",
                ),
            )),
            pystray.MenuItem("Регион для ИИ", pystray.Menu(
                *[
                    pystray.MenuItem(
                        f"{r['name']} ({r['code']})",
                        act_region_to(r["code"]),
                        checked=lambda _i, c=r["code"]: st.get("region", "").upper() == c.upper(),
                    )
                    for r in cfg.get("regions", [])
                ]
            )),
            pystray.MenuItem("Связка", pystray.Menu(
                *[
                    pystray.MenuItem(
                        STRATEGY_NAMES.get(s, s),
                        act_strat_to(s),
                        checked=lambda _i, c=s: cur_strat == c,
                    )
                    for s in cfg.get("strategies", STRATEGIES)
                ]
            )),
            pystray.MenuItem("Открыть папку логов", lambda _i, _it: os.startfile(LOG_DIR)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", act_exit),
        ]
        return pystray.Menu(*menu_items)

    icon = pystray.Icon(
        name="region-spoof",
        icon=make_tray_icon(ctl.snapshot().get("status", "off")),
        title="Region Spoof",
    )
    icon.menu = build_menu()
    icon._build_menu = build_menu

    def refresh():
        st = ctl.snapshot()
        icon.icon = make_tray_icon(st.get("status", "off"))
        icon.title = tray_title(cfg, st)
        try:
            icon.menu = build_menu()
            icon.update_menu()
        except Exception:
            pass

    icon._refresh = refresh
    return icon


# ------------------------------------------------------------------ GUI
import tkinter as tk
from tkinter import ttk, scrolledtext


class AppGUI:
    def __init__(self, cfg: dict, ctl: RegionSpoof):
        self.cfg = cfg
        self.ctl = ctl
        self.quit_requested = False
        self._seen_px: set = set()
        self._last_user_error: Optional[str] = None

        self.root = tk.Tk()
        self.root.title(f"Region Spoof — смена региона  v{APP_VERSION}")
        try:
            self.root.geometry("720x520")
            self.root.minsize(620, 460)
        except Exception:
            pass

        self._build_widgets()
        self._poll()
        self._poll_proxy()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------ виджеты
    def _build_widgets(self):
        st = self.ctl.snapshot()

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        self.lamp = tk.Canvas(top, width=46, height=46, highlightthickness=0, bg="#f0f0f0")
        self.lamp.create_oval(4, 4, 42, 42, fill="#8a8a8a", outline="", tags="circle")
        self.lamp.pack(side="left", padx=(0, 10))

        lab = ttk.Frame(top)
        lab.pack(side="left", fill="x", expand=True)
        self.region_lbl = tk.Label(
            lab, text="Регион: —", font=("Segoe UI", 14, "bold"), bg="#f0f0f0"
        )
        self.region_lbl.pack(anchor="w")
        self.status_lbl = tk.Label(
            lab, text="Статус: выключено", font=("Segoe UI", 10), bg="#f0f0f0"
        )
        self.status_lbl.pack(anchor="w")
        self.detail_lbl = tk.Label(
            lab, text="", foreground="#555555", bg="#f0f0f0", font=("Segoe UI", 9)
        )
        self.detail_lbl.pack(anchor="w")

        self.port_lbl = tk.Label(
            lab, text="", foreground="#333333", bg="#f0f0f0", font=("Segoe UI", 9)
        )
        self.port_lbl.pack(anchor="w")

        # управление
        ctrl = ttk.LabelFrame(self.root, text="Управление", padding=8)
        ctrl.pack(fill="x", padx=10)

        b_row = ttk.Frame(ctrl)
        b_row.pack(fill="x", pady=(0, 6))
        self.btn_start = ttk.Button(b_row, text="▶ Старт", command=self._on_start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(b_row, text="■ Стоп", command=self._on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 0))
        self.btn_check = ttk.Button(b_row, text="Проверить регион", command=self._on_check)
        self.btn_check.pack(side="left", padx=(6, 0))
        ttk.Button(b_row, text="Открыть логи", command=lambda: os.startfile(LOG_DIR)).pack(side="left", padx=(6, 0))
        ttk.Button(b_row, text="Выйти", command=self._on_exit).pack(side="right")

        opt_row = ttk.Frame(ctrl)
        opt_row.pack(fill="x")

        self.zone_var = tk.BooleanVar(value=self.cfg.get("zone", "foreign") == "foreign")
        chk = ttk.Checkbutton(
            opt_row,
            text="Зарубежная зона (спуфинг) — выкл. = РФ",
            variable=self.zone_var,
            command=self._on_zone_toggle,
        )
        chk.pack(side="left", padx=(0, 20))

        ttk.Label(opt_row, text="Регион:").pack(side="left")
        self.region_var = tk.StringVar(value=self.cfg.get("region", "DE"))
        self.region_box = ttk.Combobox(
            opt_row,
            textvariable=self.region_var,
            values=[f"{r['name']} ({r['code']})" for r in self.cfg.get("regions", [])],
            state="readonly",
            width=22,
        )
        self.region_box.pack(side="left", padx=(4, 20))
        self.region_box.bind("<<ComboboxSelected>>", self._on_region_change)

        ttk.Label(opt_row, text="Связка:").pack(side="left")
        self.strategy_var = tk.StringVar(
            value=self.cfg.get("last_working") or self.cfg.get("strategy", "system")
        )
        self.strategy_box = ttk.Combobox(
            opt_row,
            textvariable=self.strategy_var,
            values=[STRATEGY_NAMES.get(s, s) for s in self.cfg.get("strategies", STRATEGIES)],
            state="readonly",
            width=26,
        )
        self.strategy_box.pack(side="left", padx=(4, 0))
        self.strategy_box.bind("<<ComboboxSelected>>", self._on_strategy_change)

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=8)

        # вкладка «Журнал»
        tab_log = ttk.Frame(nb, padding=4)
        nb.add(tab_log, text="Журнал")
        self.log_text = scrolledtext.ScrolledText(
            tab_log, height=12, state="disabled", font=("Consolas", 9), wrap="word"
        )
        self.log_text.pack(fill="both", expand=True)

        # вкладка «Подбор прокси»
        tab_px = ttk.Frame(nb, padding=4)
        nb.add(tab_px, text="Подбор прокси")

        self.pb_summary = tk.Label(
            tab_px, text="Подбор ещё не запускался", anchor="w",
            font=("Segoe UI", 9), bg="#f0f0f0", fg="#333333",
        )
        self.pb_summary.pack(fill="x", pady=(0, 4))

        px_lab = ttk.LabelFrame(tab_px, text="Последние проверенные прокси", padding=2)
        px_lab.pack(fill="both", expand=True, pady=(0, 4))
        self.px_tree = ttk.Treeview(
            px_lab, columns=("addr", "type", "res", "time"), show="headings", height=8
        )
        self.px_tree.heading("addr", text="Адрес:Порт")
        self.px_tree.heading("type", text="Тип")
        self.px_tree.heading("res", text="Результат")
        self.px_tree.heading("time", text="Время")
        self.px_tree.column("addr", width=170)
        self.px_tree.column("type", width=70)
        self.px_tree.column("res", width=80)
        self.px_tree.column("time", width=70)
        vs1 = ttk.Scrollbar(px_lab, orient="vertical", command=self.px_tree.yview)
        self.px_tree.configure(yscrollcommand=vs1.set)
        self.px_tree.pack(side="left", fill="both", expand=True)
        vs1.pack(side="right", fill="y")

        src_lab = ttk.LabelFrame(tab_px, text="Источники прокси", padding=2)
        src_lab.pack(fill="x")
        self.src_tree = ttk.Treeview(
            src_lab, columns=("url", "added", "received"), show="headings", height=6
        )
        self.src_tree.heading("url", text="Источник")
        self.src_tree.heading("added", text="Добавлено")
        self.src_tree.heading("received", text="Получено из списка")
        self.src_tree.column("url", width=380)
        self.src_tree.column("added", width=90)
        self.src_tree.column("received", width=140)
        self.src_tree.pack(fill="x")

        # вкладка «Сеть» (Р7.1: гибкие настройки портов и таймаутов)
        tab_net = ttk.Frame(nb, padding=8)
        nb.add(tab_net, text="Сеть")

        net_box = ttk.LabelFrame(tab_net, text="Порты и проверка", padding=8)
        net_box.pack(fill="x", pady=(0, 6))

        row = ttk.Frame(net_box)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Основной порт:").pack(side="left")
        self.net_main_var = tk.StringVar(value=str(self.cfg.get("proxy_port", PROXY_PORT_DEFAULT)))
        ttk.Entry(row, textvariable=self.net_main_var, width=8).pack(side="left", padx=(4, 16))
        ttk.Label(row, text="Таймаут подъёма pb2 (с):").pack(side="left")
        self.net_timeout_var = tk.StringVar(
            value=str(self.cfg.get("pb2_start_timeout_sec", DEFAULT_PB2_START_TIMEOUT_SEC))
        )
        ttk.Entry(row, textvariable=self.net_timeout_var, width=6).pack(side="left", padx=(4, 0))

        row2 = ttk.Frame(net_box)
        row2.pack(fill="x", pady=3)
        ttk.Label(row2, text="Запасные порты (через запятую):").pack(side="left")
        self.net_spares_var = tk.StringVar(
            value=", ".join(str(p) for p in self.cfg.get("spare_ports", DEFAULT_SPARE_PORTS))
        )
        ttk.Entry(row2, textvariable=self.net_spares_var, width=24).pack(side="left", padx=(4, 0))

        row3 = ttk.Frame(net_box)
        row3.pack(fill="x", pady=3)
        ttk.Label(row3, text="Список сканирования (пусто = основной + запасные):").pack(side="left")
        self.net_scan_var = tk.StringVar(
            value=", ".join(str(p) for p in self.cfg.get("scan_ports") or [])
            if self.cfg.get("scan_ports") else ""
        )
        ttk.Entry(row3, textvariable=self.net_scan_var, width=28).pack(side="left", padx=(4, 0))

        self.net_actual_lbl = tk.Label(
            net_box, text="", anchor="w", fg="#333333", font=("Segoe UI", 9), bg="#ececec"
        )
        self.net_actual_lbl.pack(fill="x", pady=(6, 0))

        btn_row = ttk.Frame(net_box)
        btn_row.pack(fill="x", pady=(6, 0))
        ttk.Button(btn_row, text="Применить и сохранить", command=self._on_net_apply).pack(side="left")
        ttk.Button(btn_row, text="Пересканировать порты", command=self._on_net_rescan).pack(side="left", padx=(6, 0))

        # автозапуск
        self.auto_var = tk.BooleanVar(value=bool(self.cfg.get("auto_start", True)))
        ttk.Checkbutton(
            ctrl, text="Автозапуск последней рабочей связки при запуске приложения",
            variable=self.auto_var, command=self._on_auto_toggle,
        ).pack(fill="x", pady=(6, 0))

    # ------------------------------------------------------------ действия
    def _on_start(self):
        log_action("Нажата кнопка «Старт»")
        threading.Thread(target=self.ctl.start, daemon=True).start()
        self._refresh_view()

    def _on_stop(self):
        log_action("Нажата кнопка «Стоп»")
        threading.Thread(target=self.ctl.stop, daemon=True).start()
        self._refresh_view()

    def _on_check(self):
        log_action("Нажата кнопка «Проверить регион»")
        new = self.ctl.snapshot()
        if new.get("status") == "on":
            threading.Thread(target=self.ctl.verify_now, daemon=True).start()
        else:
            self._append_log("INFO", "Сначала нажмите «Старт» и дождитесь подключения.")

    def _on_zone_toggle(self):
        z = "foreign" if self.zone_var.get() else "ru"
        if z != self.ctl.snapshot().get("zone"):
            log_action("Переключена зона: " + ("зарубежье" if z == "foreign" else "РФ"))
            threading.Thread(target=lambda: self.ctl.set_zone(z), daemon=True).start()
        self._refresh_view()

    def _on_region_change(self, _e=None):
        val = self.region_var.get()
        code = val.split("(")[-1].rstrip(")").strip()
        if code:
            log_action(f"Выбран регион: {code}")
            threading.Thread(target=lambda: self.ctl.set_region(code), daemon=True).start()
        self._refresh_view()

    def _on_strategy_change(self, _e=None):
        val = self.strategy_var.get()
        rev = {v: k for k, v in STRATEGY_NAMES.items()}
        s = rev.get(val, val)
        if s != self.ctl.snapshot().get("strategy"):
            log_action(f"Выбрана связка: {val}")
            threading.Thread(target=lambda: self.ctl.switch_strategy(s), daemon=True).start()
        self._refresh_view()

    def _on_auto_toggle(self):
        log_action("Изменён автозапуск: " + ("вкл" if self.auto_var.get() else "выкл"))
        self.cfg["auto_start"] = self.auto_var.get()
        save_config(self.cfg)

    def _on_net_apply(self):
        try:
            main = int(self.net_main_var.get().strip())
            if not (1 <= main <= 65535):
                raise ValueError("порт вне диапазона")
            spares = parse_int_list(self.net_spares_var.get())
            scan = parse_int_list(self.net_scan_var.get()) or None
            timeout = max(1, int(self.net_timeout_var.get().strip()))
        except (ValueError, TypeError):
            self._append_log(
                "ERROR",
                "Сетевые настройки: введены некорректные значения "
                "(порты 1-65535, таймаут ≥ 1 с).",
            )
            return
        log_action(
            f"Применены сетевые настройки: основной {main}, "
            f"запасные {spares}, сканирование {scan or 'авто'}, таймаут {timeout} с"
        )
        threading.Thread(
            target=self.ctl.apply_network_settings,
            args=(main, spares, scan, timeout),
            daemon=True,
        ).start()
        self._refresh_view()

    def _on_net_rescan(self):
        log_action("Нажата кнопка «Пересканировать порты»")
        threading.Thread(target=self.ctl.rescan_ports_now, daemon=True).start()
        self._refresh_view()

    def _on_exit(self):
        log_action("Нажата кнопка «Выйти»")
        self.quit_requested = True
        threading.Thread(target=self.ctl.shutdown, daemon=True).start()
        time.sleep(0.3)
        self.root.quit()
        self.root.destroy()

    def _on_close(self):
        self.root.withdraw()

    # ------------------------------------------------------------ обновление
    def _poll(self):
        self._drain_log()
        self._refresh_view()
        try:
            self.root.after(250, self._poll)
        except Exception:
            pass

    def _poll_proxy(self):
        self._refresh_proxy()
        try:
            self.root.after(1000, self._poll_proxy)
        except Exception:
            pass

    def _refresh_proxy(self):
        st = self.ctl.pb2_stats()
        if not st or not st.get("sources"):
            self.pb_summary.config(text="Подбор ещё не запускался")
            return
        try:
            self.pb_summary.config(
                text=(
                    f"Всего найдено: {st.get('total', 0)} · Рабочих (в последних проверках): "
                    f"{st.get('working', 0)} · Источников: {len(st.get('sources', []))}"
                )
            )
            existing = {}
            for item in self.px_tree.get_children():
                vals = self.px_tree.item(item, "values")
                if vals:
                    existing[vals[0]] = item
            for p in st.get("proxies", []):
                key = f"{p['host']}:{p['port']}"
                row = (key, p["type"], "рабочий" if p["ok"] else "отказ", p.get("time", ""))
                if key in existing:
                    self.px_tree.item(existing[key], values=row)
                else:
                    self.px_tree.insert("", 0, values=row)
                    if p["ok"] and key not in self._seen_px:
                        self._seen_px.add(key)
                        if len(self._seen_px) > 2000:
                            self._seen_px.clear()
                        self._append_log("INFO", f"Рабочий прокси: {key} [{p['type']}]")
            rows = self.px_tree.get_children()
            if len(rows) > 350:
                for item in rows[350:]:
                    self.px_tree.delete(item)
            for i in self.src_tree.get_children():
                self.src_tree.delete(i)
            for s in st.get("sources", []):
                self.src_tree.insert("", "end", values=(s["url"], s["added"], s["received"]))
        except Exception:
            pass

    def _refresh_view(self):
        st = self.ctl.snapshot()
        zone = st.get("zone")
        status = st.get("status")
        reg_code = st.get("region", "DE")
        reg = region_name(self.cfg, reg_code)

        # лампа
        color = STATUS_COLORS.get(status, STATUS_COLORS["off"])
        self.lamp.itemconfig("circle", fill=color)

        if zone != "foreign":
            self.region_lbl.config(text="Регион: РФ (локально)")
            if st.get("geo"):
                g = st["geo"]
                self.status_lbl.config(text=f"Статус: безопасный режим, фактически {g.get('name')} ({g.get('code')})")
            else:
                self.status_lbl.config(text="Статус: безопасный режим (РФ)")
        else:
            self.region_lbl.config(text=f"Регион: {reg} ({reg_code})")
            if status == "on" and st.get("geo"):
                g = st["geo"]
                if (g.get("code") or "").upper() == reg_code.upper():
                    v = f"✓ Подключено: {g.get('name')} ({g.get('code')}), IP {g.get('ip')}"
                else:
                    v = f"! Подключено, но регион другой: {g.get('name')} ({g.get('code')})"
                self.status_lbl.config(text=v, foreground="#1c7a2e")
            elif status == "starting":
                self.status_lbl.config(text="Подключение… (идёт подбор прокси)", foreground="#a06a00")
            elif status == "error":
                self.status_lbl.config(text="Ошибка: внешний регион не подтверждён", foreground="#c62828")
            else:
                self.status_lbl.config(text="Статус: выключено", foreground="#333")

        self.detail_lbl.config(text=st.get("last_check") or "")
        enabled = st.get("enabled")
        self.btn_start.config(state="disabled" if enabled else "normal")
        self.btn_stop.config(state="normal" if enabled else "disabled")

        # Р7.5: индикация перезапуска при смене порта (счётчик времени)
        notice = st.get("notice")
        if notice:
            elapsed = time.monotonic() - notice.get("ts", time.monotonic())
            left = notice.get("expires_after", 12) - elapsed
            if left > 0:
                self.port_lbl.config(
                    text=f"{notice.get('title', '')} · {notice.get('text', '')} "
                         f"(прошло {elapsed:.0f} с)",
                    foreground="#b26a00",
                )
            else:
                self.port_lbl.config(text="", foreground="#333")
        else:
            main_p = st.get("proxy_port") or "-"
            spare_p = st.get("spare_port")
            base = f"Порт: {main_p}"
            if spare_p:
                base += f" · запасной: {spare_p}"
            self.port_lbl.config(text=base, foreground="#333")

        # Р7.2: сообщение об ошибке пользователю (не крашим приложение)
        err = st.get("user_error")
        if err and err != self._last_user_error:
            self._last_user_error = err
            self.root.after(0, lambda e=err: tk.messagebox.showerror("Region Spoof", e))
            self.ctl.clear_user_error()
        elif not err:
            pass

        # фактическое состояние портов во вкладке «Сеть»
        try:
            self.net_actual_lbl.config(
                text=f"Фактически: основной {st.get('proxy_port') or '-'}, "
                     f"запасной {st.get('spare_port') or '—'}"
            )
        except Exception:
            pass

    def _drain_log(self):
        try:
            while True:
                level, msg = LOG_Q.get_nowait()
                self._append_log(level, msg)
        except queue.Empty:
            pass

    def _append_log(self, level, msg):
        try:
            self.log_text.config(state="normal")
            self.log_text.insert("end", f"{time.strftime('%H:%M:%S')} [{level}] {msg}\n")
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        except Exception:
            pass


# ------------------------------------------------------------------ CLI
def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(exist_ok=True)
    setup_logging()
    ensure_data_dirs()

    if "--check" in sys.argv:
        cfg = load_config()
        port = cfg.get("proxy_port", PROXY_PORT_DEFAULT)
        proxy = f"http://127.0.0.1:{port}"
        if is_port_open("127.0.0.1", port):
            info = verify_region(proxy=proxy, timeout=int(cfg.get("verify_timeout_sec", 18)))
        else:
            info = verify_region(proxy=None, timeout=int(cfg.get("verify_timeout_sec", 18)))
        if info:
            print(json.dumps(info, ensure_ascii=False))
        else:
            print("{}")
            sys.exit(2)
        return

    if "--stop-all" in sys.argv:
        cfg = load_config()
        tmp = RegionSpoof(cfg)
        tmp.stop()
        print("Все соединения остановлены, системный прокси выключен.")
        return

    cfg = load_config()
    ctl = RegionSpoof(cfg)

    # Р7.4: фоновый автоскан портов (основной + запасной из списка сканирования)
    threading.Thread(target=ctl.scan_ports_init, daemon=True).start()

    root = tk.Tk()
    gui = AppGUI(cfg, ctl)

    if is_first_launch():
        mark_first_launch_done()
        tk.messagebox.showinfo(
            "Region Spoof — первое запуск",
            "Привет! Это бесплатная программа для некоммерческого использования.\n\n"
            "Личные ключи, токены и платные аккаунты не требуются: регион "
            "достигается через общедоступные прокси выбранной страны.\n\n"
            "Все данные хранятся только локально и разработчику не отправляются.\n"
            f"Рабочая папка: {DATA_DIR}",
        )

    icon = None
    if HAVE_TRAY:
        try:
            icon = system_tray(cfg, ctl, root)
            icon.run_detached()
        except Exception as e:
            log(f"Трей-иконка недоступна: {e}", "WARNING")
            icon = None

    ctl.start_engine()

    if cfg.get("auto_start", True):
        threading.Thread(
            target=lambda: (ctl.wait_scan(5), ctl.start()), daemon=True
        ).start()

    def _tray_poll():
        if icon is not None and not gui.quit_requested:
            try:
                st = ctl.snapshot()
                icon.icon = make_tray_icon(st.get("status", "off"))
                icon.title = tray_title(cfg, st)
                if hasattr(icon, "_build_menu"):
                    icon.menu = icon._build_menu()
                    icon.update_menu()
            except Exception:
                pass
        if not gui.quit_requested:
            root.after(1500, _tray_poll)

    root.after(1500, _tray_poll)

    try:
        root.mainloop()
    finally:
        ctl.shutdown()


if __name__ == "__main__":
    main()