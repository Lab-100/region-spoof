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
import glob
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import queue
import time
import winreg
from pathlib import Path
from typing import Optional

import requests

BASE = Path(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = BASE / "config.json"
RUN_DIR = BASE / "run"
LOG_DIR = BASE / "logs"
PID_DIR = BASE / "logs"

STRATEGIES = ["system", "singbox", "mihomo"]
STRATEGY_NAMES = {
    "system": "Системный прокси Windows",
    "singbox": "sing-box (TUN)",
    "mihomo": "mihomo (TUN)",
}
TUN_STRATEGIES = ["singbox", "mihomo"]

PROXY_PORT_DEFAULT = 8888
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
    for name in ("pb2", "proxybroker2"):
        p = shutil.which(name)
        if p:
            return p
    return None


def find_binary(subdir: str, name_part: str) -> Optional[str]:
    patterns = [
        str(BASE / "bin" / subdir / "**" / "*.exe"),
        str(BASE / "bin" / subdir / "*.exe"),
    ]
    for p in patterns:
        for f in glob.glob(p, recursive=True):
            bname = os.path.basename(f).lower()
            if name_part in bname:
                return f
    return None


def find_wintun() -> Optional[str]:
    for p in glob.glob(str(BASE / "bin" / "wintun" / "bin" / "amd64" / "wintun.dll")):
        return p
    for p in glob.glob(str(BASE / "bin" / "**" / "wintun.dll"), recursive=True):
        return p
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
            }

    def pb2_alive(self) -> bool:
        p = self.pb2_proc
        return bool(p) and p.poll() is None

    # ------------------------------------------------------------------ pb2
    def _start_pb2(self):
        if self.pb2_alive():
            return
        exe = find_pb2()
        if not exe:
            log("Утилита ProxyBroker2 (pb2) не найдена. Установите: pip install proxybroker2", "ERROR")
            return
        port = self.cfg.get("proxy_port", PROXY_PORT_DEFAULT)
        args = [
            exe,
            "--timeout", str(self.cfg.get("pb2_timeout_sec", 10)),
            "--log", "WARNING",
            "serve",
            "--host", "127.0.0.1",
            "--port", str(port),
            "--types", "HTTPS", "SOCKS5",
            "--countries", self.region.upper(),
            "--lvl", "High",
            "--limit", str(self.cfg.get("pb2_limit", 40)),
        ]
        LOG_DIR.mkdir(exist_ok=True)
        err = open(LOG_DIR / "pb2.log", "ab")
        out = open(LOG_DIR / "pb2.out.log", "ab")
        try:
            self.pb2_proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                creationflags=0x08000000,
            )
            log(f"Запущен подбор прокси: страна {self.region.upper()}, порт {port}")
        except Exception as e:
            log(f"Не удалось запустить ProxyBroker2: {e}", "ERROR")

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
        proxy = f"http://127.0.0.1:{self.cfg.get('proxy_port', PROXY_PORT_DEFAULT)}"

        while not self._stop_event.wait(interval):
            try:
                with self.lock:
                    enabled = self.enabled
                    zone = self.zone
                    strat = self.strategy
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
            ctl.start()
            refresh()

        def act_stop(_i, _it):
            ctl.stop()
            refresh()

        def act_check(_i, _it):
            threading.Thread(target=ctl.verify_now, daemon=True).start()

        def act_exit(_i, _it):
            ctl.shutdown()
            icon.stop()
            root.after(0, lambda: (root.quit(), root.destroy()))

        def act_zone_to(chosen):
            def fn(_i=None, _it=None):
                ctl.set_zone(chosen)
                refresh()
            return fn

        def act_region_to(code):
            def fn(_i=None, _it=None):
                ctl.set_region(code)
                refresh()
            return fn

        def act_strat_to(s):
            def fn(_i=None, _it=None):
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

        self.root = tk.Tk()
        self.root.title("Region Spoof — смена региона")
        try:
            self.root.geometry("720x520")
            self.root.minsize(620, 460)
        except Exception:
            pass

        self._build_widgets()
        self._poll()

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

        bot = ttk.Frame(self.root)
        bot.pack(fill="both", expand=True, padx=10, pady=8)

        lbf = ttk.LabelFrame(bot, text="Журнал", padding=4)
        lbf.pack(fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(
            lbf, height=12, state="disabled", font=("Consolas", 9), wrap="word"
        )
        self.log_text.pack(fill="both", expand=True)

        # автозапуск
        self.auto_var = tk.BooleanVar(value=bool(self.cfg.get("auto_start", True)))
        ttk.Checkbutton(
            ctrl, text="Автозапуск последней рабочей связки при запуске приложения",
            variable=self.auto_var, command=self._on_auto_toggle,
        ).pack(fill="x", pady=(6, 0))

    # ------------------------------------------------------------ действия
    def _on_start(self):
        threading.Thread(target=self.ctl.start, daemon=True).start()
        self._refresh_view()

    def _on_stop(self):
        threading.Thread(target=self.ctl.stop, daemon=True).start()
        self._refresh_view()

    def _on_check(self):
        new = self.ctl.snapshot()
        if new.get("status") == "on":
            threading.Thread(target=self.ctl.verify_now, daemon=True).start()
        else:
            self._append_log("INFO", "Сначала нажмите «Старт» и дождитесь подключения.")

    def _on_zone_toggle(self):
        z = "foreign" if self.zone_var.get() else "ru"
        if z != self.ctl.snapshot().get("zone"):
            threading.Thread(target=lambda: self.ctl.set_zone(z), daemon=True).start()
        self._refresh_view()

    def _on_region_change(self, _e=None):
        val = self.region_var.get()
        code = val.split("(")[-1].rstrip(")").strip()
        if code:
            threading.Thread(target=lambda: self.ctl.set_region(code), daemon=True).start()
        self._refresh_view()

    def _on_strategy_change(self, _e=None):
        val = self.strategy_var.get()
        rev = {v: k for k, v in STRATEGY_NAMES.items()}
        s = rev.get(val, val)
        if s != self.ctl.snapshot().get("strategy"):
            threading.Thread(target=lambda: self.ctl.switch_strategy(s), daemon=True).start()
        self._refresh_view()

    def _on_auto_toggle(self):
        self.cfg["auto_start"] = self.auto_var.get()
        save_config(self.cfg)

    def _on_exit(self):
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
    logging.basicConfig(
        filename=str(LOG_DIR / "applet.log"),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )
    LOG_DIR.mkdir(exist_ok=True)
    RUN_DIR.mkdir(exist_ok=True)

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

    root = tk.Tk()
    gui = AppGUI(cfg, ctl)

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
        threading.Thread(target=ctl.start, daemon=True).start()

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