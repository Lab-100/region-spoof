#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Загрузка бинарников Region Spoof из GitHub Releases.

Скрипт скачивает три zip-архива (ядра маршрутизации sing-box и mihomo плюс
TUN-драйвер wintun) из релиза v1.3-alpha публичного репозитория
Lab-100/region-spoof, ОБЯЗАТЕЛЬНО сверяет SHA256 каждого архива по
файлу-манифесту SHA256SUMS и только после успешной проверки распаковывает
их в каталог ``bin/`` проекта.

Структура, которую создаёт распаковка (её ищет applet.py):
    bin/singbox/sing-box-1.14.0-windows-amd64/sing-box.exe
    bin/singbox/sing-box-1.14.0-windows-amd64/libcronet.dll
    bin/singbox/sing-box-1.14.0-windows-amd64/LICENSE
    bin/mihomo/mihomo-windows-amd64-v1.exe
    bin/wintun/bin/amd64/wintun.dll   (TUN-драйвер, ищется find_wintun)

Хэши НИКОГДА не хранятся в коде: они берутся из файла SHA256SUMS
(локальный файл рядом со скриптом либо вложение того же релиза).

TUN-драйвер wintun.dll входит в архив region-spoof-bin-wintun.zip — это
официальная сборка с wintun.net (подпись WireGuard LLC проверена),
распаковывается по пути bin\\wintun\\bin\\amd64\\wintun.dll.

Используются только модули стандартной библиотеки — зависимости из
requirements/pip не требуются.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional

# --- Параметры релиза (меняются здесь же, если нужно) ------------------------
REPO_OWNER = "Lab-100"
REPO_NAME = "region-spoof"
RELEASE_TAG = "v1.3-alpha"

SHA256SUMS_NAME = "SHA256SUMS"

# Фиксированный набор вложений релиза, которые скачиваются и проверяются.
ARCHIVES: List[str] = [
    "region-spoof-bin-singbox-1.14.0.zip",
    "region-spoof-bin-mihomo-v1.zip",
    "region-spoof-bin-wintun.zip",
]

SCRIPT_DIR = Path(__file__).resolve().parent
USER_AGENT = "region-spoof-download-binaries/1.0"
TIMEOUT_SEC = 60
CHUNK_SIZE = 1024 * 1024  # 1 МБ — и для хэширования, и для записи
MANIFEST_MAX_BYTES = 1024 * 1024  # манифест — маленький текстовый файл
PROGRESS_INTERVAL_SEC = 0.3  # как часто печатать прогресс скачивания

# Путь, куда пользователь должен вручную положить TUN-драйвер (см. докстринг).
WINTUN_HINT = "bin\\wintun\\bin\\amd64\\wintun.dll"


class DownloadError(Exception):
    """Любая ошибка скрипта: сеть, хэш, архив, аргументы. Код выхода — 1."""


# --------------------------------------------------------------------- URL
def build_default_base_url() -> str:
    """Базовый URL вложений релиза в формате GitHub Releases (без API)."""
    return (
        "https://github.com/"
        f"{REPO_OWNER}/{REPO_NAME}/releases/download/{RELEASE_TAG}"
    )


def join_url(base_url: str, file_name: str) -> str:
    """Склеивает базовый URL и имя вложения, терпя завершающий слэш у базы."""
    return base_url.rstrip("/") + "/" + file_name.lstrip("/")


# ------------------------------------------------------------------- сеть
def download_bytes(url: str, max_bytes: Optional[int] = None) -> bytes:
    """Скачивает URL целиком в память (для маленьких файлов вроде манифеста)."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SEC) as response:
            data = response.read(max_bytes + 1 if max_bytes else None)
    except urllib.error.HTTPError as exc:
        raise DownloadError(
            f"не удалось скачать {url}: HTTP {exc.code} {exc.reason}. "
            "Проверьте, что релиз и имя вложения существуют и доступны."
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DownloadError(
            f"не удалось скачать {url}: {exc}. Проверьте интернет-соединение, "
            "антивирус/файрвол и доступность github.com."
        ) from exc
    if max_bytes is not None and len(data) > max_bytes:
        raise DownloadError(
            f"файл {url} больше допустимого предела {max_bytes} байт — "
            "похоже, это не ожидаемый файл."
        )
    return data


def download_to_file(url: str, dest: Path, label: str) -> int:
    """Скачивает URL в dest (пишет блоками), печатает прогресс. Возвращает размер."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    print(f"Загрузка: {label}", flush=True)
    print(f"  источник: {url}", flush=True)
    downloaded = 0
    last_report = 0.0
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SEC) as response:
            total_header = response.headers.get("Content-Length")
            total = int(total_header) if total_header and total_header.isdigit() else None
            with open(dest, "wb") as out_file:
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    out_file.write(chunk)
                    downloaded += len(chunk)
                    now = time.monotonic()
                    if now - last_report >= PROGRESS_INTERVAL_SEC:
                        last_report = now
                        print(f"  ... {human_size(downloaded)} скачано", flush=True)
    except urllib.error.HTTPError as exc:
        raise DownloadError(
            f"не удалось скачать {label}: HTTP {exc.code} {exc.reason}. "
            "Проверьте, что релиз и имя вложения существуют и доступны."
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DownloadError(
            f"не удалось скачать {label}: {exc}. Проверьте интернет-соединение, "
            "антивирус/файрвол и доступность github.com."
        ) from exc
    if downloaded == 0:
        raise DownloadError(
            f"файл {label} скачан пустым (0 байт) — сервер вернул не тот контент."
        )
    print(f"  всего скачано: {human_size(downloaded)} ({downloaded} байт)", flush=True)
    return downloaded


def human_size(num: int) -> str:
    """Человекочитаемый размер: 78,4 МБ и т.п."""
    value = float(num)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if value < 1024.0 or unit == "ГБ":
            if unit == "Б":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} ГБ"  # недостижимо, но синтаксически безопасно


# ------------------------------------------------------------------ SHA256
def parse_sha256_manifest(text: str) -> Dict[str, str]:
    """
    Разбирает манифест в формате GNU coreutils: '<hex sha256>  <имя файла>'.

    Возвращает {имя_файла_без_каталога: hex_в_нижнем_регистре}.
    Пустые строки и строки-комментарии (#) игнорируются.
    """
    manifest: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].strip().lower(), parts[1].strip()
        # Имя нормализуем к базовому имени: в манифесте путь без каталога,
        # но на случай «./» или обратных слэшей берём только последний сегмент.
        base_name = PurePosixPath(name.replace("\\", "/")).name
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise DownloadError(
                f"в файле {SHA256SUMS_NAME} повреждена строка: {raw_line!r} — "
                "хэш должен быть 64 шестнадцатеричными символами."
            )
        if not base_name:
            continue
        manifest[base_name] = digest
    return manifest


def load_sha256_manifest(explicit_path: Optional[Path], base_url: str) -> Dict[str, str]:
    """
    Читает манифест SHA256SUMS: локальный файл (если задан или лежит рядом со
    скриптом), иначе — скачивает из релиза. Пустой/отсутствующий файл — ошибка.
    """
    candidates: List[Path] = []
    if explicit_path is not None:
        candidates.append(Path(explicit_path))
    else:
        candidates.append(SCRIPT_DIR / SHA256SUMS_NAME)

    for candidate in candidates:
        if not candidate.exists():
            if explicit_path is not None:
                raise DownloadError(
                    f"указанный файл хэшей не найден: {candidate}"
                )
            continue
        try:
            text = candidate.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise DownloadError(f"не удалось прочитать {candidate}: {exc}") from exc
        manifest = parse_sha256_manifest(text)
        if not manifest:
            raise DownloadError(
                f"файл хэшей пуст или не содержит ни одной корректной записи: "
                f"{candidate}. Дождитесь, пока участник подготовит {SHA256SUMS_NAME}, "
                "либо скачайте его из релиза."
            )
        print(f"Хэши взяты из локального файла: {candidate}", flush=True)
        return manifest

    url = join_url(base_url, SHA256SUMS_NAME)
    print(f"Локального {SHA256SUMS_NAME} нет — скачиваю из релиза...", flush=True)
    raw = download_bytes(url, max_bytes=MANIFEST_MAX_BYTES)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DownloadError(
            f"файл {SHA256SUMS_NAME} из релиза не является текстом UTF-8 — "
            "скачайте его заново."
        ) from exc
    manifest = parse_sha256_manifest(text)
    if not manifest:
        raise DownloadError(
            f"скачанный из релиза {SHA256SUMS_NAME} пуст или повреждён — "
            "повторите загрузку."
        )
    print(f"Хэши получены из релиза ({len(manifest)} записей).", flush=True)
    return manifest


def sha256_of_file(path: Path) -> str:
    """Считает SHA256 файла, читая его блоками по 1 МБ."""
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected_hex: str, label: str) -> None:
    """
    Сверяет SHA256 файла с ожидаемым (регистронезависимо).

    При несовпадении бросает DownloadError с подробностями: имя, ожидаемый и
    фактический хэши, размер и объяснение, что это значит.
    """
    actual_hex = sha256_of_file(path)
    if actual_hex.lower() == expected_hex.lower():
        print(f"  SHA256 совпал: {actual_hex}", flush=True)
        return
    size = path.stat().st_size if path.exists() else 0
    raise DownloadError(
        f"ПРОВЕРКА SHA256 ПРОВАЛЕНА для файла {label}\n"
        f"    ожидаемый хэш: {expected_hex.lower()}\n"
        f"    фактический хэш: {actual_hex.lower()}\n"
        f"    размер файла: {human_size(size)} ({size} байт)\n"
        "    Это означает, что файл повреждён при скачивании либо подделан "
        "(подменён на стороне сети/зеркала).\n"
        "    НЕ ИГНОРИРУЙТЕ ЭТУ ОШИБКУ: повторите загрузку ещё раз, при "
        f"повторном несовпадении скачайте {SHA256SUMS_NAME} и архивы вручную "
        "со страницы релиза и сверьте хэши самостоятельно."
    )


# ------------------------------------------------------------------ zip
def _resolve_member_target(member_name: str, target_root: Path) -> Path:
    """
    Возвращает путь распаковки элемента архива либо бросает DownloadError.

    Защита от Zip Slip / path traversal: запрещаем абсолютные пути, пути с
    диском, сегменты '..' и выход за пределы целевого каталога.
    """
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/"):
        raise DownloadError(
            f"архив содержит опасный абсолютный путь: {member_name!r} — распаковка запрещена"
        )
    if re.match(r"^[A-Za-z]:", normalized):
        raise DownloadError(
            f"архив содержит путь с диском: {member_name!r} — распаковка запрещена"
        )
    parts = PurePosixPath(normalized).parts
    if ".." in parts:
        raise DownloadError(
            f"архив содержит путь с '..': {member_name!r} — распаковка запрещена"
        )
    root = target_root.resolve()
    candidate = (root / normalized).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise DownloadError(
            f"архив пытается записать файл вне целевого каталога: {member_name!r} — "
            "распаковка запрещена (возможна подделка архива)"
        ) from exc
    return candidate


def safe_extract_zip(zip_path: Path, target_root: Path) -> List[str]:
    """
    Проверяет и распаковывает zip в target_root, сохраняя структуру архива.

    Сначала проверяются ВСЕ имена элементов (защита от Zip Slip), только затем
    выполняется распаковка. Возвращает список распакованных относительных путей
    (файлы).
    """
    extracted: List[str] = []
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = archive.infolist()
            for member in members:
                _resolve_member_target(member.filename, target_root)
            for member in members:
                target = _resolve_member_target(member.filename, target_root)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, open(target, "wb") as out_file:
                    while True:
                        chunk = source.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        out_file.write(chunk)
                # Сохраняем права на исполнение не нужны в Windows,
                # поэтому атрибуты из архива намеренно не применяем.
                extracted.append(member.filename.replace("\\", "/"))
    except zipfile.BadZipFile as exc:
        raise DownloadError(
            f"файл {zip_path.name} не является корректным zip-архивом: {exc}. "
            "Скорее всего, загрузка оборвалась — повторите её."
        ) from exc
    except OSError as exc:
        raise DownloadError(
            f"не удалось распаковать {zip_path.name} в {target_root}: {exc}. "
            "Проверьте, что файлы не заняты другим процессом (закройте апплет) "
            "и что на диске есть место."
        ) from exc
    if not extracted:
        raise DownloadError(
            f"в архиве {zip_path.name} нет ни одного файла — архив неполон или помят."
        )
    return extracted


# ------------------------------------------------------------------- main
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="download_binaries.py",
        description=(
            "Скачивает архивы бинарников (sing-box, mihomo, wintun) из релиза "
            f"{RELEASE_TAG} репозитория {REPO_OWNER}/{REPO_NAME}, проверяет их "
            "SHA256 по файлу SHA256SUMS и распаковывает в каталог bin/ проекта."
        ),
        epilog=(
            "Для режимов TUN (sing-box/mihomo) требуется запуск от администратора; "
            f"драйвер wintun.dll скрипт ставит по пути: {WINTUN_HINT}"
        ),
    )
    parser.add_argument(
        "--dir",
        metavar="PATH",
        default=None,
        help="каталог назначения (по умолчанию — каталог, где лежит скрипт)",
    )
    parser.add_argument(
        "--sha256-file",
        metavar="PATH",
        default=None,
        help=f"явный путь к файлу {SHA256SUMS_NAME} (по умолчанию: рядом со скриптом, иначе — из релиза)",
    )
    parser.add_argument(
        "--base-url",
        metavar="URL",
        default=build_default_base_url(),
        help=(
            "базовый URL загрузки вложений (по умолчанию — страница релиза GitHub). "
            "Для локального теста можно указать http://127.0.0.1:PORT — итоговый "
            "URL строится как <base-url>/<имя_вложения>"
        ),
    )
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir).resolve() if args.dir else SCRIPT_DIR
    base_url = args.base_url
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DownloadError(f"не удалось создать каталог {target_dir}: {exc}") from exc

    manifest_path = Path(args.sha256_file) if args.sha256_file else None
    manifest = load_sha256_manifest(manifest_path, base_url)

    extracted_all: List[str] = []
    for archive_name in ARCHIVES:
        expected_hex = manifest.get(archive_name)
        if not expected_hex:
            raise DownloadError(
                f"вложение {archive_name} отсутствует в файле {SHA256SUMS_NAME} — "
                "неизвестное вложение, распаковка запрещена. Обновите файл хэшей "
                "или проверьте состав релиза."
            )
        print(f"\n=== {archive_name} ===", flush=True)
        part_path = target_dir / (archive_name + ".part")
        try:
            download_to_file(join_url(base_url, archive_name), part_path, archive_name)
            verify_sha256(part_path, expected_hex, archive_name)
            extracted = safe_extract_zip(part_path, target_dir)
        finally:
            # Временный архив больше не нужен — убираем его в любом случае,
            # чтобы не засорять рабочий каталог и не тащить в git.
            try:
                if part_path.exists():
                    part_path.unlink()
            except OSError as exc:
                print(
                    f"  предупреждение: не удалось удалить временный файл "
                    f"{part_path.name}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
        extracted_all.extend(extracted)
        print(f"  распаковано файлов: {len(extracted)}", flush=True)

    print("\nВСЁ ГОТОВО: бинарники скачаны и распакованы.", flush=True)
    print("Файлы прошли проверку SHA256 и размещены по путям:", flush=True)
    for rel_path in extracted_all:
        print(f"  - {(target_dir / rel_path).as_posix()}", flush=True)
    print(
        "\nДля режимов TUN (sing-box/mihomo) нужен запуск от администратора;\n"
        f"драйвер wintun.dll установлен по пути: {target_dir / WINTUN_HINT}\n"
        "Без TUN работают связки «системный прокси».",
        file=sys.stderr,
        flush=True,
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Точка входа: 0 — успех (все проверки пройдены), 1 — любая ошибка."""
    args = parse_args(argv)
    try:
        return run(args)
    except DownloadError as exc:
        print(f"\nОШИБКА: {exc}", file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        print("\nОШИБКА: загрузка прервана пользователем (Ctrl+C).", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
