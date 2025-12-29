import argparse
import os
import sys
import subprocess
import csv
import logging
import time
import random
import base64
from datetime import datetime, timezone
from pathlib import Path
import shutil
import re
import signal
import locale
import segno
import segno.encoder as segno_encoder
import random
import json

YAML_BACKUPS_CREATED = set()
ASSUME_YES = os.environ.get("WG_CONFIG_GEN_ASSUME_YES") == "1"
ASSUME_BY_SCOPE = {}
CONFIG_FILE = Path("wg_config.yaml")
SUBNETS_FILE = Path("subnets.csv")
OUTPUT_ROOT = Path(".")
SERVER_DIR = OUTPUT_ROOT / "server"
CLIENTS_DIR = OUTPUT_ROOT / "clients"
SERVER_CONF_PATH = SERVER_DIR / "wg0.conf"
VALIDATE_ONLY = False
ALLOW_CONFIG_WRITES = True
CONFIG_WRITE_OVERRIDE = False
FORCE_BILINGUAL = os.environ.get("WG_ATELIER_BILINGUAL", "0") == "1"
FORCE_WRITE = False
DEPENDENCY_HINTS = [
    ("yaml", "pyyaml"),
    ("segno", "segno"),
]
DEFAULT_SPECIAL_JUNK_FILE = "amnezia-I-list.json"
SPECIAL_PACKET_KEYS = ("I1", "I2", "I3", "I4", "I5")
DEFAULT_GENERATE_QR = True
DEFAULT_SPECIAL_MODE = "per_subnet_unique"  # per_client_random | per_subnet_unique | global


def detect_language():
    env_override = os.environ.get("WG_ATELIER_LANG")
    if env_override:
        lowered = env_override.lower()
        if lowered.startswith("ru"):
            return "ru"
        if lowered.startswith("en"):
            return "en"
    lang = ""
    try:
        loc = locale.getlocale() if locale else (None, None)
        if loc and loc[0]:
            lang = loc[0]
        elif locale:
            fallback = locale.getdefaultlocale()
            if fallback and fallback[0]:
                lang = fallback[0]
    except Exception:
        lang = ""
    if lang.lower().startswith("ru"):
        return "ru"
    if lang.lower().startswith("en"):
        return "en"
    return ""


ACTIVE_LANG = detect_language()


def tr(ru_text, en_text):
    if FORCE_BILINGUAL or not ACTIVE_LANG:
        return f"{ru_text} / {en_text}"
    return ru_text if ACTIVE_LANG == "ru" else en_text


def tr_fmt(ru_text, en_text, **kwargs):
    return tr(ru_text, en_text).format(**kwargs)


# RU: Обработка Ctrl+C
# EN: Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    logger.error(tr("Получено прерывание (Ctrl+C), завершаю выполнение", "Interrupt received (Ctrl+C), aborting"))
    raise KeyboardInterrupt

signal.signal(signal.SIGINT, signal_handler)

# RU: Настройка логирования
# EN: Configure application logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('wg-atelier.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# RU: Проверка валидности префикса (только Base64-символы)
# EN: Validate vanity prefix against Base64 charset
def is_valid_prefix(prefix):
    return bool(re.match(r'^[A-Za-z0-9+/]+$', prefix))

# RU: Генерация PSK
# EN: Generate a Pre-Shared Key
def generate_psk():
    logger.info(tr("Генерация Pre-Shared Key", "Generating Pre-Shared Key"))
    psk = subprocess.check_output(["wg", "genpsk"], text=True, encoding='utf-8').strip()
    logger.debug(tr_fmt("Сгенерирован PSK: {psk}", "Generated PSK: {psk}", psk=psk))
    return psk

# RU: Запрос подтверждения у пользователя
# EN: Simple Y/N confirmation helper
def prompt_yes_no(message, default=True, scope="general"):
    if ASSUME_YES:
        choice = "Yes" if default else "No"
        logger.info(tr_fmt('WG_CONFIG_GEN_ASSUME_YES=1: автоматически выбираю {choice} для "{message}"', 'WG_CONFIG_GEN_ASSUME_YES=1: automatically choosing {choice} for "{message}"', choice=choice, message=message))
        return default
    scoped = ASSUME_BY_SCOPE.get(scope)
    if scoped == "yes":
        logger.info(tr_fmt('Режим "все=да" для "{scope}": автоматически выбираю Yes для "{message}"', 'All=Yes mode for "{scope}": automatically choosing Yes for "{message}"', scope=scope, message=message))
        return True
    if scoped == "no":
        logger.info(tr_fmt('Режим "все=нет" для "{scope}": автоматически выбираю No для "{message}"', 'All=No mode for "{scope}": automatically choosing No for "{message}"', scope=scope, message=message))
        return False
    if FORCE_BILINGUAL or ACTIVE_LANG == "ru":
        if default:
            suffix = "[Да/нет/все/нетвсем]"
        else:
            suffix = "[да/Нет/все/нетвсем]"
    else:
        if default:
            suffix = "[Yes/no/all/none]"
        else:
            suffix = "[yes/No/all/none]"
    while True:
        response = input(f"{message} {suffix}: ").strip().lower()
        if not response:
            return default
        if response in ("a", "all", "в", "все"):
            ASSUME_BY_SCOPE[scope] = "yes"
            return True
        if response in ("none", "allno", "all-no", "noall", "alln", "всенет", "нетвсем", "нет всем"):
            ASSUME_BY_SCOPE[scope] = "no"
            return False
        if response in ("y", "yes", "д", "да"):
            return True
        if response in ("n", "no", "н", "нет"):
            return False
        print(tr("Ответьте 'д', 'н', 'в'/'все' или 'нетвсем'.", "Please answer 'y', 'n', 'a'/'all', or 'none'."))

# RU: Парсинг PrivateKey и PresharedKey из клиентского .conf
# EN: Parse PrivateKey and PresharedKey from a client config
def parse_client_keys(conf_path):
    privkey = None
    psk = None
    try:
        with open(conf_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            in_interface = False
            in_peer = False
            for line in lines:
                line = line.strip()
                if line == '[Interface]':
                    in_interface = True
                    in_peer = False
                elif line == '[Peer]':
                    in_interface = False
                    in_peer = True
                elif in_interface and line.startswith('PrivateKey ='):
                    privkey = line.split(' = ')[1]
                elif in_peer and line.startswith('PresharedKey ='):
                    psk = line.split(' = ')[1]
        if not privkey:
            raise ValueError(tr_fmt("PrivateKey не найден в {path}", "PrivateKey not found in {path}", path=conf_path))
        return privkey, psk
    except Exception as e:
        logger.error(tr_fmt("Ошибка парсинга {path}: {error}", "Failed to parse {path}: {error}", path=conf_path, error=e))
        raise

# RU: Извлечение приватного ключа сервера из server/wg0.conf
# EN: Extract server PrivateKey from server/wg0.conf
def extract_server_private_key_from_server_conf(conf_path=None):
    path = Path(conf_path) if conf_path else SERVER_CONF_PATH
    if not path.exists():
        logger.warning(tr_fmt("Файл {path} не найден при попытке восстановить приватный ключ сервера", "File {path} not found while trying to recover the server private key", path=conf_path))
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            in_interface = False
            for line in f:
                stripped = line.strip()
                if stripped == "[Interface]":
                    in_interface = True
                    continue
                if stripped.startswith("[") and stripped.endswith("]") and stripped != "[Interface]":
                    in_interface = False
                if in_interface and stripped.startswith("PrivateKey ="):
                    return stripped.split(" = ", 1)[1]
    except Exception as e:
        logger.error(tr_fmt("Не удалось извлечь приватный ключ сервера из {path}: {error}", "Failed to extract the server private key from {path}: {error}", path=conf_path, error=e))
    return None

# RU: Создание директорий для конфигов
# EN: Ensure server/ and clients/ directories exist
def ensure_dirs():
    if VALIDATE_ONLY:
        logger.debug("Режим валидации: директории server/clients не создаются")
        return
    logger.info(tr("Создание директорий для конфигураций", "Creating configuration directories"))
    SERVER_DIR.mkdir(parents=True, exist_ok=True)
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    logger.debug("Директории %s и %s готовы", SERVER_DIR, CLIENTS_DIR)

# RU: Генерация стандартного ключа WireGuard
# EN: Generate a standard WireGuard key pair
def generate_standard_key():
    logger.info(tr("Генерация стандартного ключа WireGuard", "Generating a standard WireGuard key pair"))
    if not shutil.which("wg"):
        logger.error(tr("Утилита wg не найдена. Установите wireguard-tools", 'Utility "wg" not found. Install wireguard-tools'))
        raise RuntimeError(tr("Утилита wg не найдена", 'Utility "wg" not found'))
    try:
        privkey = subprocess.check_output(["wg", "genkey"], text=True, encoding='utf-8').strip()
        pubkey = subprocess.check_output(["wg", "pubkey"], input=privkey, text=True, encoding='utf-8').strip()
        logger.debug(f"Сгенерированы стандартные ключи: public={pubkey}, private={privkey}")
        return pubkey, privkey
    except subprocess.CalledProcessError as e:
        logger.error(tr_fmt("Ошибка генерации стандартного ключа WireGuard: {error}", "Failed to generate a standard WireGuard key pair: {error}", error=e.stderr))
        raise RuntimeError(tr_fmt("Ошибка генерации стандартного ключа: {error}", "Failed to generate the standard key: {error}", error=e.stderr))

PSK_MODES = {"generate", "generate_per_client", "static"}

def parse_psk_settings(raw_psk):
    settings = {
        "mode": "generate",
        "static_value": None,
        "reuse": True,
        "force_mode_static": False
    }
    if isinstance(raw_psk, dict):
        reuse = raw_psk.get("reuse")
        settings["reuse"] = True if reuse is None else bool(reuse)
        mode = raw_psk.get("mode")
        value = raw_psk.get("value")
        if value:
            settings["static_value"] = str(value).strip()
        if not mode:
            mode = "static" if value else "generate"
        if mode not in PSK_MODES:
            logger.warning(tr_fmt("Неизвестный режим PSK '{mode}', использую 'generate'", "Unknown PSK mode '{mode}', defaulting to 'generate'", mode=mode))
            mode = "generate"
        if settings["static_value"] and mode != "static":
            settings["force_mode_static"] = True
            mode = "static"
        settings["mode"] = mode
        if settings["mode"] == "static" and not settings["static_value"]:
            raise ValueError(tr("psk.mode=static требует непустого поля value", "psk.mode=static requires a non-empty value"))
    else:
        if raw_psk in ("generate", "generate_per_client", None):
            settings["mode"] = raw_psk or "generate"
        else:
            settings["mode"] = "static"
            settings["static_value"] = str(raw_psk).strip()
    return settings

def maybe_backup_yaml(path: Path):
    resolved = path.resolve()
    if resolved in YAML_BACKUPS_CREATED:
        return
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    backup_name = f"{path.name}.{timestamp}.bak"
    backup_path = path.with_name(backup_name)
    shutil.copy2(path, backup_path)
    YAML_BACKUPS_CREATED.add(resolved)
    logger.info(tr_fmt("Создана резервная копия {backup} перед изменением {name}", "Created backup {backup} before modifying {name}", backup=backup_name, name=path.name))


def update_yaml_field(file_path, field_path, new_value):
    global CONFIG_WRITE_OVERRIDE
    if not ALLOW_CONFIG_WRITES and not CONFIG_WRITE_OVERRIDE:
        logger.info(tr("Режим валидации: пропускаю обновление %s", "Validation mode: skipping update for %s"), ".".join(field_path))
        return False
    indent = "  " * len(field_path[:-1])
    field = field_path[-1]
    line_prefix = f"{indent}{field}:"
    pattern = re.compile(rf"(?m)^{re.escape(line_prefix)}.*$")
    replacement = f"{line_prefix} {new_value}"
    path = Path(file_path)
    if not path.exists():
        return False
    content = path.read_text(encoding="utf-8")
    if not pattern.search(content):
        if CONFIG_WRITE_OVERRIDE:
            CONFIG_WRITE_OVERRIDE = False
        logger.warning(tr_fmt("Не удалось автоматически обновить {field} в {file} — добавьте значение вручную.", "Could not update {field} in {file} automatically — please edit it manually.", field=".".join(field_path), file=file_path))
        return False
    maybe_backup_yaml(path)
    path.write_text(pattern.sub(replacement, content, count=1), encoding="utf-8")
    if CONFIG_WRITE_OVERRIDE:
        CONFIG_WRITE_OVERRIDE = False
    return True


def maybe_backup_yaml(path: Path):
    if not ALLOW_CONFIG_WRITES and not CONFIG_WRITE_OVERRIDE:
        return
    resolved = path.resolve()
    if resolved in YAML_BACKUPS_CREATED:
        return
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    backup_name = f"{path.name}.{timestamp}.bak"
    backup_path = path.with_name(backup_name)
    shutil.copy2(path, backup_path)
    YAML_BACKUPS_CREATED.add(resolved)
    logger.info(tr_fmt("Создана резервная копия {backup} перед изменением {name}", "Created backup {backup} before modifying {name}", backup=backup_name, name=path.name))


def require_config_write(reason_ru, reason_en):
    global CONFIG_WRITE_OVERRIDE
    if VALIDATE_ONLY:
        ask = tr(
            f"Режим валидации: {reason_ru}. Разрешить одноразовую запись для этого шага?",
            f"Validation mode: {reason_en}. Allow a one-time write for this step?",
        )
        if prompt_yes_no(ask, default=False, scope="validate_override"):
            logger.warning(tr(
                "Подтверждена разовая запись в режиме validate.",
                "User confirmed a one-time write in validate mode.",
            ))
            CONFIG_WRITE_OVERRIDE = True
            return
        raise ValueError(tr(
            "Режим валидации: запись запрещена. Обновите конфиг и повторите без --validate.",
            "Validation mode: writes are blocked. Update the config and rerun without --validate.",
        ))


def render_mtu_comment(template, mtu_value):
    if not mtu_value:
        return None
    comment_body = (template or "MTU = {mtu}")
    if "{mtu}" in comment_body:
        comment_body = comment_body.replace("{mtu}", str(mtu_value))
    return f"# {comment_body}"


def set_secure_permissions(path: Path):
    if VALIDATE_ONLY:
        return
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME")
            if not user:
                logger.debug("USERNAME не задан, пропускаю настройку прав для %s", path)
                return
            subprocess.run(
                ["icacls", str(path), "/inheritance:r"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["icacls", str(path), "/grant:r", f"{user}:F"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            os.chmod(path, 0o600)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Не удалось изменить права для %s: %s", path, exc)




def write_text_if_changed(path: Path, content: str) -> bool:
    """Записывает файл только при изменении содержимого. Возвращает True, если запись произошла."""
    if VALIDATE_ONLY:
        logger.debug("Режим валидации: запись %s пропущена", path)
        return False
    if FORCE_WRITE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.debug("FORCE: файл %s перезаписан без сравнения", path)
        return True
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
            if existing == content:
                logger.debug("Файл %s не изменился — пропускаю запись", path)
                return False
        except Exception as exc:
            logger.debug("Не удалось прочитать %s для сравнения: %s", path, exc)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def collect_missing_dependencies():
    missing = []
    for module_name, pip_name in DEPENDENCY_HINTS:
        try:
            module = __import__(module_name)
            globals()[module_name] = module
        except ModuleNotFoundError:
            missing.append((module_name, pip_name))
    return missing


def _parse_special_cycle(packets: dict, cycle: int) -> dict:
    """Возвращает словарь I1..I5 для заданного цикла или пустой."""
    result = {}
    for key in SPECIAL_PACKET_KEYS:
        value = packets.get(f"{key}_c{cycle}")
        if not value:
            return {}
        result[key] = value
    return result


def select_special_packets(meta: dict, client_key: str) -> dict:
    if not meta:
        return {}
    if meta.get("type") == "manual":
        manual = meta["manual"].copy()
        manual["_special_cycle"] = "manual"
        manual["_special_source"] = meta.get("source", "amneziawg")
        return manual

    if meta.get("type") != "file":
        return {}

    packets = meta["packets"]
    strategy = meta.get("strategy", DEFAULT_SPECIAL_MODE)
    pool = meta.get("pool") or []

    if strategy == "global":
        cycle = meta.get("global_cycle")
        if cycle is None:
            return {}
    elif strategy == "per_subnet_unique":
        subnet = client_key.split("#", 1)[0]
        state_by_subnet = meta.setdefault("subnet_state", {})
        state = state_by_subnet.get(subnet)
        if not state:
            shuffled = list(pool)
            random.shuffle(shuffled)
            state = {"pool": shuffled, "idx": 0, "exhausted": False}
            state_by_subnet[subnet] = state
        if state["idx"] >= len(state["pool"]):
            state["idx"] = 0
            random.shuffle(state["pool"])
            if not state["exhausted"]:
                logger.warning(tr_fmt(
                    "Пул I1..I5 исчерпан для {subnet}: повторы неизбежны.",
                    "I1..I5 pool exhausted for {subnet}: repeats are inevitable.",
                    subnet=subnet,
                ))
                state["exhausted"] = True
        cycle = state["pool"][state["idx"]]
        state["idx"] += 1
    else:  # per_client_random
        cache = meta.setdefault("cache", {})
        if client_key in cache:
            cycle = cache[client_key]
        else:
            cycle = random.choice(pool)
            cache[client_key] = cycle

    selected = _parse_special_cycle(packets, cycle)
    if not selected:
        return {}
    selected["_special_cycle"] = cycle
    selected["_special_source"] = meta.get("source_path", DEFAULT_SPECIAL_JUNK_FILE)
    return selected


def load_special_packets(config: dict) -> dict:
    """
    Загружает цепочку I1..I5 (Custom Protocol Signature) из файла amnezia-I-list.json.
    Возвращает метаданные для выбора I1..I5 или пустой словарь, если выключено/нет данных.
    Логика:
    - Работает только если задан блок amneziawg.
    - Сначала ищет I1..I5 прямо в amneziawg (ручные значения) — общий набор.
    - enabled=None => включено при наличии репозитория; True/False — принудительно.
    - При enabled=True и отсутствии данных выбрасывает исключение.
    - random_cycle=true выбирает случайный полный набор из файла (иначе — последний).
    - mode: global (один набор на всех) или per_client_random (каждому клиенту случайный cycle из pool).
    """
    amz_present = bool(config.get("amneziawg"))
    if not amz_present:
        return {}

    sp_cfg = config.get("amneziawg_special_packets") or {}
    enabled_cfg = sp_cfg.get("enabled")  # None | bool
    manual_values = {k: v for k, v in (config.get("amneziawg") or {}).items() if k in SPECIAL_PACKET_KEYS}
    data_path = Path(sp_cfg.get("file") or DEFAULT_SPECIAL_JUNK_FILE)
    forced_cycle = sp_cfg.get("cycle")
    random_cycle = bool(sp_cfg.get("random_cycle", False))
    cycles_pool = sp_cfg.get("cycles_pool") or None
    strategy = (sp_cfg.get("mode") or DEFAULT_SPECIAL_MODE).strip().lower()
    reuse_within_client = bool(sp_cfg.get("reuse_within_client", False))

    if not data_path.is_absolute():
        data_path = (CONFIG_FILE.parent / data_path).resolve()
    file_exists = data_path.exists()
    manual_complete = len(manual_values) == len(SPECIAL_PACKET_KEYS)

    if enabled_cfg is False:
        logger.debug("Special packets disabled explicitly (enabled=false)")
        return {}

    if enabled_cfg is None:
        effective_enabled = manual_complete or file_exists
    else:
        effective_enabled = bool(enabled_cfg)

    if not effective_enabled:
        logger.debug("Special packets disabled: enabled=%s, file=%s", enabled_cfg, data_path)
        return {}

    # Приоритет: ручные значения I1..I5 внутри amneziawg
    manual_selected = {}
    if manual_values:
        for key in SPECIAL_PACKET_KEYS:
            if key in manual_values:
                manual_selected[key] = manual_values[key]
        if len(manual_selected) == len(SPECIAL_PACKET_KEYS):
            logger.info(tr("Используются I1..I5 из amneziawg (manual)", "Using I1..I5 from amneziawg (manual)"))
            return {
                "type": "manual",
                "manual": manual_selected,
                "source": "amneziawg",
            }

    if not data_path.exists():
        message = tr_fmt(
            "Файл I1..I5 не найден: {file}. Укажите amneziawg_special_packets.file или заполните I1..I5 вручную в amneziawg.",
            "I1..I5 file not found: {file}. Set amneziawg_special_packets.file or provide manual I1..I5 in amneziawg.",
            file=data_path,
        )
        if VALIDATE_ONLY:
            raise FileNotFoundError(tr_fmt(
                "Файл I1..I5 не найден: {file}. Режим validate не позволяет продолжать без I1..I5 — укажите файл или отключите amneziawg_special_packets.enabled.",
                "I1..I5 file not found: {file}. Validate mode cannot continue without I1..I5 — set the file or disable amneziawg_special_packets.enabled.",
                file=data_path,
            ))
        logger.error(message)
        ask = tr(
            "Продолжить генерацию без I1..I5? (Рекомендуется потом поставить amneziawg_special_packets.enabled=false.)",
            "Continue without I1..I5? (Recommended to set amneziawg_special_packets.enabled=false afterwards.)",
        )
        if prompt_yes_no(ask, default=False, scope="i_fields_missing"):
            logger.warning(tr(
                "Генерация продолжена без I1..I5.",
                "Continuing without I1..I5.",
            ))
            if ALLOW_CONFIG_WRITES:
                ask_update = tr(
                    "Записать в конфиг amneziawg_special_packets.enabled=false?",
                    "Write amneziawg_special_packets.enabled=false into the config?",
                )
                if prompt_yes_no(ask_update, default=True, scope="i_fields_missing"):
                    if update_yaml_field(CONFIG_FILE, ["amneziawg_special_packets", "enabled"], "false"):
                        logger.info(tr(
                            "amneziawg_special_packets.enabled записан как false.",
                            "amneziawg_special_packets.enabled written as false.",
                        ))
                    else:
                        logger.warning(tr(
                            "Не удалось автоматически обновить amneziawg_special_packets.enabled — добавьте вручную.",
                            "Failed to update amneziawg_special_packets.enabled automatically — please add it manually.",
                        ))
            return {}
        raise FileNotFoundError(message)

    with data_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    packets = {}
    raw_packets = data.get("packets")
    raw_sets = data.get("sets") or data.get("blocks")
    # Support simple list format: {"sets": [{"I1": "...", ...}, ...]}
    if isinstance(raw_sets, list) and raw_sets:
        for idx, item in enumerate(raw_sets, start=1):
            if not isinstance(item, dict):
                continue
            if all(k in item for k in SPECIAL_PACKET_KEYS):
                for key in SPECIAL_PACKET_KEYS:
                    packets[f"{key}_c{idx}"] = item[key]
    else:
        packets = raw_packets or {}
        # Support single-set format without cycles: {"packets": {"I1": "...", ...}}
        if packets and all(k in packets for k in SPECIAL_PACKET_KEYS):
            packets = {f"{key}_c1": packets[key] for key in SPECIAL_PACKET_KEYS}
        # Support top-level single-set: {"I1": "...", "I2": "...", ...}
        if not packets and all(k in data for k in SPECIAL_PACKET_KEYS):
            packets = {f"{key}_c1": data[key] for key in SPECIAL_PACKET_KEYS}

        # Support any packet keys starting with I1..I5 and arbitrary suffixes
        # Example: I1_c1, I2_custom, I3foo, I4, I5_any -> normalized to I*_cN
        if packets:
            suffix_map = {}
            for name, value in packets.items():
                m = re.match(r"^(I[1-5])(.*)$", name)
                if not m:
                    continue
                key = m.group(1)
                suffix = m.group(2) or ""
                suffix_map.setdefault(suffix, {})
                suffix_map[suffix][key] = value
            if suffix_map:
                normalized = {}
                # deterministic order: empty suffix first, then sorted suffixes
                suffixes = []
                if "" in suffix_map:
                    suffixes.append("")
                suffixes += sorted(s for s in suffix_map.keys() if s != "")
                cycle = 1
                for suffix in suffixes:
                    item = suffix_map.get(suffix, {})
                    if all(k in item for k in SPECIAL_PACKET_KEYS):
                        for key in SPECIAL_PACKET_KEYS:
                            normalized[f"{key}_c{cycle}"] = item[key]
                        cycle += 1
                if normalized:
                    packets = normalized
    cycles_found = {}
    for name in packets:
        m = re.match(r"I[1-5]_c(\d+)$", name)
        if not m:
            continue
        cycles_found.setdefault(int(m.group(1)), 0)
        cycles_found[int(m.group(1))] += 1
    complete_cycles = sorted(c for c, cnt in cycles_found.items() if cnt >= len(SPECIAL_PACKET_KEYS))
    if not complete_cycles:
        raise ValueError(
            tr_fmt(
                "В {file} нет полного набора I1..I5",
                "File {file} has no full I1..I5 set",
                file=data_path,
            )
        )
    pool = cycles_pool or complete_cycles
    pool = [int(c) for c in pool if int(c) in complete_cycles]
    if not pool:
        pool = complete_cycles

    global_cycle = None
    if strategy == "global":
        if forced_cycle is not None:
            chosen_cycle = int(forced_cycle)
        elif random_cycle:
            chosen_cycle = random.choice(pool)
        else:
            chosen_cycle = pool[-1]
        selected = _parse_special_cycle(packets, chosen_cycle)
        if not selected:
            raise ValueError(
                tr_fmt(
                    "В {file} отсутствуют все I1..I5 для цикла {cycle}",
                    "File {file} lacks complete I1..I5 for cycle {cycle}",
                    file=data_path,
                    cycle=chosen_cycle,
                )
            )
        global_cycle = chosen_cycle

    logger.info(
        tr_fmt(
            "Загружены I1..I5 из {file} (cycles={count}, strategy={strategy}, global_cycle={gc})",
            "Loaded I1..I5 from {file} (cycles={count}, strategy={strategy}, global_cycle={gc})",
            file=data_path,
            count=len(pool),
            strategy=strategy,
            gc=global_cycle,
        )
    )
    return {
        "type": "file",
        "packets": packets,
        "pool": pool,
        "forced_cycle": forced_cycle,
        "random_cycle": random_cycle,
        "strategy": strategy,
        "reuse_within_client": reuse_within_client,
        "global_cycle": global_cycle,
        "source_path": str(data_path),
        "cache": {},
    }


def configure_paths(args):
    global CONFIG_FILE, SUBNETS_FILE, OUTPUT_ROOT, SERVER_DIR, CLIENTS_DIR, SERVER_CONF_PATH, VALIDATE_ONLY, ALLOW_CONFIG_WRITES
    CONFIG_FILE = Path(args.config).expanduser().resolve()
    SUBNETS_FILE = Path(args.subnets).expanduser().resolve()
    OUTPUT_ROOT = Path(args.output_root).expanduser().resolve()
    SERVER_DIR = OUTPUT_ROOT / "server"
    CLIENTS_DIR = OUTPUT_ROOT / "clients"
    SERVER_CONF_PATH = SERVER_DIR / "wg0.conf"
    VALIDATE_ONLY = args.validate
    ALLOW_CONFIG_WRITES = not args.validate


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="Генератор серверных и клиентских конфигураций WireGuard",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-c", "--config", default="wg_config.yaml", help="Путь к wg_config.yaml")
    parser.add_argument("-s", "--subnets", default="subnets.csv", help="Путь к subnets.csv")
    parser.add_argument(
        "-o",
        "--output-root",
        default=".",
        help="Каталог, куда будут записаны server/ и clients/",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Только проверить конфигурацию и выйти без записи файлов",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Перезаписывать server/clients и QR-коды, даже если содержимое не изменилось",
    )
    return parser.parse_args()


def apply_force_flag(args):
    """Обработать --force: подтвердить один раз и учесть при валидации."""
    global FORCE_WRITE
    if args.validate and args.force:
        logger.warning(tr("Флаг --force игнорируется при --validate: файлы не будут записаны.", "--force is ignored when --validate is set; no files will be written."))
        FORCE_WRITE = False
        return
    if not args.force:
        FORCE_WRITE = False
        return
    prompt = tr(
        "Перезаписать все конфиги и QR даже без изменений? Это может стереть ручные правки.",
        "Rewrite all configs and QR even if unchanged? This may wipe manual edits.",
    )
    if prompt_yes_no(prompt, default=False, scope="force"):
        FORCE_WRITE = True
        logger.info(tr("FORCE включен: файлы будут перезаписываться даже без изменений.", "FORCE enabled: files will be rewritten even if unchanged."))
    else:
        FORCE_WRITE = False
        logger.info(tr("FORCE отключён по отказу пользователя.", "FORCE disabled per user choice."))


def resolve_port_value(server_cfg):
    """Определить порт: server.port -> ListenPort из server/wg0.conf -> случайный."""
    cfg_port = server_cfg.get("port")
    if cfg_port:
        try:
            port_int = int(cfg_port)
            if 1 <= port_int <= 65535:
                return port_int
            logger.error(tr_fmt("Некорректный port={port} в конфиге", "Invalid port={port} in config", port=cfg_port))
        except Exception:
            logger.error(tr_fmt("Некорректный формат port={port} в конфиге", "Invalid port format {port} in config", port=cfg_port))
    if SERVER_CONF_PATH.exists():
        try:
            with SERVER_CONF_PATH.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("ListenPort ="):
                        listen_port = line.strip().split("=", 1)[1].strip()
                        port_int = int(listen_port)
                        if 1 <= port_int <= 65535:
                            logger.info(tr_fmt("Порт не указан в YAML, использую ListenPort из {path}: {port}", "Port missing in YAML; reusing ListenPort from {path}: {port}", path=SERVER_CONF_PATH, port=port_int))
                            return port_int
        except Exception as exc:
            logger.debug("Не удалось прочитать ListenPort из %s: %s", SERVER_CONF_PATH, exc)
    generated_port = random.randint(1024, 65535)
    logger.info(tr_fmt("Порт не указан: выбран случайный порт {port}", "Port not specified: selected random port {port}", port=generated_port))
    return generated_port

def resolve_server_private_key(server_cfg):
    key = server_cfg.get("private_key")
    if key:
        return key.strip()
    if VALIDATE_ONLY:
        if SERVER_CONF_PATH.exists():
            require_config_write(
                "server.private_key отсутствует; в режиме validate нельзя переносить ключ из server/wg0.conf",
                "server.private_key is missing; validate mode cannot import the key from server/wg0.conf",
            )
        require_config_write(
            "server.private_key отсутствует; в режиме validate ключ не генерируется",
            "server.private_key is missing; validate mode will not generate a key",
        )
    ask_generate = tr(
        "server.private_key отсутствует. Сгенерировать новый ключ, записать его в конфиг и продолжить?",
        "server.private_key is missing. Generate a new key, write it to the config, and continue?",
    )
    if SERVER_CONF_PATH.exists():
        logger.warning(tr("server.private_key отсутствует в %s. Найден файл %s с ключом.", "server.private_key is missing in %s. Found %s with a key."), CONFIG_FILE, SERVER_CONF_PATH)
        ask = tr_fmt("Разрешить прочитать {server_conf}, чтобы перенести приватный ключ в {config}?",
                     "Allow reading {server_conf} to move the private key into {config}?",
                     server_conf=SERVER_CONF_PATH, config=CONFIG_FILE)
        if prompt_yes_no(ask, default=True, scope="server_key"):
            legacy_key = extract_server_private_key_from_server_conf(SERVER_CONF_PATH)
            if not legacy_key:
                raise ValueError(tr_fmt("Не удалось извлечь приватный ключ из {path}. Добавьте значение вручную.",
                                         "Failed to extract the private key from {path}. Please add it manually.",
                                         path=SERVER_CONF_PATH))
            if update_yaml_field(CONFIG_FILE, ["server", "private_key"], legacy_key):
                logger.info(tr("server.private_key автоматически записан в %s", "server.private_key was written to %s"), CONFIG_FILE)
            else:
                logger.warning(tr("Не удалось перезаписать server.private_key — добавьте значение вручную.",
                                  "Failed to update server.private_key automatically — please add it manually."))
            return legacy_key
        if prompt_yes_no(ask_generate, default=True, scope="server_key"):
            generated_key, _ = generate_standard_key()
            if update_yaml_field(CONFIG_FILE, ["server", "private_key"], generated_key):
                logger.info(tr("server.private_key автоматически записан в %s", "server.private_key was written to %s"), CONFIG_FILE)
            else:
                logger.warning(tr("Не удалось перезаписать server.private_key — добавьте значение вручную.",
                                  "Failed to update server.private_key automatically — please add it manually."))
            return generated_key
        raise ValueError(tr("Продолжение без server.private_key запрещено. Добавьте значение вручную и повторите запуск.",
                            "Cannot continue without server.private_key. Add the value manually and rerun."))
    if prompt_yes_no(ask_generate, default=True, scope="server_key"):
        generated_key, _ = generate_standard_key()
        if update_yaml_field(CONFIG_FILE, ["server", "private_key"], generated_key):
            logger.info(tr("server.private_key автоматически записан в %s", "server.private_key was written to %s"), CONFIG_FILE)
        else:
            logger.warning(tr("Не удалось перезаписать server.private_key — добавьте значение вручную.",
                              "Failed to update server.private_key automatically — please add it manually."))
        return generated_key
    raise ValueError(tr_fmt("Не указан server.private_key и не найден {path} с действующим ключом.",
                           "server.private_key missing and {path} with a valid key not found.", path=SERVER_CONF_PATH))
def extract_static_psk_from_clients():
    root = CLIENTS_DIR
    if not root.exists():
        return None
    for conf in root.rglob("*.conf"):
        _, psk = parse_client_keys(conf)
        if psk:
            return psk
    return None


def count_existing_client_configs():
    root = CLIENTS_DIR
    if not root.exists():
        return 0
    count = 0
    for _ in root.rglob("*.conf"):
        count += 1
        if count > 5000:
            break
    return count

def prompt_delete_missing_subnets(csv_subnet_names):
    root = CLIENTS_DIR
    if not root.exists():
        return
    csv_set = set(csv_subnet_names)
    existing = sorted([d.name for d in root.iterdir() if d.is_dir()])
    for name in existing:
        if name in csv_set:
            continue
        if VALIDATE_ONLY:
            logger.warning(tr_fmt("Подсеть {name} отсутствует в {csv} (режим валидации, удаление пропущено)", "Subnet {name} is missing from {csv} (validation mode, deletion skipped)", name=name, csv=SUBNETS_FILE))
            continue
        ask = tr_fmt("Подсеть {name} отсутствует в {csv}. Удалить {path}?", "Subnet {name} is missing from {csv}. Remove {path}?", name=name, csv=SUBNETS_FILE, path=root / name)
        if prompt_yes_no(ask, default=False, scope="delete_subnet"):
            shutil.rmtree(root / name)
            logger.info(tr_fmt("Удалены конфиги {path}/", "Removed configs under {path}/", path=root / name))
        else:
            logger.warning(tr_fmt(
                "Подсеть {name} осталась в {root}, но не попадёт в новые конфиги. "
                "Её индекс может быть переиспользован новой подсетью.",
                "Subnet {name} remains in {root} but will not be included in new configs. "
                "Its index may be reused by a new subnet.",
                name=name, root=root))


def extract_subnet_index_from_client_conf(conf_path: Path):
    """RU: Извлекает индекс подсети (X в 10.0.X.* / fd00::X:*) из client .conf.
       EN: Extracts subnet index (X in 10.0.X.* / fd00::X:*) from client .conf."""
    try:
        content = conf_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning(tr_fmt("Не удалось прочитать {path}: {error}",
                              "Failed to read {path}: {error}", path=conf_path, error=exc))
        return None
    match_ipv4 = re.search(r"\b10\.0\.(\d+)\.\d+/\d+\b", content)
    match_ipv6 = re.search(r"\bfd00::(\d+):\d+/\d+\b", content)
    idx4 = int(match_ipv4.group(1)) if match_ipv4 else None
    idx6 = int(match_ipv6.group(1)) if match_ipv6 else None
    if idx4 and idx6 and idx4 != idx6:
        logger.warning(tr_fmt(
            "Несовпадение индекса подсети в {path}: IPv4={idx4}, IPv6={idx6}",
            "Subnet index mismatch in {path}: IPv4={idx4}, IPv6={idx6}",
            path=conf_path, idx4=idx4, idx6=idx6))
    return idx4 or idx6


def discover_existing_subnet_indices(csv_subnet_names):
    """RU: Пытается определить индексы подсетей по существующим клиентским конфигам.
       EN: Tries to determine subnet indices from existing client configs."""
    root = CLIENTS_DIR
    if not root.exists():
        return {}
    indices = {}
    used = set()
    for subnet_dir in sorted([d for d in root.iterdir() if d.is_dir()]):
        subnet_name = subnet_dir.name
        if subnet_name not in csv_subnet_names:
            continue
        conf_files = sorted([f for f in subnet_dir.iterdir() if f.suffix == ".conf"])
        if not conf_files:
            continue
        found = []
        for conf in conf_files:
            idx = extract_subnet_index_from_client_conf(conf)
            if idx:
                found.append(idx)
        if not found:
            continue
        # Pick the most common index to tolerate a stray file.
        idx_counts = {}
        for idx in found:
            idx_counts[idx] = idx_counts.get(idx, 0) + 1
        best_idx = sorted(idx_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        if best_idx in used:
            logger.warning(tr_fmt(
                "Индекс подсети {idx} уже занят другой подсетью; {name} будет переназначена",
                "Subnet index {idx} is already used by another subnet; {name} will be reassigned",
                idx=best_idx, name=subnet_name))
            continue
        indices[subnet_name] = best_idx
        used.add(best_idx)
    if indices:
        logger.info(tr_fmt("Восстановлены индексы подсетей из существующих конфигов: {count}",
                           "Restored subnet indices from existing configs: {count}", count=len(indices)))
    return indices


def allocate_subnet_indices(subnets, existing_indices):
    """RU: Назначает индексы подсетей, сохраняя старые и заполняя свободные.
       EN: Assigns subnet indices, keeping existing ones and filling gaps."""
    subnet_indices = {}
    used = set(existing_indices.values())
    next_idx = 1
    for subnet in subnets:
        name = subnet["name"]
        if name in existing_indices:
            subnet_indices[name] = existing_indices[name]
            continue
        while next_idx in used:
            next_idx += 1
        subnet_indices[name] = next_idx
        used.add(next_idx)
        next_idx += 1
    return subnet_indices
# RU: Генерация пары ключей с красивым публичным ключом
# EN: Generate a key pair with a vanity public key prefix
def generate_vanity_key(prefix, client_idx, vanity_length):
    logger.info(tr_fmt("Генерация ключа для клиента #{idx} с префиксом {prefix} (длина {length})", "Generating key for client #{idx} with prefix {prefix} (length {length})", idx=client_idx+1, prefix=prefix, length=vanity_length))
    start_time = time.time()
    
    if not is_valid_prefix(prefix) or vanity_length == 0:
        logger.warning(tr_fmt("Невалидный префикс {prefix} или vanity_length=0 — использую стандартный ключ", "Invalid prefix {prefix} or vanity_length=0 — falling back to a standard key", prefix=prefix))
        return generate_standard_key()
    
    if not shutil.which("wireguard-vanity-address"):
        logger.warning(tr("Утилита wireguard-vanity-address не найдена, использую стандартный ключ", "wireguard-vanity-address not found, using a standard key"))
        return generate_standard_key()
    
    cmd = ["wireguard-vanity-address", "--in", str(vanity_length), prefix]
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )
        pubkey, privkey = None, None
        while True:
            try:
                line = process.stdout.readline().strip()
                if not line and process.poll() is not None:
                    break
                if line.startswith("private ") and " public " in line:
                    parts = line.split(" public ")
                    if len(parts) == 2:
                        privkey = parts[0].replace("private ", "").strip()
                        pubkey = parts[1].strip()
                        process.terminate()
                        break
            except UnicodeDecodeError as e:
                process.terminate()
                logger.error(tr_fmt("Ошибка декодирования вывода wireguard-vanity-address: {error}", "Failed to decode wireguard-vanity-address output: {error}", error=e))
                raise RuntimeError(tr_fmt("Ошибка декодирования вывода: {error}", "Failed to decode output: {error}", error=e))
        
        try:
            stdout, stderr = process.communicate(timeout=1)
            logger.debug(f"Вывод wireguard-vanity-address для префикса {prefix}:\n{stdout}\nОшибки: {stderr}")
        except subprocess.TimeoutExpired:
            process.kill()
            logger.warning(tr_fmt("Процесс для префикса {prefix} не завершился — остановлен принудительно", "Process for prefix {prefix} did not finish and was terminated", prefix=prefix))
        
        if pubkey and privkey:
            duration = time.time() - start_time
            logger.info(tr_fmt("Ключи для префикса {prefix} сгенерированы за {seconds:.2f} сек", "Keys for prefix {prefix} generated in {seconds:.2f} s", prefix=prefix, seconds=duration))
            return pubkey, privkey
        
        logger.warning(tr_fmt("Ключи не найдены в выводе для префикса {prefix}, использую стандартный ключ", "No keys found in the output for prefix {prefix}; using a standard key", prefix=prefix))
        return generate_standard_key()
    
    except subprocess.CalledProcessError as e:
        logger.error(tr_fmt("Ошибка вызова wireguard-vanity-address для префикса {prefix}: {error}", "wireguard-vanity-address call failed for prefix {prefix}: {error}", prefix=prefix, error=e.stderr))
        raise RuntimeError(tr_fmt("Ошибка генерации ключа для префикса {prefix}: {error}", "Failed to generate key for prefix {prefix}: {error}", prefix=prefix, error=e.stderr))
    except Exception as e:
        logger.error(tr_fmt("Неожиданная ошибка при генерации ключа для префикса {prefix}: {error}", "Unexpected error while generating a key for prefix {prefix}: {error}", prefix=prefix, error=e))
        raise RuntimeError(tr_fmt("Неожиданная ошибка: {error}", "Unexpected error: {error}", error=e))

# RU: Генерация серверного конфига для NetworkManager
# EN: Build the server configuration (wg0.conf)
def generate_server_config(config, server_privkey, server_pubkey, client_psks, subnet_indices, special_meta=None):
    logger.info(tr("Генерация серверного конфига wg0.conf", "Generating server config wg0.conf"))
    port = config['_resolved_port']
    if 'port' not in config:
        logger.info(tr_fmt("Порт не указан, используется вычисленный порт: {port}", "Port not specified; using resolved port {port}", port=port))
    psk_mode = config.get('_psk_mode', 'generate')
    static_psk = config.get('_psk_static_value')
    common_psk = config.get('common_psk')

    server_conf = "# Import into NetworkManager: sudo nmcli connection import type wireguard file server/wg0.conf\n\n"
    server_conf += f"""[Interface]
PrivateKey = {server_privkey}
Address = {config['server_ipv4']}/24, {config['server_ipv6']}/64
ListenPort = {port}
"""
    server_mtu_comment = render_mtu_comment(config.get('server_mtu_comment'), config.get('mtu'))
    if server_mtu_comment:
        server_conf += f"{server_mtu_comment}\n"
    
    if config.get('amneziawg_on_server', False) and config.get('amneziawg'):
        amneziawg_params = ['Jc', 'Jmin', 'Jmax', 'Jd', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']
        amneziawg_long = {
            'Jc': 'JunkPacketCount',
            'Jmin': 'JunkPacketMinSize',
            'Jmax': 'JunkPacketMaxSize',
            'Jd': 'JunkPacketDelay',
            'S1': 'RandomDataInitiation',
            'S2': 'RandomDataResponse',
            'H1': 'HandshakeInitiationType',
            'H2': 'HandshakeResponseType',
            'H3': 'CookieReplyType',
            'H4': 'TransportDataType'
        }
        logger.debug(f"Добавление параметров AmneziaWG в серверный конфиг: {list(config['amneziawg'].keys())}")
        for param in amneziawg_params:
            param_lower = param.lower()
            if param_lower in config['amneziawg'] or param in config['amneziawg']:
                value = config['amneziawg'].get(param_lower, config['amneziawg'].get(param))
                server_conf += f"# {amneziawg_long[param]} = {value}\n"
                server_conf += f"{param} = {value}\n"

        special_packets = select_special_packets(special_meta, "__server__") if special_meta else {}
        if special_packets:
            src = special_packets.get("_special_source", DEFAULT_SPECIAL_JUNK_FILE)
            cycle = special_packets.get("_special_cycle")
            server_conf += "# Custom protocol signature\n"
            for key in SPECIAL_PACKET_KEYS:
                if key in special_packets:
                    server_conf += f"{key} = {special_packets[key]}\n"

    server_conf += "\n"
    
    ordered_subnets = sorted(subnet_indices.items(), key=lambda item: item[1])
    existing_dirs = set()
    if CLIENTS_DIR.exists():
        existing_dirs = {d.name for d in CLIENTS_DIR.iterdir() if d.is_dir()}
    for subnet_name, subnet_idx in ordered_subnets:
        if subnet_name not in existing_dirs:
            continue
        subnet_dir = CLIENTS_DIR / subnet_name
        conf_files = sorted([f for f in subnet_dir.iterdir() if f.suffix == '.conf'])
        for conf_file in conf_files:
            conf_path = conf_file
            client_name = conf_file.stem
            try:
                client_idx = int(client_name.split('_client')[1])
            except ValueError:
                logger.warning(tr("Неверное имя файла %s, пропускаю", "Invalid file name %s; skipping"), conf_file)
                continue
            privkey, psk = parse_client_keys(conf_path)
            client_pubkey = subprocess.check_output(["wg", "pubkey"], input=privkey, text=True, encoding='utf-8').strip()
            client_ipv4 = f"10.0.{subnet_idx}.{client_idx}/32"
            client_ipv6 = f"fd00::{subnet_idx}:{client_idx}/128"
            server_conf += f"""[Peer]
# Client {client_name}
PublicKey = {client_pubkey}
AllowedIPs = {client_ipv4}, {client_ipv6}
"""
            psk_key = f"{subnet_name}_client{client_idx}"
            if psk_key in client_psks:
                server_conf += f"PresharedKey = {client_psks[psk_key]}\n"
            elif psk_mode == 'static' and static_psk:
                server_conf += f"PresharedKey = {static_psk}\n"
            elif psk_mode == 'generate' and common_psk:
                server_conf += f"PresharedKey = {common_psk}\n"
            server_keepalive = config.get('server_keepalive')
            keepalive_value = server_keepalive if server_keepalive is not None else config.get('persistent_keepalive')
            if config.get('keepalive_on_server', True) and keepalive_value:
                server_conf += f"PersistentKeepalive = {keepalive_value}\n"
            server_conf += "\n"
    
    if VALIDATE_ONLY:
        logger.info(tr("Режим валидации: серверный конфиг не записан.", "Validation mode: server config not written."))
        return server_conf

    if not write_text_if_changed(SERVER_CONF_PATH, server_conf):
        logger.info(tr_fmt("Серверный конфиг {path} не изменился — запись пропущена", "Server config {path} unchanged — skipping write", path=SERVER_CONF_PATH))
        return server_conf
    set_secure_permissions(SERVER_CONF_PATH)
    logger.info(tr_fmt("Серверный конфиг сохранён в {path}", "Server config saved to {path}", path=SERVER_CONF_PATH))
    return server_conf

# RU: Генерация клиентского конфига с поддержкой AmneziaWG
# EN: Build client configs with optional AmneziaWG hints
def existing_has_special(path: Path) -> bool:
    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return False
    return any(re.search(rf"^{k}\s*=", content, re.MULTILINE) for k in SPECIAL_PACKET_KEYS)


def generate_client_config(config, subnet, client_idx, client_privkey, client_pubkey, server_pubkey, psk=None, special_meta=None):
    client_name = f"{subnet['name']}_client{client_idx+1}"
    logger.info(tr_fmt("Генерация конфига для клиента {name}", "Generating config for client {name}", name=client_name))
    client_ipv4 = f"{subnet['ipv4_base']}{client_idx+1}/32"
    client_ipv6 = f"{subnet['ipv6_base']}:{client_idx+1}/128"
    endpoint_port = config['_resolved_port']
    psk_mode = config.get('_psk_mode', 'generate')
    static_psk = config.get('_psk_static_value')
    common_psk = config.get('common_psk')
    client_conf = f"""[Interface]
PrivateKey = {client_privkey}
Address = {client_ipv4}, {client_ipv6}
"""
    if config.get('dns_ipv4') or config.get('dns_ipv6'):
        dns_addresses = ', '.join(config.get('dns_ipv4', []) + config.get('dns_ipv6', []))
        client_conf += f"DNS = {dns_addresses}\n"
    
    client_mtu_comment = render_mtu_comment(
        config.get('client_mtu_comment') or config.get('server_mtu_comment'),
        config.get('mtu')
    )
    if client_mtu_comment:
        client_conf += f"{client_mtu_comment}\n"
    
    if config.get('amneziawg'):
        amneziawg_params = ['Jc', 'Jmin', 'Jmax', 'Jd', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']
        amneziawg_long = {
            'Jc': 'JunkPacketCount',
            'Jmin': 'JunkPacketMinSize',
            'Jmax': 'JunkPacketMaxSize',
            'Jd': 'JunkPacketDelay',
            'S1': 'RandomDataInitiation',
            'S2': 'RandomDataResponse',
            'H1': 'HandshakeInitiationType',
            'H2': 'HandshakeResponseType',
            'H3': 'CookieReplyType',
            'H4': 'TransportDataType'
        }
        logger.debug(f"Добавление параметров AmneziaWG в клиентский конфиг {client_name}: {list(config['amneziawg'].keys())}")
        for param in amneziawg_params:
            param_lower = param.lower()
            if param_lower in config['amneziawg'] or param in config['amneziawg']:
                value = config['amneziawg'].get(param_lower, config['amneziawg'].get(param))
                client_conf += f"# {amneziawg_long[param]} = {value}\n"
                client_conf += f"{param} = {value}\n"

        special_packets = select_special_packets(special_meta, f"{subnet['name']}#{client_idx}") if special_meta else {}
        if special_packets:
            src = special_packets.get("_special_source", DEFAULT_SPECIAL_JUNK_FILE)
            cycle = special_packets.get("_special_cycle")
            client_conf += "# Custom protocol signature\n"
            for key in SPECIAL_PACKET_KEYS:
                if key in special_packets:
                    client_conf += f"{key} = {special_packets[key]}\n"

    client_conf += f"""
[Peer]
PublicKey = {server_pubkey}
Endpoint = {config['server_endpoint']}:{endpoint_port}
AllowedIPs = 0.0.0.0/0, ::/0
"""
    if psk:
        client_conf += f"PresharedKey = {psk}\n"
    elif psk_mode == 'static' and static_psk:
        client_conf += f"PresharedKey = {static_psk}\n"
    elif psk_mode == 'generate' and common_psk:
        client_conf += f"PresharedKey = {common_psk}\n"
    if 'persistent_keepalive' in config:
        client_conf += f"PersistentKeepalive = {config['persistent_keepalive']}\n"
    
    # RU: Краткая подсказка для Keenetic (CLI после импорта .conf)
    # EN: Short Keenetic note (CLI after Web UI import)
    amz = config.get('amneziawg') or {}
    def _awg(key, default):
        return amz.get(key.lower(), amz.get(key, default))
    asc_values = [
        _awg('Jc', 0),
        _awg('Jmin', 0),
        _awg('Jmax', 0),
        _awg('S1', 0),
        _awg('S2', 0),
        _awg('H1', 1),
        _awg('H2', 2),
        _awg('H3', 3),
        _awg('H4', 4),
    ]
    asc_str = " ".join(str(v) for v in asc_values)
    client_conf += (
        "\n"
        "# Netcraze/Keenetic: firmware >=5.0.2 usually applies ASC on import; firmware <5.0.2 set ASC manually:\n"
        "#   1) Open Web CLI https://<ROUTER_IP>/a (or SSH).\n"
        "#   2) \"show interface\" (find name like Wireguard0)\n"
        "#   3) \"interface <NAME>\"\n"
        f"#   4) \"wireguard asc {asc_str}\"\n"
        "#   5) \"show running-config\" (check wireguard asc ...)\n"
        "#   6) \"system configuration save\"\n"
        "# I1..I5 are not supported by Netcraze/Keenetic; they are safe to ignore there.\n"
    )
    
    subnet_dir = CLIENTS_DIR / subnet['name']
    if VALIDATE_ONLY:
        return
    subnet_dir.mkdir(parents=True, exist_ok=True)
    conf_path = subnet_dir / f"{client_name}.conf"

    # Запрос перед перезаписью I-полей, если уже есть и нет FORCE_WRITE
    if not FORCE_WRITE and conf_path.exists() and special_packets and existing_has_special(conf_path):
        ask = tr_fmt("В {path} уже есть I1..I5. Перезаписать их новыми значениями?", "File {path} already contains I1..I5. Overwrite with new values?", path=conf_path)
        if not prompt_yes_no(ask, default=False, scope="i_fields_overwrite"):
            logger.info(tr_fmt("Пропускаю обновление {path} по запросу пользователя", "Skipping update of {path} per user choice", path=conf_path))
            return

    if not write_text_if_changed(conf_path, client_conf):
        logger.info(tr_fmt("Конфиг {path} не изменился — пропускаю перезапись и генерацию QR", "Client config {path} unchanged — skipping write and QR generation.", path=conf_path))
        return
    set_secure_permissions(conf_path)
    logger.info(tr_fmt("Конфиг клиента сохранён в {path}", "Client config saved to {path}", path=conf_path))

    special_packets = config.get('_special_packets') or {}
    generate_qr = config.get('_generate_qr', DEFAULT_GENERATE_QR)
    if special_packets:
        logger.info(tr("QR пропущен: заданы I-поля (I1..I5). Конфиг сохранён.", "QR skipped: I1..I5 present. Config saved."))
        return
    if not generate_qr:
        logger.info(tr("QR пропущен по конфигурации (generate_qr=false).", "QR skipped per config (generate_qr=false)."))
        return

    logger.debug("Генерация QR-кода для %s", client_name)
    try:
        qr = segno.make(client_conf)
        qr_path = subnet_dir / f"{client_name}.qr.png"
        qr.save(qr_path, scale=8)
        logger.info(tr_fmt("QR-код сохранён в {path}", "QR code saved to {path}", path=qr_path))
    except segno_encoder.DataOverflowError:
        logger.warning(tr(
            "QR пропущен: данные слишком объёмные (возможно из-за I1..I5 или больших комментариев). Конфиг сохранён, QR не создан.",
            "QR skipped: data too large (likely due to I1..I5 or verbose comments). Config saved; QR not generated."
        ))
    except Exception as exc:
        logger.error(tr_fmt("Не удалось сгенерировать QR: {error}", "Failed to generate QR: {error}", error=exc))

# RU: Чтение подсетей из CSV
# EN: Read subnet definitions from CSV
def read_subnets_csv(csv_file):
    logger.info(tr_fmt("Чтение подсетей из {path}", "Reading subnets from {path}", path=csv_file))
    subnets = []
    try:
        with open(csv_file, newline='', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=';')
            for row in reader:
                if len(row) >= 2:
                    name = row[0].strip()
                    try:
                        count = int(row[1].strip())
                        subnets.append({'name': name, 'clients': count})
                        logger.debug(f"Прочитана подсеть: {name}, клиентов: {count}")
                    except ValueError:
                        logger.warning(tr_fmt("Пропущена строка с некорректным числом клиентов: {row}", "Skipped row with invalid client count: {row}", row=row))
                        continue
        if not subnets:
            logger.warning(tr("В файле CSV нет валидных строк с подсетями", "CSV file contains no valid subnet rows"))
        else:
            logger.info(tr_fmt("Успешно прочитано {count} подсетей из CSV", "Successfully read {count} subnets from CSV", count=len(subnets)))
        return subnets
    except FileNotFoundError:
        logger.error(tr_fmt("Файл {path} не найден", "File {path} not found", path=csv_file))
        raise
    except Exception as e:
        logger.error(tr_fmt("Ошибка обработки CSV: {error}", "Error processing CSV: {error}", error=e))
        raise

# RU: Основная функция
# EN: Entry point
def main():
    args = parse_cli_args()
    configure_paths(args)
    logger.info(tr("Запуск генератора конфигураций WireGuard", "Starting the WireGuard config generator"))
    start_time = time.time()
    if ASSUME_YES:
        logger.warning(tr("WG_CONFIG_GEN_ASSUME_YES=1: все запросы подтверждаются автоматически. Используйте осторожно.", "WG_CONFIG_GEN_ASSUME_YES=1: all prompts auto-confirmed. Use with caution."))

    logger.info(tr("Проверка зависимостей", "Checking dependencies"))
    missing = collect_missing_dependencies()
    if missing:
        logger.error(tr("Не найдены обязательные Python-пакеты:", "Missing required Python packages:"))
        for module_name, pip_name in missing:
            logger.error(tr_fmt(" - {module}: установите через pip install {pip}", " - {module}: install via pip install {pip}", module=module_name, pip=pip_name))
        logger.error(tr("Установите зависимости командой: pip install -r requirements.txt", "Install dependencies with: pip install -r requirements.txt"))
        raise SystemExit(1)

    if not shutil.which("wg"):
        logger.error(tr("Утилита wg не найдена. Установите wireguard-tools", 'Utility "wg" not found. Install wireguard-tools'))
        raise RuntimeError(tr("Утилита wg не найдена", 'Utility "wg" not found'))

    if not CONFIG_FILE.exists():
        logger.error(tr("Файл %s не найден", "File %s not found"), CONFIG_FILE)
        raise FileNotFoundError(CONFIG_FILE)

    apply_force_flag(args)

    if not VALIDATE_ONLY:
        ensure_dirs()
    else:
        logger.info(tr("Режим валидации: пропускаю создание каталога output.", "Validation mode: skipping output directory creation."))
    
    logger.info(tr("Загрузка конфигурации из %s", "Loading configuration from %s"), CONFIG_FILE)
    try:
        with CONFIG_FILE.open("r", encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.debug(f"Конфигурация: {config}")
    except FileNotFoundError:
        logger.error(tr("Файл %s не найден", "File %s not found"), CONFIG_FILE)
        raise
    except yaml.YAMLError as e:
        logger.error(tr_fmt("Ошибка парсинга YAML: {error}", "YAML parsing error: {error}", error=e))
        raise
    
    server_cfg = config.get('server')
    if not isinstance(server_cfg, dict):
        raise ValueError(tr_fmt("В {config} отсутствует блок server", "Block 'server' is missing in {config}", config=CONFIG_FILE))
    for field in ('endpoint', 'ipv4', 'ipv6'):
        if field not in server_cfg:
            raise ValueError(tr_fmt("В блоке server отсутствует параметр {field}", "Parameter {field} is missing in the server block", field=field))

    client_defaults = config.get('client_defaults', {})
    vanity_length = client_defaults.get('vanity_length', 0) or 0
    if vanity_length > 10:
        logger.error(tr("Длина vanity-префикса превышает 10 символов", "Vanity prefix length exceeds 10 characters"))
        raise ValueError(tr("Длина vanity-префикса не может превышать 10 символов", "Vanity prefix length must not exceed 10 characters"))
    if vanity_length > 0:
        if not shutil.which("wireguard-vanity-address"):
            logger.error(tr("Утилита wireguard-vanity-address не найдена, а vanity_length > 0. Установите: cargo install wireguard-vanity-address", "wireguard-vanity-address not found while vanity_length > 0. Install it via: cargo install wireguard-vanity-address"))
            raise RuntimeError(tr("Утилита wireguard-vanity-address не найдена", "Utility wireguard-vanity-address not found"))
    else:
        if not shutil.which("wireguard-vanity-address"):
            logger.info(tr("vanity_length=0 и wireguard-vanity-address недоступна — использую стандартные ключи", "vanity_length=0 and wireguard-vanity-address unavailable — using standard keys"))

    server_privkey = resolve_server_private_key(server_cfg)
    try:
        server_pubkey = subprocess.check_output(["wg", "pubkey"], input=server_privkey, text=True, encoding='utf-8').strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(tr_fmt("Не удалось получить публичный ключ сервера: {error}", "Failed to obtain the server public key: {error}", error=e.stderr)) from e

    # Совместимость с прежними именами ключей
    config['server_endpoint'] = server_cfg['endpoint']
    config['server_ipv4'] = server_cfg['ipv4']
    config['server_ipv6'] = server_cfg['ipv6']
    config['port'] = server_cfg.get('port')
    config['dns_ipv4'] = server_cfg.get('dns_ipv4', [])
    config['dns_ipv6'] = server_cfg.get('dns_ipv6', [])
    config['keepalive_on_server'] = server_cfg.get('keepalive_on_server', True)
    config['server_keepalive'] = server_cfg.get('keepalive')
    config['amneziawg_on_server'] = server_cfg.get('amneziawg_on_server', False)
    config['mtu'] = server_cfg.get('mtu')
    config['server_mtu_comment'] = server_cfg.get('mtu_comment')
    config['client_mtu_comment'] = client_defaults.get('mtu_comment') or server_cfg.get('mtu_comment')
    config['persistent_keepalive'] = client_defaults.get('persistent_keepalive', 25)
    config['_generate_qr'] = client_defaults.get('generate_qr', DEFAULT_GENERATE_QR)
    config['vanity_length'] = vanity_length
    config['amneziawg'] = config.get('amneziawg')
    config['_resolved_port'] = resolve_port_value(server_cfg)
    special_meta = load_special_packets(config)

    raw_psk = config.get('psk', {})
    psk_settings = parse_psk_settings(raw_psk)
    psk_mode = psk_settings['mode']
    psk_reuse = psk_settings.get('reuse', True)
    static_value = psk_settings.get('static_value')
    client_conf_count = count_existing_client_configs()
    has_clients = client_conf_count > 0
    restored_psk = None
    if has_clients:
        ask = tr_fmt("Найдено {count} клиентских конфигов в {clients_dir}. Разрешить прочитать их, чтобы переиспользовать текущие PSK?", "Found {count} client configs in {clients_dir}. Allow reading them to reuse PSK values?", count=client_conf_count, clients_dir=CLIENTS_DIR)
        if prompt_yes_no(ask, default=True, scope="psk_read"):
            restored_psk = extract_static_psk_from_clients()
            if not restored_psk:
                logger.warning(tr("Существующие конфиги обнаружены, но ни один не содержит PSK.", "Existing configs found, but none contain a PSK."))
        else:
            logger.info(tr("Пропускаю чтение %s по запросу пользователя.", "Skipping read of %s per user request."), CLIENTS_DIR)

    def persist_psk_mode(new_mode):
        require_config_write(
            "psk.mode требует изменения (запись запрещена в validate)",
            "psk.mode needs to be updated (writes are blocked in validate)",
        )
        if update_yaml_field(CONFIG_FILE, ["psk", "mode"], new_mode):
            logger.info(tr("psk.mode обновлён до '%s' в %s", "psk.mode updated to '%s' in %s"), new_mode, CONFIG_FILE)

    def persist_psk_value(new_value):
        require_config_write(
            "psk.value требует изменения (запись запрещена в validate)",
            "psk.value needs to be updated (writes are blocked in validate)",
        )
        if update_yaml_field(CONFIG_FILE, ["psk", "value"], f'"{new_value}"'):
            logger.info(tr("psk.value синхронизирован с %s", "psk.value synchronized with %s"), CONFIG_FILE)

    if psk_settings.get('force_mode_static'):
        logger.info(tr("Указан psk.value при режиме != static — переключаю на static", "psk.value provided while mode != static — switching to static"))
        psk_mode = 'static'
        psk_settings['mode'] = 'static'
        persist_psk_mode('static')

    def adopt_restored_psk():
        nonlocal psk_mode, static_value
        static_value = restored_psk
        psk_mode = 'static'
        psk_settings['mode'] = 'static'
        psk_settings['static_value'] = restored_psk
        persist_psk_mode('static')
        persist_psk_value(restored_psk)
        logger.info(tr("PSK восстановлен из существующих конфигов и записан в %s", "PSK restored from existing configs and written to %s"), CONFIG_FILE)

    if psk_mode == 'static' and not static_value:
        if restored_psk:
            ask = tr_fmt("psk.mode=static, но value пуст. Найден PSK в существующих клиентах. Перенести его в {config} и продолжить?", "psk.mode=static but value is empty. Found a PSK in existing clients. Copy it into {config} and continue?", config=CONFIG_FILE)
            if VALIDATE_ONLY:
                require_config_write(
                    "psk.value пуст, найден PSK в существующих клиентах",
                    "psk.value is empty but a PSK was found in existing clients",
                )
            if prompt_yes_no(ask, default=True, scope="psk"):
                adopt_restored_psk()
            else:
                raise ValueError(tr("psk.value обязателен. Добавьте значение вручную и перезапустите генерацию.", "psk.value is required. Enter it manually and rerun the generator."))
        elif has_clients:
            raise ValueError(tr("psk.mode=static без value: найдены существующие конфиги, но PSK не удалось извлечь. Укажите psk.value вручную, иначе старые клиенты перестанут работать.", "psk.mode=static without value: existing configs found but PSK extraction failed. Provide psk.value manually or older clients will stop working."))
        else:
            if ALLOW_CONFIG_WRITES:
                ask_generate_psk = tr("psk.mode=static, но value пуст. Сгенерировать общий PSK, записать его в конфиг и продолжить?", "psk.mode=static but value is empty. Generate a shared PSK, write it to the config, and continue?")
                if VALIDATE_ONLY:
                    require_config_write(
                        "psk.value пуст и требуется генерация общего PSK",
                        "psk.value is empty and a shared PSK must be generated",
                    )
                if prompt_yes_no(ask_generate_psk, default=True, scope="psk"):
                    generated_psk = generate_psk()
                    static_value = generated_psk
                    psk_mode = 'static'
                    psk_settings['mode'] = 'static'
                    psk_settings['static_value'] = generated_psk
                    persist_psk_mode('static')
                    persist_psk_value(generated_psk)
                    logger.info(tr("Сгенерирован общий PSK, записан в %s и режим переключен на static", "Generated a shared PSK, wrote it to %s, and switched mode to static"), CONFIG_FILE)
                else:
                    raise ValueError(tr("psk.value обязателен. Добавьте значение вручную и перезапустите генерацию.", "psk.value is required. Enter it manually and rerun the generator."))
            else:
                raise ValueError(tr("psk.mode=static требует заполненного value.", "psk.mode=static requires a populated value."))

    if psk_mode in ('generate', 'generate_per_client') and has_clients and psk_reuse:
        if restored_psk:
            message = tr_fmt("В каталоге {clients_dir} уже есть конфиги. Режим PSK — '{mode}'. Найден существующий PSK. Подтянуть его в {config} и продолжить без изменений у пользователей? (Ответьте 'n', если хотите принудительно сгенерировать новый ключ и выставите psk.reuse=false перед повторным запуском.)", "Configs already exist under {clients_dir}. PSK mode '{mode}' detected an existing PSK. Import it into {config} and continue without client-side changes? (Answer 'n' if you want to regenerate the key and set psk.reuse=false before rerunning.)", clients_dir=CLIENTS_DIR, mode=psk_mode, config=CONFIG_FILE)
            if VALIDATE_ONLY:
                require_config_write(
                    "найден существующий PSK, требуется синхронизировать psk.value",
                    "an existing PSK was found and psk.value must be synchronized",
                )
            if prompt_yes_no(message, default=True, scope="psk"):
                adopt_restored_psk()
            else:
                raise ValueError(tr("Операция отменена пользователем. Чтобы перегенерировать ключи, установите psk.reuse=false и подтвердите, что готовы обновить все клиентские конфиги.", "Operation canceled by user. Set psk.reuse=false and confirm you are ready to update all client configs to regenerate keys."))
        else:
            raise ValueError(tr_fmt("Найдены существующие клиенты, но PSK извлечь не удалось. Укажите psk.value или удалите каталоги {client_dir}/<name>, чтобы сгенерировать новый ключ.", "Existing clients found but PSK extraction failed. Provide psk.value or remove {client_dir}/<name> to generate a new key.", client_dir=CLIENTS_DIR))

    if psk_mode == 'generate':
        if has_clients and not psk_reuse:
            ask = tr("psk.mode=generate и psk.reuse=false: будут сгенерированы новые PSK, а все текущие клиенты станут недействительными. Продолжить?", "psk.mode=generate with psk.reuse=false will generate new PSKs and invalidate every existing client. Continue?")
            if VALIDATE_ONLY:
                require_config_write(
                    "psk.mode=generate и psk.reuse=false требует регенерации PSK",
                    "psk.mode=generate with psk.reuse=false requires regenerating PSKs",
                )
            if not prompt_yes_no(ask, default=False, scope="psk"):
                raise ValueError(tr("Генерация отменена пользователем.", "Generation canceled by user."))
        if VALIDATE_ONLY:
            require_config_write(
                "psk.mode=generate требует генерации и записи общего PSK",
                "psk.mode=generate requires generating and writing a shared PSK",
            )
        generated_psk = generate_psk()
        static_value = generated_psk
        psk_mode = 'static'
        psk_settings['mode'] = 'static'
        psk_settings['static_value'] = generated_psk
        persist_psk_mode('static')
        persist_psk_value(generated_psk)
        logger.info(tr("Сгенерирован общий PSK, записан в %s и режим переключен на static", "Generated a shared PSK, wrote it to %s, and switched mode to static"), CONFIG_FILE)
    elif psk_mode == 'generate_per_client':
        if has_clients and not psk_reuse:
            ask = tr("psk.mode=generate_per_client и psk.reuse=false: будут пересозданы все PSK. Продолжить?", "psk.mode=generate_per_client with psk.reuse=false will recreate every PSK. Continue?")
            if VALIDATE_ONLY:
                require_config_write(
                    "psk.mode=generate_per_client и psk.reuse=false требует пересоздания PSK",
                    "psk.mode=generate_per_client with psk.reuse=false requires recreating PSKs",
                )
            if not prompt_yes_no(ask, default=False, scope="psk"):
                raise ValueError(tr("Операция отменена пользователем.", "Operation canceled by user."))
        logger.info(tr("Генерация индивидуальных PSK для каждого клиента", "Generating individual PSKs for each client"))

    if psk_mode == 'static' and static_value:
        config['common_psk'] = static_value

    config['_psk_mode'] = psk_mode
    config['_psk_static_value'] = psk_settings.get('static_value')
    config['_psk_reuse'] = psk_reuse

    # Генерация PSK
    client_psks = {}
    psk_mode = config.get('_psk_mode', 'generate')
    static_psk = config.get('_psk_static_value')
    if psk_mode == 'generate_per_client':
        logger.info(tr("Генерация индивидуальных PSK для каждого клиента", "Generating individual PSKs for each client"))
    elif psk_mode == 'static' and static_psk:
        logger.info(tr("Используется статический PSK из конфигурации", "Using the static PSK from configuration"))
    
    subnets = []
    if SUBNETS_FILE.exists():
        subnets = read_subnets_csv(SUBNETS_FILE)
    else:
        logger.info(tr("Файл %s не найден, запрашиваю подсети вручную", "File %s not found; prompting for subnets manually"), SUBNETS_FILE)
        while True:
            name = input(tr("Введите название подсети (или 'done' для завершения): ", "Enter subnet name (or 'done' to finish): "))
            if name.lower() == 'done':
                break
            try:
                count = int(input(tr_fmt("Введите количество клиентов для {name}: ", "Enter the number of clients for {name}: ", name=name)))
                subnets.append({'name': name, 'clients': count})
                logger.info(tr_fmt("Добавлена подсеть: {name}, клиентов: {count}", "Added subnet {name} with {count} clients", name=name, count=count))
            except ValueError:
                logger.warning(tr("Неверное количество клиентов, попробуйте снова", "Invalid client count, try again"))
                print(tr("Неверное количество клиентов. Попробуйте снова.", "Invalid client count. Please try again."))
    
    if not subnets:
        logger.error(tr("Не задано ни одной подсети, завершаю выполнение", "No subnets defined; exiting"))
        raise ValueError(tr("Требуется хотя бы одна подсеть", "At least one subnet is required"))
    
    prompt_delete_missing_subnets([s['name'] for s in subnets])
    logger.info(tr("Сравнение CSV с существующими конфигами в %s", "Comparing CSV against existing configs in %s"), CLIENTS_DIR)
    csv_subnet_names = [s['name'] for s in subnets]
    existing_indices = discover_existing_subnet_indices(set(csv_subnet_names))
    subnet_indices = allocate_subnet_indices(subnets, existing_indices)
    total_subnets = len(subnets)
    for idx, subnet in enumerate(subnets, start=1):
        logger.info(tr("Обработка подсети %s (%d/%d)", "Processing subnet %s (%d/%d)"), subnet['name'], idx, total_subnets)
        subnet_dir = CLIENTS_DIR / subnet['name']
        subnet_idx = subnet_indices[subnet['name']]
        subnet['ipv4_base'] = f"10.0.{subnet_idx}."
        subnet['ipv6_base'] = f"fd00::{subnet_idx}"
        subnet['client_keys'] = []
        
        if subnet_dir.exists():
            conf_files = sorted([f for f in os.listdir(subnet_dir) if f.endswith('.conf')])
            current_clients = len(conf_files)
            if current_clients > subnet['clients']:
                response = input(tr_fmt("В подсети {name} в {root} больше конфигов ({current}) чем в CSV ({csv}). Скорректировать CSV? (y/n): ", "Subnet {name} in {root} has more configs ({current}) than the CSV ({csv}). Adjust the CSV? (y/n): ", name=subnet['name'], root=CLIENTS_DIR, current=current_clients, csv=subnet['clients']))
                if response.lower() == 'y':
                    print(tr_fmt("Скорректируйте {path} и запустите скрипт заново.", "Adjust {path} and rerun the script.", path=SUBNETS_FILE))
                    raise SystemExit(0)
                else:
                    logger.warning(tr_fmt("Продолжаем с CSV, но существующие конфиги в {path} останутся", "Continuing with CSV, but existing configs in {path} will remain", path=subnet_dir))
                    subnet['clients'] = current_clients
            
            for i in range(current_clients):
                conf_path = subnet_dir / f"{subnet['name']}_client{i+1}.conf"
                if conf_path.exists():
                    privkey, psk = parse_client_keys(conf_path)
                    pubkey = subprocess.check_output(["wg", "pubkey"], input=privkey, text=True, encoding='utf-8').strip()
                    psk_key = f"{subnet['name']}_client{i+1}"
                    if psk and psk_mode != 'generate_per_client':
                        client_psks[psk_key] = psk
                    elif psk_mode == 'generate_per_client':
                        client_psks[psk_key] = generate_psk()
                    subnet['client_keys'].append({'public': pubkey, 'private': privkey})
                    generate_client_config(config, subnet, i, privkey, pubkey, server_pubkey, client_psks.get(psk_key, config.get('common_psk')), special_meta)
                else:
                    logger.error(tr_fmt("Файл {path} не существует, хотя ожидался", "File {path} does not exist although it was expected", path=conf_path))
                    raise RuntimeError(tr_fmt("Файл {path} не существует", "File {path} does not exist", path=conf_path))
            
            for i in range(current_clients, subnet['clients']):
                prefix = subnet['name'][:config.get('vanity_length', 0)]
                pubkey, privkey = generate_vanity_key(prefix, i, config.get('vanity_length', 0))
                psk = generate_psk() if psk_mode == 'generate_per_client' else config.get('common_psk')
                psk_key = f"{subnet['name']}_client{i+1}"
                if psk:
                    client_psks[psk_key] = psk
                subnet['client_keys'].append({'public': pubkey, 'private': privkey})
                generate_client_config(config, subnet, i, privkey, pubkey, server_pubkey, psk, special_meta)
        else:
            if not VALIDATE_ONLY:
                subnet_dir.mkdir(parents=True, exist_ok=True)
            for i in range(subnet['clients']):
                prefix = subnet['name'][:config.get('vanity_length', 0)]
                pubkey, privkey = generate_vanity_key(prefix, i, config.get('vanity_length', 0))
                psk = generate_psk() if psk_mode == 'generate_per_client' else config.get('common_psk')
                psk_key = f"{subnet['name']}_client{i+1}"
                if psk:
                    client_psks[psk_key] = psk
                subnet['client_keys'].append({'public': pubkey, 'private': privkey})
                generate_client_config(config, subnet, i, privkey, pubkey, server_pubkey, psk, special_meta)
    
    config['_subnet_indices'] = subnet_indices
    generate_server_config(config, server_privkey, server_pubkey, client_psks, subnet_indices, special_meta)
    
    elapsed = time.time() - start_time
    if VALIDATE_ONLY:
        logger.info(tr("Конфигурация успешно проверена (--validate). Файлы не изменялись.", "Configuration validated (--validate). No files were modified."))
        logger.info(tr_fmt("Проверка завершена за {seconds:.2f} сек", "Validation finished in {seconds:.2f} s", seconds=elapsed))
        return
    
    # RU: Управление .gitignore перенесено в репозиторий; не перезаписываем его из скрипта
    # EN: .gitignore is managed in the repo; do not overwrite it from the script
    logger.info(tr_fmt("Генерация завершена за {seconds:.2f} сек", "Generation finished in {seconds:.2f} s", seconds=elapsed))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error(tr("Программа прервана пользователем (Ctrl+C)", "Execution interrupted by user (Ctrl+C)"))
        raise SystemExit(1)
    except Exception as e:
        logger.error(tr_fmt("Критическая ошибка: {error}", "Critical error: {error}", error=e))
        raise







