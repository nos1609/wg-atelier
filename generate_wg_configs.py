import argparse
import os
import subprocess
import yaml
import csv
import qrcode
import logging
import time
import random
import base64
from datetime import datetime
from pathlib import Path
import shutil
import re
import signal

YAML_BACKUPS_CREATED = set()
ASSUME_YES = os.environ.get("WG_CONFIG_GEN_ASSUME_YES") == "1"
CONFIG_FILE = Path("wg_config.yaml")
SUBNETS_FILE = Path("subnets.csv")
OUTPUT_ROOT = Path(".")
SERVER_DIR = OUTPUT_ROOT / "server"
CLIENTS_DIR = OUTPUT_ROOT / "clients"
SERVER_CONF_PATH = SERVER_DIR / "wg0.conf"
VALIDATE_ONLY = False
ALLOW_CONFIG_WRITES = True

# RU: Обработка Ctrl+C
# EN: Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    logger.error("Получено прерывание (Ctrl+C), завершаю выполнение")
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
    logger.info("Генерация Pre-Shared Key")
    psk = subprocess.check_output(["wg", "genpsk"], text=True, encoding='utf-8').strip()
    logger.debug(f"Сгенерирован PSK: {psk}")
    return psk

# RU: Запрос подтверждения у пользователя
# EN: Simple Y/N confirmation helper
def prompt_yes_no(message, default=True):
    if ASSUME_YES:
        logger.info(f"WG_CONFIG_GEN_ASSUME_YES=1, автоматически выбираю {'Yes' if default else 'No'} для: {message}")
        return default
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        response = input(f"{message} {suffix}: ").strip().lower()
        if not response:
            return default
        if response in ("y", "yes", "д", "да"):
            return True
        if response in ("n", "no", "н", "нет"):
            return False
        print("Ответьте 'y' или 'n'.")

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
            raise ValueError(f"PrivateKey не найден в {conf_path}")
        return privkey, psk
    except Exception as e:
        logger.error(f"Ошибка парсинга {conf_path}: {e}")
        raise

# RU: Извлечение приватного ключа сервера из server/wg0.conf
# EN: Extract server PrivateKey from server/wg0.conf
def extract_server_private_key_from_server_conf(conf_path=None):
    path = Path(conf_path) if conf_path else SERVER_CONF_PATH
    if not path.exists():
        logger.warning(f"Файл {conf_path} не найден при попытке восстановить приватный ключ сервера")
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
        logger.error(f"Не удалось извлечь приватный ключ сервера из {conf_path}: {e}")
    return None

# RU: Создание директорий для конфигов
# EN: Ensure server/ and clients/ directories exist
def ensure_dirs():
    if VALIDATE_ONLY:
        logger.debug("Режим валидации: директории server/clients не создаются")
        return
    logger.info("Создание директорий для конфигураций")
    SERVER_DIR.mkdir(parents=True, exist_ok=True)
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    logger.debug("Директории %s и %s готовы", SERVER_DIR, CLIENTS_DIR)

# RU: Генерация стандартного ключа WireGuard
# EN: Generate a standard WireGuard key pair
def generate_standard_key():
    logger.info("Генерация стандартного ключа WireGuard")
    if not shutil.which("wg"):
        logger.error("Утилита wg не найдена. Установите wireguard-tools")
        raise RuntimeError("Утилита wg не найдена")
    try:
        privkey = subprocess.check_output(["wg", "genkey"], text=True, encoding='utf-8').strip()
        pubkey = subprocess.check_output(["wg", "pubkey"], input=privkey, text=True, encoding='utf-8').strip()
        logger.debug(f"Сгенерированы стандартные ключи: public={pubkey}, private={privkey}")
        return pubkey, privkey
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка генерации стандартного ключа WireGuard: {e.stderr}")
        raise RuntimeError(f"Ошибка генерации стандартного ключа: {e.stderr}")

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
            logger.warning(f"Неизвестный режим PSK '{mode}', использую 'generate'")
            mode = "generate"
        if settings["static_value"] and mode != "static":
            settings["force_mode_static"] = True
            mode = "static"
        settings["mode"] = mode
        if settings["mode"] == "static" and not settings["static_value"]:
            raise ValueError("psk.mode=static требует непустого поля value")
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
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup_name = f"{path.name}.{timestamp}.bak"
    backup_path = path.with_name(backup_name)
    shutil.copy2(path, backup_path)
    YAML_BACKUPS_CREATED.add(resolved)
    logger.info(f"Создана резервная копия {backup_name} перед изменением {path.name}")


def update_yaml_field(file_path, field_path, new_value):
    if not ALLOW_CONFIG_WRITES:
        logger.info("Режим валидации: пропускаю обновление %s", ".".join(field_path))
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
        logger.warning(f"Не удалось автоматически обновить {'.'.join(field_path)} в {file_path} — добавьте значение вручную.")
        return False
    maybe_backup_yaml(path)
    path.write_text(pattern.sub(replacement, content, count=1), encoding="utf-8")
    return True


def maybe_backup_yaml(path: Path):
    if not ALLOW_CONFIG_WRITES:
        return
    resolved = path.resolve()
    if resolved in YAML_BACKUPS_CREATED:
        return
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup_name = f"{path.name}.{timestamp}.bak"
    backup_path = path.with_name(backup_name)
    shutil.copy2(path, backup_path)
    YAML_BACKUPS_CREATED.add(resolved)
    logger.info(f"Создана резервная копия {backup_name} перед изменением {path.name}")


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
    return parser.parse_args()

def resolve_server_private_key(server_cfg):
    key = server_cfg.get("private_key")
    if key:
        return key.strip()
    if SERVER_CONF_PATH.exists():
        logger.warning("server.private_key отсутствует в %s. Найден файл %s с ключом.", CONFIG_FILE, SERVER_CONF_PATH)
        if prompt_yes_no(f"Разрешить прочитать {SERVER_CONF_PATH}, чтобы перенести приватный ключ в {CONFIG_FILE}?",
                         default=True):
            legacy_key = extract_server_private_key_from_server_conf(SERVER_CONF_PATH)
            if not legacy_key:
                raise ValueError(f"Не удалось извлечь приватный ключ из {SERVER_CONF_PATH}. Добавьте значение вручную.")
            if update_yaml_field(CONFIG_FILE, ["server", "private_key"], legacy_key):
                logger.info("server.private_key автоматически записан в %s", CONFIG_FILE)
            else:
                logger.warning("Не удалось перезаписать server.private_key — добавьте значение вручную.")
            return legacy_key
        raise ValueError("Продолжение без server.private_key запрещено. Добавьте значение вручную и повторите запуск.")
    raise ValueError(f"Не указан server.private_key и не найден {SERVER_CONF_PATH} с действующим ключом.")

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
            logger.warning("Подсеть %s отсутствует в %s (режим валидации, удаление пропущено)", name, SUBNETS_FILE)
            continue
        prompt = input(f"Подсеть {name} отсутствует в {SUBNETS_FILE}. Удалить {root / name}? (y/n): ")
        if prompt.lower().startswith("y"):
            shutil.rmtree(root / name)
            logger.info(f"Удалены конфиги {root / name}/")
        else:
            logger.warning(f"Подсеть {name} осталась в {root}, но не попадёт в новые конфиги.")
# RU: Генерация пары ключей с красивым публичным ключом
# EN: Generate a key pair with a vanity public key prefix
def generate_vanity_key(prefix, client_idx, vanity_length):
    logger.info(f"Генерация ключа для клиента {client_idx+1} с префиксом {prefix} (длина {vanity_length})")
    start_time = time.time()
    
    if not is_valid_prefix(prefix) or vanity_length == 0:
        logger.warning(f"Невалидный префикс {prefix} или vanity_length=0, использую стандартный ключ")
        return generate_standard_key()
    
    if not shutil.which("wireguard-vanity-address"):
        logger.warning("Утилита wireguard-vanity-address не найдена, использую стандартный ключ")
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
                logger.error(f"Ошибка декодирования вывода wireguard-vanity-address: {e}")
                raise RuntimeError(f"Ошибка декодирования вывода: {e}")
        
        try:
            stdout, stderr = process.communicate(timeout=1)
            logger.debug(f"Вывод wireguard-vanity-address для префикса {prefix}:\n{stdout}\nОшибки: {stderr}")
        except subprocess.TimeoutExpired:
            process.kill()
            logger.warning(f"Процесс для префикса {prefix} не завершился, принудительно остановлен")
        
        if pubkey and privkey:
            logger.info(f"Ключи для префикса {prefix} сгенерированы за {time.time() - start_time:.2f} сек")
            return pubkey, privkey
        
        logger.warning(f"Ключи не найдены в выводе для префикса {prefix}, использую стандартный ключ")
        return generate_standard_key()
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка вызова wireguard-vanity-address для префикса {prefix}: {e.stderr}")
        raise RuntimeError(f"Ошибка генерации ключа для префикса {prefix}: {e.stderr}")
    except Exception as e:
        logger.error(f"Неожиданная ошибка при генерации ключа для префикса {prefix}: {e}")
        raise RuntimeError(f"Неожиданная ошибка: {e}")

# RU: Генерация серверного конфига для NetworkManager
# EN: Build the server configuration (wg0.conf)
def generate_server_config(config, server_privkey, server_pubkey, client_psks, subnet_indices):
    logger.info("Генерация серверного конфига wg0.conf")
    port = config.get('port', random.randint(1024, 65535))
    if 'port' not in config:
        logger.info(f"Порт не указан, выбран случайный порт: {port}")
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
                logger.warning("Неверное имя файла %s, пропускаю", conf_file)
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
            if config.get('keepalive_on_server', False) and 'persistent_keepalive' in config:
                server_conf += f"PersistentKeepalive = {config['persistent_keepalive']}\n"
            server_conf += "\n"
    
    if VALIDATE_ONLY:
        logger.info("Режим валидации: серверный конфиг не записан.")
        return server_conf

    with SERVER_CONF_PATH.open("w", encoding='utf-8', newline='\n') as f:
        f.write(server_conf)
    set_secure_permissions(SERVER_CONF_PATH)
    logger.info("Серверный конфиг сохранён в %s", SERVER_CONF_PATH)
    return server_conf

# RU: Генерация клиентского конфига с поддержкой AmneziaWG
# EN: Build client configs with optional AmneziaWG hints
def generate_client_config(config, subnet, client_idx, client_privkey, client_pubkey, server_pubkey, psk=None):
    client_name = f"{subnet['name']}_client{client_idx+1}"
    logger.info(f"Генерация конфига для клиента {client_name}")
    client_ipv4 = f"{subnet['ipv4_base']}{client_idx+1}/32"
    client_ipv6 = f"{subnet['ipv6_base']}:{client_idx+1}/128"
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
    
    client_conf += f"""
[Peer]
PublicKey = {server_pubkey}
Endpoint = {config['server_endpoint']}:{config.get('port', random.randint(1024, 65535))}
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
    
    subnet_dir = CLIENTS_DIR / subnet['name']
    if VALIDATE_ONLY:
        return
    subnet_dir.mkdir(parents=True, exist_ok=True)
    conf_path = subnet_dir / f"{client_name}.conf"
    with conf_path.open("w", encoding='utf-8', newline='\n') as f:
        f.write(client_conf)
    set_secure_permissions(conf_path)
    logger.info("Конфиг клиента сохранён в %s", conf_path)
    
    logger.debug("Генерация QR-кода для %s", client_name)
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(client_conf)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save(subnet_dir / f"{client_name}.qr.png")
    logger.info("QR-код сохранён в %s", subnet_dir / f"{client_name}.qr.png")

# RU: Чтение подсетей из CSV
# EN: Read subnet definitions from CSV
def read_subnets_csv(csv_file):
    logger.info(f"Чтение подсетей из {csv_file}")
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
                        logger.warning(f"Пропущена строка с некорректным числом клиентов: {row}")
                        continue
        if not subnets:
            logger.warning("В файле CSV нет валидных строк с подсетями")
        else:
            logger.info(f"Успешно прочитано {len(subnets)} подсетей из CSV")
        return subnets
    except FileNotFoundError:
        logger.error(f"Файл {csv_file} не найден")
        raise
    except Exception as e:
        logger.error(f"Ошибка обработки CSV: {e}")
        raise

# RU: Основная функция
# EN: Entry point
def main():
    args = parse_cli_args()
    configure_paths(args)
    logger.info("Запуск генератора конфигураций WireGuard")
    start_time = time.time()
    if ASSUME_YES:
        logger.warning("WG_CONFIG_GEN_ASSUME_YES=1: все запросы подтверждаются автоматически. Используйте осторожно.")
    
    logger.info("Проверка зависимостей")
    try:
        import yaml
        import qrcode
        import PIL
    except ImportError as e:
        logger.error(f"Отсутствует Python-модуль: {e}")
        raise RuntimeError(f"Установите зависимости: pip3 install -r requirements.txt")
    
    if not shutil.which("wg"):
        logger.error("Утилита wg не найдена. Установите wireguard-tools")
        raise RuntimeError("Утилита wg не найдена")
    
    if not VALIDATE_ONLY:
        ensure_dirs()
    else:
        logger.info("Режим валидации: пропускаю создание каталога output.")
    
    logger.info("Загрузка конфигурации из %s", CONFIG_FILE)
    try:
        with CONFIG_FILE.open("r", encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.debug(f"Конфигурация: {config}")
    except FileNotFoundError:
        logger.error("Файл %s не найден", CONFIG_FILE)
        raise
    except yaml.YAMLError as e:
        logger.error(f"Ошибка парсинга YAML: {e}")
        raise
    
    server_cfg = config.get('server')
    if not isinstance(server_cfg, dict):
        raise ValueError(f"В {CONFIG_FILE} отсутствует блок server")
    for field in ('endpoint', 'ipv4', 'ipv6'):
        if field not in server_cfg:
            raise ValueError(f"В блоке server отсутствует параметр {field}")

    client_defaults = config.get('client_defaults', {})
    vanity_length = client_defaults.get('vanity_length', 0) or 0
    if vanity_length > 0:
        if not shutil.which("wireguard-vanity-address"):
            logger.error("Утилита wireguard-vanity-address не найдена, а vanity_length > 0. Установите: cargo install wireguard-vanity-address")
            raise RuntimeError("Утилита wireguard-vanity-address не найдена")
    else:
        if not shutil.which("wireguard-vanity-address"):
            logger.info("vanity_length=0 и wireguard-vanity-address недоступна — использую стандартные ключи")
    if vanity_length > 10:
        logger.error("Длина vanity-префикса превышает 10 символов")
        raise ValueError("Длина vanity-префикса не может превышать 10 символов")

    server_privkey = resolve_server_private_key(server_cfg)
    try:
        server_pubkey = subprocess.check_output(["wg", "pubkey"], input=server_privkey, text=True, encoding='utf-8').strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Не удалось получить публичный ключ сервера: {e.stderr}") from e

    # Совместимость с прежними именами ключей
    config['server_endpoint'] = server_cfg['endpoint']
    config['server_ipv4'] = server_cfg['ipv4']
    config['server_ipv6'] = server_cfg['ipv6']
    config['port'] = server_cfg.get('port')
    config['dns_ipv4'] = server_cfg.get('dns_ipv4', [])
    config['dns_ipv6'] = server_cfg.get('dns_ipv6', [])
    config['keepalive_on_server'] = server_cfg.get('keepalive_on_server', False)
    config['amneziawg_on_server'] = server_cfg.get('amneziawg_on_server', False)
    config['mtu'] = server_cfg.get('mtu')
    config['server_mtu_comment'] = server_cfg.get('mtu_comment')
    config['client_mtu_comment'] = client_defaults.get('mtu_comment') or server_cfg.get('mtu_comment')
    config['persistent_keepalive'] = client_defaults.get('persistent_keepalive', 25)
    config['vanity_length'] = vanity_length
    config['amneziawg'] = config.get('amneziawg')

    raw_psk = config.get('psk', {})
    psk_settings = parse_psk_settings(raw_psk)
    psk_mode = psk_settings['mode']
    psk_reuse = psk_settings.get('reuse', True)
    static_value = psk_settings.get('static_value')
    client_conf_count = count_existing_client_configs()
    has_clients = client_conf_count > 0
    restored_psk = None
    if has_clients:
        if prompt_yes_no(f"Найдено {client_conf_count} клиентских конфигов в {CLIENTS_DIR}. "
                         "Разрешить прочитать их, чтобы переиспользовать текущие PSK?", default=True):
            restored_psk = extract_static_psk_from_clients()
            if not restored_psk:
                logger.warning("Существующие конфиги обнаружены, но ни один не содержит PSK.")
        else:
            logger.info("Пропускаю чтение %s по запросу пользователя.", CLIENTS_DIR)

    def persist_psk_mode(new_mode):
        if update_yaml_field(CONFIG_FILE, ["psk", "mode"], new_mode):
            logger.info("psk.mode обновлён до '%s' в %s", new_mode, CONFIG_FILE)

    def persist_psk_value(new_value):
        if update_yaml_field(CONFIG_FILE, ["psk", "value"], f"\"{new_value}\""):
            logger.info("psk.value синхронизирован с %s", CONFIG_FILE)

    if psk_settings.get('force_mode_static'):
        logger.info("Указан psk.value при режиме != static — переключаю на static")
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
        logger.info("PSK восстановлен из существующих конфигов и записан в %s", CONFIG_FILE)

    if psk_mode == 'static' and not static_value:
        if restored_psk:
            if prompt_yes_no("psk.mode=static, но value пуст. Найден PSK в существующих клиентах. "
                             f"Перенести его в {CONFIG_FILE} и продолжить?", default=True):
                adopt_restored_psk()
            else:
                raise ValueError("psk.value обязателен. Добавьте значение вручную и перезапустите генерацию.")
        elif has_clients:
            raise ValueError("psk.mode=static без value: найдены существующие конфиги, но PSK не удалось извлечь. "
                             "Укажите psk.value вручную, иначе старые клиенты перестанут работать.")
        else:
            raise ValueError("psk.mode=static требует заполненного value.")

    if psk_mode in ('generate', 'generate_per_client') and has_clients and psk_reuse:
        if restored_psk:
            message = (f"В каталоге {CLIENTS_DIR} уже есть конфиги. Режим PSK установлен на "
                       f"'{psk_mode}'. Найден существующий PSK. Подтянуть его в {CONFIG_FILE} и продолжить "
                       "без изменений у пользователей? (Ответьте 'n', если хотите принудительно сгенерировать новый ключ "
                       "и выставите psk.reuse=false перед повторным запуском.)")
            if prompt_yes_no(message, default=True):
                adopt_restored_psk()
            else:
                raise ValueError("Операция отменена пользователем. Чтобы перегенерировать ключи, установите psk.reuse=false "
                                 "и подтвердите, что готовы обновить все клиентские конфиги.")
        else:
            raise ValueError(f"Найдены существующие клиенты, но PSK извлечь не удалось. "
                             f"Укажите psk.value или удалите каталоги {CLIENTS_DIR}/<name>, чтобы сгенерировать новый ключ.")

    if psk_mode == 'generate':
        if has_clients and not psk_reuse:
            if not prompt_yes_no("psk.mode=generate и psk.reuse=false: будут сгенерированы новые PSK, "
                                 "а все текущие клиенты станут недействительными. Продолжить?", default=False):
                raise ValueError("Генерация отменена пользователем.")
        generated_psk = generate_psk()
        static_value = generated_psk
        psk_mode = 'static'
        psk_settings['mode'] = 'static'
        psk_settings['static_value'] = generated_psk
        persist_psk_mode('static')
        persist_psk_value(generated_psk)
        logger.info("Сгенерирован общий PSK, записан в %s и режим переключен на static", CONFIG_FILE)
    elif psk_mode == 'generate_per_client':
        if has_clients and not psk_reuse:
            if not prompt_yes_no("psk.mode=generate_per_client и psk.reuse=false: будут пересозданы все PSK. Продолжить?", default=False):
                raise ValueError("Операция отменена пользователем.")
        logger.info("Генерация индивидуальных PSK для каждого клиента")

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
        logger.info("Генерация индивидуальных PSK для каждого клиента")
    elif psk_mode == 'static' and static_psk:
        logger.info("Используется статический PSK из конфигурации")
    
    subnets = []
    if SUBNETS_FILE.exists():
        subnets = read_subnets_csv(SUBNETS_FILE)
    else:
        logger.info("Файл %s не найден, запрашиваю подсети вручную", SUBNETS_FILE)
        while True:
            name = input("Введите название подсети (или 'done' для завершения): ")
            if name.lower() == 'done':
                break
            try:
                count = int(input(f"Введите количество клиентов для {name}: "))
                subnets.append({'name': name, 'clients': count})
                logger.info(f"Добавлена подсеть: {name}, клиентов: {count}")
            except ValueError:
                logger.warning("Неверное количество клиентов, попробуйте снова")
                print("Неверное количество клиентов. Попробуйте снова.")
    
    if not subnets:
        logger.error("Не задано ни одной подсети, завершаю выполнение")
        raise ValueError("Требуется хотя бы одна подсеть")
    
    prompt_delete_missing_subnets([s['name'] for s in subnets])
    logger.info("Сравнение CSV с существующими конфигами в %s", CLIENTS_DIR)
    subnet_indices = {}
    total_subnets = len(subnets)
    for idx, subnet in enumerate(subnets, start=1):
        logger.info("Обработка подсети %s (%d/%d)", subnet['name'], idx, total_subnets)
        subnet_indices[subnet['name']] = idx
        subnet_dir = CLIENTS_DIR / subnet['name']
        subnet_idx = subnet_indices[subnet['name']]
        subnet['ipv4_base'] = f"10.0.{subnet_idx}."
        subnet['ipv6_base'] = f"fd00::{subnet_idx}"
        subnet['client_keys'] = []
        
        if subnet_dir.exists():
            conf_files = sorted([f for f in os.listdir(subnet_dir) if f.endswith('.conf')])
            current_clients = len(conf_files)
            if current_clients > subnet['clients']:
                response = input(f"В подсети {subnet['name']} в {CLIENTS_DIR} больше конфигов ({current_clients}) чем в CSV ({subnet['clients']}). Скорректировать CSV? (y/n): ")
                if response.lower() == 'y':
                    print(f"Скорректируйте {SUBNETS_FILE} и запустите скрипт заново.")
                    raise SystemExit(0)
                else:
                    logger.warning(f"Продолжаем с CSV, но существующие конфиги в {subnet_dir} останутся")
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
                    generate_client_config(config, subnet, i, privkey, pubkey, server_pubkey, client_psks.get(psk_key, config.get('common_psk')))
                else:
                    logger.error(f"Файл {conf_path} не существует, хотя ожидался")
                    raise RuntimeError(f"Файл {conf_path} не существует")
            
            for i in range(current_clients, subnet['clients']):
                prefix = subnet['name'][:config.get('vanity_length', 0)]
                pubkey, privkey = generate_vanity_key(prefix, i, config.get('vanity_length', 0))
                psk = generate_psk() if psk_mode == 'generate_per_client' else config.get('common_psk')
                psk_key = f"{subnet['name']}_client{i+1}"
                if psk:
                    client_psks[psk_key] = psk
                subnet['client_keys'].append({'public': pubkey, 'private': privkey})
                generate_client_config(config, subnet, i, privkey, pubkey, server_pubkey, psk)
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
                generate_client_config(config, subnet, i, privkey, pubkey, server_pubkey, psk)
    
    config['_subnet_indices'] = subnet_indices
    generate_server_config(config, server_privkey, server_pubkey, client_psks, subnet_indices)
    
    elapsed = time.time() - start_time
    if VALIDATE_ONLY:
        logger.info("Конфигурация успешно проверена (--validate). Файлы не изменялись.")
        logger.info(f"Проверка завершена за {elapsed:.2f} сек")
        return
    
    # RU: Управление .gitignore перенесено в репозиторий; не перезаписываем его из скрипта
    # EN: .gitignore is managed in the repo; do not overwrite it from the script
    logger.info(f"Генерация завершена за {elapsed:.2f} сек")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.error("Программа прервана пользователем (Ctrl+C)")
        raise SystemExit(1)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        raise

