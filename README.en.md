# wg-atelier

[Русская версия 🇷🇺](README.md)

## Purpose

**wg-atelier** hosts the `generate_wg_configs.py` utility, which builds complete WireGuard configurations from `wg_config.yaml`, `subnets.csv`, and any existing client profiles. It reuses private keys, manages PSK handling, and outputs both the server config (`server/wg0.conf`) and per-client profiles/QR codes.

## Features

- parses server parameters and AmneziaWG settings from YAML;
- compares CSV with `clients/<subnet>/` contents and asks for confirmation when something changes;
- generates server & client configs plus QR codes;
- logs to `wg-atelier.log` and creates `wg_config.yaml.<timestamp>.bak` before writing secrets back to YAML;
- interactive PSK workflow (restoring existing values, asking before regeneration);
- `--validate` mode for dry runs without touching the filesystem.

## Requirements

### CLI tools
- `wg` (`wireguard-tools`) for key generation and public-key export.
- `wireguard-vanity-address` only when `vanity_length > 0`.
- Runs on Python 3.10\+ (Windows only). 

### Python
- Python 3.10+.
- Install dependencies from `requirements.txt` via `pip install -r requirements.txt`.

## Inputs

### `wg_config.yaml`
- `server` block: `endpoint`, `ipv4`, `ipv6`, `private_key`, optional `port`, `dns_ipv4`/`dns_ipv6`, `keepalive_on_server`, `amneziawg_on_server`, `mtu`, `mtu_comment`.
- `client_defaults`: `persistent_keepalive`, `vanity_length`, `mtu_comment` (defaults to the server template).
- `psk`: `mode` (`generate`/`generate_per_client`/`static`), `value` for static mode, `reuse` to pull values from existing configs.
- `amneziawg`: JunkPacket/RandomData/Handshake/Transport parameters.

### `subnets.csv`
- Format `prefix;num_clients` (see `subnets.example.csv`).
- Row order defines the order of subnets in the resulting configs.

### Existing clients
- `clients/<prefix>/<prefix>_clientN.conf` are treated as the source of private keys/PSK.
- When a CSV row is removed, the script offers to delete the corresponding directory.

## Usage

1. Prepare `wg_config.yaml` and `subnets.csv`; clean up unused directories in `clients/` if needed.
2. Install dependencies (`pip install -r requirements.txt`) and ensure `wg`/`wireguard-vanity-address` are on PATH.
3. Run the generator:
   ```
   python generate_wg_configs.py -c config/wg_config.yaml -s data/subnets.csv -o ./artifacts
   ```
   Dry run without writing files: `python generate_wg_configs.py --validate`.
4. Follow the prompts (confirm deletions, PSK reuse, reading existing client configs).

| Flag | Description |
| --- | --- |
| `-c/--config` | Path to `wg_config.yaml` |
| `-s/--subnets` | Path to `subnets.csv` |
| `-o/--output-root` | Directory where `server/` and `clients/` will be written |
| `--validate` | Check configuration without writing files |

> `WG_CONFIG_GEN_ASSUME_YES=1` disables all confirmations. Use only in fully controlled environments.

## PSK, AmneziaWG, keepalive

- `psk: generate` creates a single shared PSK and automatically switches the mode to `static`.
- `psk: generate_per_client` issues unique PSK values per client.
- `psk: static` + `value` uses a predefined Base64 string (32 bytes). If the value is missing, the script can recover it from existing configs.
- `psk.reuse=true` reuses discovered PSK values; `false` forces you to explicitly acknowledge regeneration.
- `amneziawg_on_server` + `amneziawg` block add hints to both server and client configs.
- `persistent_keepalive` is always written for clients; if `keepalive_on_server=true`, the same value is added to the server config.

## Vanity keys

- Uses `name[:vanity_length]` as a prefix.
- Falls back to standard `wg genkey` when `vanity_length=0` or when the vanity CLI is missing.
- Maximum prefix length is 10 characters (validated in code).

## Logs & diagnostics

- Main log: `wg-atelier.log`.
- Ctrl+C is caught and logged.
- Run `python -m py_compile generate_wg_configs.py` and `python generate_wg_configs.py --validate` before publishing to catch obvious issues.

## Security

- Keep private keys/configs local: the script sets `0600` permissions (or the Windows equivalent via `icacls`), but you should still restrict access to the folders.
- `wg_config.yaml.<timestamp>.bak` files are ignored by Git; store or delete them manually.
- Run `gitleaks detect --source . --redact` before publishing.
- Avoid `WG_CONFIG_GEN_ASSUME_YES` in untrusted environments—automatic confirmation may overwrite keys/PSK.
