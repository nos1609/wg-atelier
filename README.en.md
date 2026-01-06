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
- For editor validation/autocomplete, you can add this line at the top: `# yaml-language-server: $schema=./schemas/wg_config.schema.json`.
- `server` block: `endpoint`, `ipv4`, `ipv6`, `private_key`, optional `port`, `dns_ipv4`/`dns_ipv6`, `keepalive_on_server`, `amneziawg_on_server`, `mtu`, `mtu_comment`.
- `client_defaults`: `persistent_keepalive`, `vanity_length`, `mtu_comment` (defaults to the server template).
- `psk`: `mode` (`generate`/`generate_per_client`/`static`), `value` for static mode, `reuse` to pull values from existing configs.
- `amneziawg`: JunkPacket/RandomData/Handshake/Transport parameters.
- `amneziawg_special_packets`: optional I1..I5 (Custom Protocol Signature) insertion from a JSON file (defaults to `./amnezia-I-list.json`; keep it local and don’t commit it).
  - Manual I1..I5 may be defined directly inside `amneziawg`; repo is skipped then.
  - The repo only ships a template `amnezia-I-list.example.json`: copy it to your local `amnezia-I-list.json` and (if needed) point `amneziawg_special_packets.file` to it. The path is resolved relative to `wg_config.yaml`.
  - `enabled` (`null` = auto, `false` = off even with manual I-fields), `file`, `cycle`, `random_cycle`, `cycles_pool`, `mode`, `reuse_within_client`.
  - `mode`: `global` (one set for all), `per_client_random` (random per client), `per_subnet_unique` (tries to keep unique within a subnet).
  - Default is per-client random cycle (`mode=per_client_random`); set `mode=global` to use one set for everyone.
  - If existing configs already contain I1..I5 but a new run does not generate them (for example, `amneziawg_special_packets` is disabled or the file is missing), the script asks to confirm removal and offers to keep the current values.
  - QR is skipped when I-fields are present; you can disable QR entirely via `client_defaults.generate_qr=false`.

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
| `--force` | Rewrite `server/`/`clients/` and QR even if unchanged (with confirmation; ignored under `--validate`) |

> Important: if you set `-o/--output-root` to a directory that isn’t ignored by Git, you’ll end up with untracked files containing private keys. Either don’t use `-o` (default `server/` and `clients/` are already in `.gitignore`), or add `<output-root>/server` and `<output-root>/clients` to your local ignore rules.

> `WG_CONFIG_GEN_ASSUME_YES=1` disables all confirmations. Use only in fully controlled environments.

## PSK, AmneziaWG, keepalive

- `psk: generate` creates a single shared PSK and automatically switches the mode to `static`.
- `psk: generate_per_client` issues unique PSK values per client.
- `psk: static` + `value` uses a predefined Base64 string (32 bytes). If the value is missing, the script can recover it from existing configs.
- `psk.reuse=true` reuses discovered PSK values; `false` forces you to explicitly acknowledge regeneration.
- `amneziawg_on_server` + `amneziawg` block add hints to both server and client configs.
- `persistent_keepalive` is always written for clients; if `keepalive_on_server=true`, the same value is added to the server config.

## Netcraze/Keenetic: import .conf + ASC

Netcraze (formerly Keenetic) does not support I1..I5. Starting with firmware 5.0.2 ASC is applied automatically on `.conf` import; on older firmware manually set it via Web CLI/SSH (`wireguard asc ...`).

Step-by-step:
1. In the web UI: Internet → Other connections / WireGuard → “Import from file” → upload the client `.conf`.
2. Open Web CLI: replace `.../dashboard` with `.../a` (e.g., `https://<router>/a`). If SSH/Telnet is available, prefer it.
3. Note the connection name (from UI or filename, e.g., `anos_client3`).
4. In Web CLI run, in order:
   - `show interface` — view connections and exact names.
   - `interface <NAME>` — enter that connection context.
   - `wireguard asc <Jc> <Jmin> <Jmax> <S1> <S2> <H1> <H2> <H3> <H4>` — apply ASC from your `wg_config.yaml`.
   - `show running-config` — ensure the `[interface <NAME>]` block contains `wireguard asc ...`.
   - `system configuration save` — persist changes so they survive reboot.
   Default (WireGuard-compatible): `wireguard asc 0 0 0 0 0 1 2 3 4`.
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

## Legal

- This project is intended for administering WireGuard/AmneziaWG within networks you own or are explicitly authorized to manage (home, organization, lab).
- Use it only where permitted by applicable law, your ISP terms, and your organization’s policies.




