#!/usr/bin/env python3
"""
2_create_vpn_certs.py — управление VPN-сертификатами и CSO в OPNsense.

Режимы запуска (меню при старте):
  1. Создать сертификаты и CSO из CSV
  2. Скачать .ovpn файлы для пользователей из CSV

Формат CSV (разделитель ;):
  login;ip;email
  ivanov.ivan;10.8.0.1/32;ivanov@company.ru
  petrov.petr;10.8.0.2/32;

Переменные окружения (опционально):
  OPNSENSE_API_KEY    — API Key
  OPNSENSE_API_SECRET — API Secret
  OPNSENSE_BASE_URL   — по умолчанию https://127.0.0.1 (запуск на сервере)
  OPNSENSE_CA         — descr или refid CA для подписания (для --yes режима)

Запуск:
  python3 2_create_vpn_certs.py users.csv
  python3 2_create_vpn_certs.py --yes --ca VPN-Lab-CA users.csv
"""

import sys
import os
import csv
import ssl
import json
import base64
import urllib.request
import urllib.error
import time

# ─────────────────────────────────────────────────────────────────────
#  КОНСТАНТЫ
# ─────────────────────────────────────────────────────────────────────

BASE_URL      = os.environ.get("OPNSENSE_BASE_URL", "https://127.0.0.1")
CERT_KEYTYPE  = "2048"
CERT_DIGEST   = "sha256"
CERT_LIFETIME = "397"
CERT_TYPE     = "usr_cert"

# ─────────────────────────────────────────────────────────────────────
#  ВСПОМОГАТЕЛЬНЫЕ
# ─────────────────────────────────────────────────────────────────────

def header(t): print(f"\n{'='*60}\n  {t}\n{'='*60}\n")
def ok(t):     print(f"  [OK]   {t}")
def warn(t):   print(f"  [WARN] {t}")
def err(t):    print(f"  [ERR]  {t}")

# ─────────────────────────────────────────────────────────────────────
#  API
# ─────────────────────────────────────────────────────────────────────

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE

_auth = None


def api(path, method="GET", body=None, raw=False):
    data = json.dumps(body).encode() if (method == "POST" and body is not None) else None
    req = urllib.request.Request(BASE_URL + path, data=data, method=method)
    req.add_header("Authorization", _auth)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=30) as r:
            content = r.read()
            return content if raw else json.loads(content)
    except urllib.error.HTTPError as e:
        print(f"  [HTTP {e.code}] {path} — {e.read()[:200].decode()}")
        return None
    except Exception as e:
        print(f"  [ERR] {path} — {e}")
        return None

# ─────────────────────────────────────────────────────────────────────
#  АРГУМЕНТЫ
# ─────────────────────────────────────────────────────────────────────

AUTO_YES    = "--yes" in sys.argv
CA_FROM_CLI = ""
_remaining  = []
_skip       = False
_argv_tail  = sys.argv[1:]
for i, a in enumerate(_argv_tail):
    if _skip:
        _skip = False
        continue
    if a == "--yes":
        continue
    if a == "--ca" and i + 1 < len(_argv_tail):
        CA_FROM_CLI = _argv_tail[i + 1].strip()
        _skip = True
        continue
    if a.startswith("--ca="):
        CA_FROM_CLI = a.split("=", 1)[1].strip()
        continue
    _remaining.append(a)
args = _remaining

# ─────────────────────────────────────────────────────────────────────
#  ЗАГРУЗКА CSV
# ─────────────────────────────────────────────────────────────────────

def load_csv(csv_path):
    users = []
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        for lineno, row in enumerate(csv.reader(f, delimiter=";"), 1):
            if not row or row[0].strip().lower() in ("", "login"):
                continue
            if len(row) < 2:
                warn(f"Строка {lineno}: недостаточно колонок — пропускаем")
                continue
            login = row[0].strip()
            ip    = row[1].strip()
            email = row[2].strip() if len(row) > 2 else ""
            if not login:
                warn(f"Строка {lineno}: пустой login — пропускаем")
                continue
            if not ip:
                warn(f"Строка {lineno}: пустой ip — пропускаем")
                continue
            users.append({"username": login, "ip": ip, "email": email})
    return users

# ─────────────────────────────────────────────────────────────────────
#  ПОДКЛЮЧЕНИЕ К API
# ─────────────────────────────────────────────────────────────────────

def connect():
    global _auth
    header("API-доступ")
    api_key    = os.environ.get("OPNSENSE_API_KEY",    "").strip() or input("  API Key    : ").strip()
    api_secret = os.environ.get("OPNSENSE_API_SECRET", "").strip() or input("  API Secret : ").strip()
    if not api_key or not api_secret:
        err("API Key и API Secret обязательны.")
        sys.exit(1)
    _auth = "Basic " + base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
    ca_resp = api("/api/trust/ca/search", method="POST")
    if ca_resp is None:
        err("Не удалось подключиться к OPNsense API. Проверьте ключи и BASE_URL.")
        sys.exit(1)
    ok(f"Подключение к API: {BASE_URL}")
    return ca_resp

# ─────────────────────────────────────────────────────────────────────
#  ВЫБОР VPN-СЕРВЕРА
# ─────────────────────────────────────────────────────────────────────

def get_vpn_server():
    vpn_providers = api("/api/openvpn/export/providers") or {}
    if not vpn_providers:
        err("Нет OpenVPN серверов. Создайте сервер в VPN → OpenVPN.")
        sys.exit(1)
    first_id, first = next(iter(vpn_providers.items()))
    vpn_id = str(first.get("vpnid", first_id))
    ok(f"OpenVPN сервер: '{first.get('name')}' (vpnid={vpn_id})")
    return vpn_id, vpn_providers

# ─────────────────────────────────────────────────────────────────────
#  РЕЖИМ 1: СОЗДАНИЕ СЕРТИФИКАТОВ И CSO
# ─────────────────────────────────────────────────────────────────────

def mode_create(users, ca_resp):
    header("Выбор CA")

    ca_rows = ca_resp.get("rows", [])
    if not ca_rows:
        err("Нет доступных CA. Создайте CA в System → Trust → Authorities.")
        sys.exit(1)

    print(f"  {'#':<4} {'Название':<35} {'refid'}")
    print(f"  {'-'*4} {'-'*35} {'-'*15}")
    for i, ca in enumerate(ca_rows, 1):
        print(f"  {i:<4} {ca.get('descr', '?'):<35} {ca.get('refid', '?')}")
    print()

    CA_HINT   = (CA_FROM_CLI or os.environ.get("OPNSENSE_CA", "")).strip()
    chosen_ca = None

    if CA_HINT:
        for ca in ca_rows:
            if ca.get("refid") == CA_HINT or ca.get("descr") == CA_HINT:
                chosen_ca = ca
                break
        if not chosen_ca:
            err(f"CA не найден по '{CA_HINT}' (ни refid, ни descr).")
            sys.exit(1)
        print(f"  CA по аргументу/ENV: '{chosen_ca.get('descr')}'")
    elif len(ca_rows) == 1:
        chosen_ca = ca_rows[0]
        print(f"  Найден один CA — выбран автоматически: '{chosen_ca.get('descr')}'")
    elif AUTO_YES:
        err("Несколько CA, --yes без --ca / OPNSENSE_CA — нечего выбрать.")
        sys.exit(1)
    else:
        while True:
            try:
                choice = int(input(f"  Введите номер CA (1-{len(ca_rows)}): ").strip())
                if 1 <= choice <= len(ca_rows):
                    chosen_ca = ca_rows[choice - 1]
                    break
            except ValueError:
                pass
            print(f"  [!] Введите число от 1 до {len(ca_rows)}.")

    CA_REFID = chosen_ca["refid"]
    ok(f"CA: '{chosen_ca.get('descr')}' (refid={CA_REFID})")

    vpn_id, _ = get_vpn_server()

    header("Подтверждение")

    print(f"  {'#':<4} {'login':<25} {'ip':<20} {'email'}")
    print(f"  {'-'*4} {'-'*25} {'-'*20} {'-'*30}")
    for i, u in enumerate(users, 1):
        print(f"  {i:<4} {u['username']:<25} {u['ip']:<20} {u['email']}")

    print(f"\n  Будет создано: {len(users)} сертификатов + {len(users)} CSO")
    print(f"  CA     : {chosen_ca.get('descr')} (refid={CA_REFID})")
    print(f"  VPN ID : {vpn_id}\n")

    if AUTO_YES:
        print("  Создать? [y/N]: y (--yes)")
    elif input("  Создать? [y/N]: ").strip().lower() not in ("y", "yes", "д", "да"):
        print("Отменено.")
        return

    header("Создание")

    existing_cso    = (api("/api/openvpn/client_overwrites/search", method="POST") or {}).get("rows", [])
    existing_cns    = {r.get("common_name") for r in existing_cso}
    existing_crts   = (api("/api/trust/cert/search", method="POST") or {}).get("rows", [])
    existing_descrs = {r.get("descr") for r in existing_crts}

    results = []

    for i, user in enumerate(users, 1):
        username = user["username"]
        print(f"\n  [{i}/{len(users)}] {username}  ({user['ip']})")

        if username in existing_descrs:
            warn("Сертификат уже существует — пропускаем")
            cert_status = "EXISTS"
        else:
            cert = api("/api/trust/cert/add", method="POST", body={
                "cert": {
                    "action":       "internal",
                    "descr":        username,
                    "caref":        CA_REFID,
                    "key_type":     CERT_KEYTYPE,
                    "digest":       CERT_DIGEST,
                    "lifetime":     CERT_LIFETIME,
                    "cert_type":    CERT_TYPE,
                    "commonname":   username,
                    "email":        user["email"],
                    "country":      "RU",
                    "state":        "Moscow",
                    "city":         "Moscow",
                    "organization": "Lab",
                }
            })
            if cert and cert.get("result") == "saved":
                ok(f"Сертификат (uuid={cert.get('uuid','?')})")
                existing_descrs.add(username)
                cert_status = "OK"
            else:
                err(f"Сертификат не создан: {cert}")
                results.append({"username": username, "cert": "FAILED", "cso": "SKIPPED"})
                continue
        time.sleep(0.2)

        if username in existing_cns:
            warn("CSO уже существует — пропускаем")
            results.append({"username": username, "cert": cert_status, "cso": "EXISTS"})
            continue

        cso = api("/api/openvpn/client_overwrites/add", method="POST", body={
            "cso": {
                "enabled":        "1",
                "common_name":    username,
                "servers":        vpn_id,
                "description":    f"VPN {username}",
                "tunnel_network": user["ip"],
            }
        })
        if cso and cso.get("result") == "saved":
            ok(f"CSO (uuid={cso.get('uuid','?')})")
            existing_cns.add(username)
            results.append({"username": username, "cert": cert_status, "cso": "OK"})
        else:
            warn(f"CSO не создан: {cso}")
            results.append({"username": username, "cert": cert_status, "cso": "FAILED"})

        time.sleep(0.2)

    header("Применение")
    api("/api/openvpn/service/reconfigure", method="POST", body={})
    ok("OpenVPN reconfigure")

    header("Итог")
    cert_ok = sum(1 for r in results if r["cert"] in ("OK", "EXISTS"))
    cso_ok  = sum(1 for r in results if r["cso"]  in ("OK", "EXISTS"))
    print(f"  Обработано   : {len(results)}")
    print(f"  Сертификатов : {cert_ok}/{len(results)}")
    print(f"  CSO записей  : {cso_ok}/{len(results)}")
    print()
    host = BASE_URL.replace("https://", "").replace("http://", "").rstrip("/")
    print(f"  Web UI: https://{host}/ui/openvpn/export")
    print()

# ─────────────────────────────────────────────────────────────────────
#  РЕЖИМ 2: СКАЧИВАНИЕ .ovpn ФАЙЛОВ
# ─────────────────────────────────────────────────────────────────────

def mode_download(users):
    vpn_id, vpn_providers = get_vpn_server()

    # Строим словарь descr → refid из export/accounts
    accounts = api(f"/api/openvpn/export/accounts/{vpn_id}") or {}
    descr_to_refid = {}
    for refid, info in accounts.items():
        if refid:
            descr_to_refid[info.get("description", "")] = refid

    # Папка для сохранения
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ovpn_files")
    os.makedirs(out_dir, exist_ok=True)
    ok(f"Папка для файлов: {out_dir}")

    header("Скачивание .ovpn")

    downloaded = 0
    skipped    = 0

    for i, user in enumerate(users, 1):
        username = user["username"]
        refid    = descr_to_refid.get(username)
        print(f"\n  [{i}/{len(users)}] {username}", end="")

        if not refid:
            print()
            warn(f"Сертификат не найден в Client Export — пропускаем")
            skipped += 1
            continue

        resp = api(
            f"/api/openvpn/export/download/{vpn_id}/{refid}",
            method="POST",
            body={"openvpn_export": {}}
        )

        if not resp or resp.get("result") != "ok":
            print()
            warn(f"Ошибка скачивания: {resp}")
            skipped += 1
            continue

        filename = resp.get("filename") or f"{username}.ovpn"
        content  = base64.b64decode(resp["content"])
        out_path = os.path.join(out_dir, filename)

        with open(out_path, "wb") as f:
            f.write(content)

        print(f"  → {filename}")
        downloaded += 1

    header("Итог")
    print(f"  Скачано  : {downloaded}/{len(users)}")
    if skipped:
        print(f"  Пропущено: {skipped} (нет сертификата в Client Export)")
    print(f"  Папка    : {out_dir}")
    print()

# ─────────────────────────────────────────────────────────────────────
#  ТОЧКА ВХОДА
# ─────────────────────────────────────────────────────────────────────

header("OPNsense VPN Manager")

# Шаг 0: подключение
ca_resp = connect()

# Шаг 1: загрузка CSV
header("Пользователи")

csv_path = args[0] if args else input("  Путь к CSV-файлу: ").strip().strip('"')
if not os.path.isfile(csv_path):
    err(f"Файл не найден: {csv_path}")
    sys.exit(1)

users = load_csv(csv_path)
if not users:
    err("Нет валидных записей.")
    sys.exit(1)

print(f"  Файл    : {csv_path}")
print(f"  Записей : {len(users)}")

# Шаг 2: выбор режима
header("Выбор режима")
print("  1. Создать сертификаты и CSO")
print("  2. Скачать .ovpn файлы")
print()

mode = ""
while mode not in ("1", "2"):
    mode = input("  Введите номер (1 или 2): ").strip()

if mode == "1":
    mode_create(users, ca_resp)
else:
    mode_download(users)
