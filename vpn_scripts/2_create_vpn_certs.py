#!/usr/bin/env python3
"""
2_create_vpn_certs.py — запускается прямо на OPNsense.

Что делает:
  1. Запрашивает API Key и API Secret (или берёт из переменных окружения)
  2. Читает JSON с пользователями (выход 1_Get-ADUsersForVPN.ps1)
  3. Показывает список доступных CA, пользователь выбирает нужный
  4. Запрашивает подтверждение перед созданием
  5. Для каждого пользователя создаёт через OPNsense API:
     - клиентский сертификат (CN = username)
     - local user с привязкой сертификата (для Client Export)
     - Client Specific Override (CSO)
  6. Выводит итог

Переменные окружения (опционально, чтобы не вводить каждый раз):
  OPNSENSE_API_KEY    — API Key
  OPNSENSE_API_SECRET — API Secret

Запуск:
  python3 2_create_vpn_certs.py users.json
  python3 2_create_vpn_certs.py --yes users.json
"""

import sys
import os
import json
import ssl
import base64
import urllib.request
import urllib.error
import time
import secrets
import string

# ─────────────────────────────────────────────────────────────────────
#  КОНСТАНТЫ
# ─────────────────────────────────────────────────────────────────────

BASE_URL      = "https://127.0.0.1"
CERT_KEYTYPE  = "RSA"
CERT_KEYLEN   = "2048"
CERT_DIGEST   = "sha256"
CERT_LIFETIME = "365"

# ─────────────────────────────────────────────────────────────────────
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ─────────────────────────────────────────────────────────────────────

def random_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$"
    return ''.join(secrets.choice(chars) for _ in range(length))

def header(text):
    print(f"\n{'='*60}\n  {text}\n{'='*60}\n")

def ok(text):   print(f"  [OK]   {text}")
def warn(text): print(f"  [WARN] {text}")
def err(text):  print(f"  [ERR]  {text}")

# ─────────────────────────────────────────────────────────────────────
#  API-КЛИЕНТ
# ─────────────────────────────────────────────────────────────────────

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE

_auth = None  # инициализируется после ввода credentials


def api(path, method="GET", body=None):
    """
    REST-запрос к OPNsense API.
    search-endpoints: POST без тела (пустой JSON {} даёт 400).
    add-endpoints: POST с JSON-телом.
    """
    data = json.dumps(body).encode() if (method == "POST" and body is not None) else None
    req = urllib.request.Request(BASE_URL + path, data=data, method=method)
    req.add_header("Authorization", _auth)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  [HTTP {e.code}] {path} — {e.read()[:150].decode()}")
        return None
    except Exception as e:
        print(f"  [ERR] {path} — {e}")
        return None

# ─────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────

AUTO_YES = "--yes" in sys.argv
args     = [a for a in sys.argv[1:] if a != "--yes"]

header("Создание VPN-сертификатов и CSO в OPNsense")

# ── Шаг 0: API credentials ───────────────────────────────────────────

header("Шаг 0: API-доступ")

api_key = os.environ.get("OPNSENSE_API_KEY", "").strip()
api_secret = os.environ.get("OPNSENSE_API_SECRET", "").strip()

if api_key:
    print(f"  API Key    : (из переменной окружения)")
else:
    api_key = input("  API Key    : ").strip()

if api_secret:
    print(f"  API Secret : (из переменной окружения)")
else:
    api_secret = input("  API Secret : ").strip()

if not api_key or not api_secret:
    err("API Key и API Secret обязательны.")
    sys.exit(1)

_auth = "Basic " + base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()

# Проверяем доступ
test = api("/api/trust/ca/search", method="POST")
if test is None:
    err("Не удалось подключиться к OPNsense API. Проверьте ключи.")
    sys.exit(1)
ok("Подключение к API успешно")

# ── Шаг 1: загрузка JSON ─────────────────────────────────────────────

header("Шаг 1: Пользователи")

json_path = args[0] if args else input("  Путь к JSON-файлу: ").strip().strip('"')

if not os.path.isfile(json_path):
    err(f"Файл не найден: {json_path}")
    sys.exit(1)

try:
    with open(json_path, encoding="utf-8") as f:
        raw = json.load(f)
except Exception as e:
    err(f"Ошибка чтения JSON: {e}")
    sys.exit(1)

users = []
for u in (raw if isinstance(raw, list) else [raw]):
    username = u.get("username", "").strip()
    if not username:
        warn("Запись без username — пропущена")
        continue
    users.append({
        "username":     username,
        "email":        u.get("email", f"{username}@lab.local").strip(),
        "source_group": u.get("source_group", ""),
    })

if not users:
    err("Нет валидных записей.")
    sys.exit(1)

print(f"  Файл    : {json_path}")
print(f"  Записей : {len(users)}")

# ── Шаг 2: выбор CA ──────────────────────────────────────────────────

header("Шаг 2: Выбор CA")

ca_rows = test.get("rows", [])
if not ca_rows:
    err("Нет доступных CA. Создайте CA в System → Trust → Authorities.")
    sys.exit(1)

print(f"  Доступные CA:\n")
print(f"  {'#':<4} {'Название':<35} {'refid'}")
print(f"  {'-'*4} {'-'*35} {'-'*15}")
for i, ca in enumerate(ca_rows, 1):
    print(f"  {i:<4} {ca.get('descr', '?'):<35} {ca.get('refid', '?')}")

print()
if len(ca_rows) == 1:
    chosen_ca = ca_rows[0]
    print(f"  Найден один CA — выбран автоматически: '{chosen_ca.get('descr')}'")
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

# ── Шаг 3: получаем VPN ID ───────────────────────────────────────────

vpn_resp = api("/api/openvpn/instances/search", method="POST")
vpn_rows = (vpn_resp or {}).get("rows", [])
if not vpn_rows:
    err("Нет OpenVPN серверов. Создайте сервер в VPN → OpenVPN → Instances.")
    sys.exit(1)

VPN_ID = str(vpn_rows[0].get("vpnid", vpn_rows[0].get("uuid", "1")))
ok(f"OpenVPN сервер: '{vpn_rows[0].get('description', vpn_rows[0].get('role', '?'))}' (id={VPN_ID})")

# ── Шаг 4: предпросмотр и подтверждение ──────────────────────────────

header("Шаг 3: Подтверждение")

print(f"  {'#':<4} {'username':<20} {'email'}")
print(f"  {'-'*4} {'-'*20} {'-'*35}")
for i, u in enumerate(users, 1):
    print(f"  {i:<4} {u['username']:<20} {u['email']}")

print(f"\n  Будет создано: {len(users)} сертификатов + {len(users)} local users + {len(users)} CSO")
print(f"  CA    : {chosen_ca.get('descr')} (refid={CA_REFID})")
print(f"  VPN ID: {VPN_ID}\n")

if AUTO_YES:
    print("  Создать? [y/N]: y (--yes)")
elif input("  Создать? [y/N]: ").strip().lower() not in ("y", "yes", "д", "да"):
    print("Отменено.")
    sys.exit(0)

# ── Шаг 5: проверка существующих записей ─────────────────────────────

header("Шаг 4: Создание")

existing_cso = api("/api/openvpn/client_overwrites/search", method="POST")
existing_cns = {r["common_name"] for r in (existing_cso or {}).get("rows", [])}

existing_users_resp = api("/api/auth/user/search", method="POST")
existing_usernames = {r["name"] for r in (existing_users_resp or {}).get("rows", [])}

# ── Шаг 6: создание ──────────────────────────────────────────────────

results = []

for i, user in enumerate(users, 1):
    username = user["username"]
    print(f"\n  [{i}/{len(users)}] {username}")

    # Сертификат
    cert = api("/api/trust/cert/add", method="POST", body={
        "cert": {
            "descr":           username,
            "caref":           CA_REFID,
            "keytype":         CERT_KEYTYPE,
            "keylen":          CERT_KEYLEN,
            "digest_alg":      CERT_DIGEST,
            "lifetime":        CERT_LIFETIME,
            "dn_commonname":   username,
            "dn_email":        user["email"],
            "dn_country":      "RU",
            "dn_state":        "Moscow",
            "dn_city":         "Moscow",
            "dn_organization": "Lab",
            "type":            "usr",
            "certmethod":      "internal",
        }
    })

    if not cert or cert.get("result") != "saved":
        err("Не удалось создать сертификат")
        results.append({"username": username, "cert": "FAILED", "local_user": "SKIPPED", "cso": "SKIPPED"})
        continue
    cert_uuid = cert.get("uuid", "")
    ok(f"Сертификат (uuid={cert_uuid})")
    time.sleep(0.3)

    # Local user
    if username in existing_usernames:
        warn("Local user уже существует — пропускаем")
        local_user_status = "EXISTS"
    else:
        local_user = api("/api/auth/user/add", method="POST", body={
            "user": {
                "name":        username,
                "password":    random_password(),
                "email":       user["email"],
                "certificate": cert_uuid,
                "disabled":    "0",
            }
        })
        if local_user and local_user.get("result") == "saved":
            ok(f"Local user (uuid={local_user.get('uuid', '?')})")
            existing_usernames.add(username)
            local_user_status = "OK"
        else:
            warn(f"Local user не создан: {local_user}")
            local_user_status = "FAILED"
    time.sleep(0.2)

    # CSO
    if username in existing_cns:
        warn("CSO уже существует — пропускаем")
        results.append({"username": username, "cert": "OK", "local_user": local_user_status, "cso": "EXISTS"})
        continue

    cso = api("/api/openvpn/client_overwrites/add", method="POST", body={
        "cso": {
            "enabled":          "1",
            "common_name":      username,
            "servers":          VPN_ID,
            "description":      f"VPN {username} ({user['source_group']})",
            "tunnel_network":   "",
            "tunnel_networkv6": "",
            "local_networks":   "",
            "remote_networks":  "",
            "push_reset":       "0",
            "block":            "0",
            "route_gateway":    "",
            "redirect_gateway": "",
        }
    })

    if cso and cso.get("result") == "saved":
        ok(f"CSO (uuid={cso.get('uuid', '?')})")
        existing_cns.add(username)
        results.append({"username": username, "cert": "OK", "local_user": local_user_status, "cso": "OK"})
    else:
        warn(f"CSO не создан: {cso}")
        results.append({"username": username, "cert": "OK", "local_user": local_user_status, "cso": "FAILED"})

    time.sleep(0.2)

# ── Итог ─────────────────────────────────────────────────────────────

header("Итог")

cert_ok = sum(1 for r in results if r["cert"] == "OK")
user_ok = sum(1 for r in results if r["local_user"] in ("OK", "EXISTS"))
cso_ok  = sum(1 for r in results if r["cso"] in ("OK", "EXISTS"))

print(f"  Обработано   : {len(results)}")
print(f"  Сертификатов : {cert_ok}/{len(results)}")
print(f"  Local users  : {user_ok}/{len(results)}")
print(f"  CSO записей  : {cso_ok}/{len(results)}")

final = api("/api/openvpn/client_overwrites/search", method="POST")
if final:
    print(f"  CSO в Web UI : {final.get('total', '?')}")

print()
print("  Web UI:")
print("  • VPN → OpenVPN → Client Specific Overrides")
print("  • VPN → OpenVPN → Client Export")
print()
