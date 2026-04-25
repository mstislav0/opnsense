#!/usr/bin/env python3
"""
2_create_vpn_certs.py — запускается прямо на OPNsense.

Что делает:
  1. Читает JSON с пользователями (выход 1_Get-ADUsersForVPN.ps1)
  2. Показывает список, запрашивает подтверждение
  3. Для каждого пользователя создаёт через OPNsense API:
     - клиентский сертификат (CN = username)
     - Client Specific Override (CSO) через /api/openvpn/client_overwrites/add
  4. Выводит итог

После выполнения:
  Web UI → VPN → OpenVPN → Client Specific Overrides  — список CSO
  Web UI → VPN → OpenVPN → Client Export              — скачать .ovpn

Запуск:
  python3 /opt/vpn_scripts/2_create_vpn_certs.py users.json
  python3 /opt/vpn_scripts/2_create_vpn_certs.py --yes users.json
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
import xml.etree.ElementTree as ET

# ─────────────────────────────────────────────────────────────────────
#  НАСТРОЙКИ — заполнить под свою инсталляцию
# ─────────────────────────────────────────────────────────────────────

API_KEY       = "7gWamJvP0dMXAzvgRQE61CWEvUSfqB_Muai8gW4oQrg"
API_SECRET    = "lzmB7BGIkAq2xsQSscyGGDDv_Hfcw5tJUhIfSxXhke0"
BASE_URL      = "https://127.0.0.1"

# refid CA (System → Trust → Authorities)
CA_REFID      = "69ecf4fe169ec"

# vpnid OpenVPN сервера из config.xml → <openvpn-server> → <vpnid>
VPN_ID        = "1"

CERT_KEYTYPE  = "RSA"
CERT_KEYLEN   = "2048"
CERT_DIGEST   = "sha256"
CERT_LIFETIME = "365"
CONFIG_XML    = "/conf/config.xml"

# ─────────────────────────────────────────────────────────────────────
#  API-КЛИЕНТ
# ─────────────────────────────────────────────────────────────────────

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE
_auth = "Basic " + base64.b64encode(f"{API_KEY}:{API_SECRET}".encode()).decode()


def api(path, method="GET", body=None):
    """
    REST-запрос к OPNsense API.

    OPNsense quirks:
    - search-endpoints: POST без тела (пустой JSON {} даёт 400)
    - add-endpoints: POST с JSON-телом
    """
    if method == "POST" and body is not None:
        data = json.dumps(body).encode()
    elif method == "POST":
        data = None   # search — без тела
    else:
        data = None

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
#  ВЫВОД
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
#  MAIN
# ─────────────────────────────────────────────────────────────────────

AUTO_YES = "--yes" in sys.argv
args     = [a for a in sys.argv[1:] if a != "--yes"]

header("Создание VPN-сертификатов и CSO в OPNsense")

# ── Шаг 1: загрузка JSON ─────────────────────────────────────────────

json_path = args[0] if args else input("Путь к JSON-файлу: ").strip().strip('"')

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

header("Шаг 1: Пользователи")
print(f"  Файл    : {json_path}")
print(f"  Записей : {len(users)}")

# ── Шаг 2: предпросмотр и подтверждение ──────────────────────────────

header("Шаг 2: Подтверждение")

print(f"  {'#':<4} {'username':<20} {'email'}")
print(f"  {'-'*4} {'-'*20} {'-'*35}")
for i, u in enumerate(users, 1):
    print(f"  {i:<4} {u['username']:<20} {u['email']}")

print(f"\n  Будет создано: {len(users)} сертификатов + {len(users)} CSO")
print(f"  CA refid : {CA_REFID}  |  VPN ID : {VPN_ID}\n")

if AUTO_YES:
    print("  Создать? [y/N]: y (--yes)")
elif input("  Создать? [y/N]: ").strip().lower() not in ("y", "yes", "д", "да"):
    print("Отменено.")
    sys.exit(0)

# ── Шаг 3: проверка API ───────────────────────────────────────────────

header("Шаг 3: Проверка")

# Проверяем CA (search → POST без тела)
ca_resp = api("/api/trust/ca/search", method="POST")
if ca_resp is None:
    err("Нет доступа к OPNsense API.")
    sys.exit(1)

ca = next((r for r in ca_resp.get("rows", []) if r.get("refid") == CA_REFID), None)
if not ca:
    err(f"CA refid='{CA_REFID}' не найден. Доступные:")
    for r in ca_resp.get("rows", []):
        print(f"    refid={r.get('refid')}  descr={r.get('descr')}")
    sys.exit(1)
ok(f"CA: '{ca.get('descr')}'")

# Проверяем OpenVPN сервер в config.xml
srv = next((s for s in ET.parse(CONFIG_XML).getroot().findall(".//openvpn-server")
            if s.findtext("vpnid") == VPN_ID), None)
if srv is None:
    err(f"OpenVPN сервер vpnid={VPN_ID} не найден в config.xml.")
    sys.exit(1)
ok(f"OpenVPN сервер: '{srv.findtext('description')}'")

# Загружаем существующие CSO чтобы не дублировать
existing_cso = api("/api/openvpn/client_overwrites/search", method="POST")
existing_cns = {r["common_name"] for r in (existing_cso or {}).get("rows", [])}
ok(f"Существующих CSO: {len(existing_cns)}")

# Загружаем существующих local users чтобы не дублировать
existing_users_resp = api("/api/auth/user/search", method="POST")
existing_usernames = {r["name"] for r in (existing_users_resp or {}).get("rows", [])}
ok(f"Существующих local users: {len(existing_usernames)}")

# ── Шаг 4: создание сертификатов и CSO ───────────────────────────────

header("Шаг 4: Создание")

results = []

for i, user in enumerate(users, 1):
    username = user["username"]
    print(f"\n  [{i}/{len(users)}] {username}")

    # Сертификат
    cert = api("/api/trust/cert/add", method="POST", body={
        "cert": {
            "descr":           username,
            "caref":           CA_REFID,       # refid, не uuid!
            "keytype":         CERT_KEYTYPE,
            "keylen":          CERT_KEYLEN,
            "digest_alg":      CERT_DIGEST,
            "lifetime":        CERT_LIFETIME,
            "dn_commonname":   username,       # CN = username — по нему OpenVPN матчит CSO
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
        err(f"Не удалось создать сертификат")
        results.append({"username": username, "cert": "FAILED", "cso": "SKIPPED", "local_user": "SKIPPED"})
        continue
    cert_uuid = cert.get("uuid", "")
    ok(f"Сертификат (uuid={cert_uuid})")
    time.sleep(0.3)

    # Local user (нужен для Client Export в Web UI)
    if username in existing_usernames:
        warn(f"Local user уже существует — пропускаем")
    else:
        local_user = api("/api/auth/user/add", method="POST", body={
            "user": {
                "name":        username,
                "password":    random_password(),   # случайный — VPN авторизуется по сертификату
                "email":       user["email"],
                "certificate": cert_uuid,           # привязываем → появится в Client Export
                "disabled":    "0",
            }
        })
        if local_user and local_user.get("result") == "saved":
            ok(f"Local user (uuid={local_user.get('uuid', '?')})")
            existing_usernames.add(username)
        else:
            warn(f"Local user не создан: {local_user}")
    time.sleep(0.2)

    # CSO
    if username in existing_cns:
        warn(f"CSO уже существует — пропускаем")
        results.append({"username": username, "cert": "OK", "cso": "EXISTS", "local_user": "EXISTS"})
        continue

    # Поле называется "cso" (не "client_overwrites") — так требует модель OPNsense
    cso = api("/api/openvpn/client_overwrites/add", method="POST", body={
        "cso": {
            "enabled":          "1",
            "common_name":      username,   # матчится с CN сертификата при подключении
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
        results.append({"username": username, "cert": "OK", "cso": "OK", "local_user": "OK"})
    else:
        warn(f"CSO не создан: {cso}")
        results.append({"username": username, "cert": "OK", "cso": "FAILED", "local_user": "OK"})

    time.sleep(0.2)

# ── Шаг 5: итог ──────────────────────────────────────────────────────

header("Итог")

cert_ok = sum(1 for r in results if r["cert"] == "OK")
cso_ok  = sum(1 for r in results if r["cso"] in ("OK", "EXISTS"))
user_ok = sum(1 for r in results if r.get("local_user") in ("OK", "EXISTS"))

print(f"  Обработано   : {len(results)}")
print(f"  Сертификатов : {cert_ok}/{len(results)}")
print(f"  Local users  : {user_ok}/{len(results)}")
print(f"  CSO записей  : {cso_ok}/{len(results)}")

# Финальный счёт из API
final = api("/api/openvpn/client_overwrites/search", method="POST")
if final:
    print(f"  CSO в Web UI : {final.get('total', '?')}")

print()
print("  Web UI:")
print("  • VPN → OpenVPN → Client Specific Overrides")
print("  • VPN → OpenVPN → Client Export")
print()
