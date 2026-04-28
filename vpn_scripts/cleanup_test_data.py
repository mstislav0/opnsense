#!/usr/bin/env python3
"""
cleanup_test_data.py — одноразовый скрипт очистки тестовых данных testuser01-20.

Удаляет:
  - CSO с common_name LIKE 'testuser%'
  - local users с name LIKE 'testuser%'
  - certs с descr LIKE 'testuser%'

НЕ удаляет:
  - CSO 'Osov Mstislav' (ручная запись)
  - root, Web GUI TLS certificate, VPN-Lab-Server cert, VPN-Lab-CA

Запуск:
  OPNSENSE_API_KEY=... OPNSENSE_API_SECRET=... python3 cleanup_test_data.py [--yes]
"""

import sys
import os
import json
import ssl
import base64
import urllib.request
import urllib.error

BASE_URL = "https://62.113.44.224"
PREFIX   = "testuser"

AUTO_YES = "--yes" in sys.argv

api_key    = os.environ.get("OPNSENSE_API_KEY",    "").strip() or input("API Key: ").strip()
api_secret = os.environ.get("OPNSENSE_API_SECRET", "").strip() or input("API Secret: ").strip()
_auth      = "Basic " + base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE


def api(path, method="GET", body=None):
    data = json.dumps(body).encode() if (method == "POST" and body is not None) else None
    req = urllib.request.Request(BASE_URL + path, data=data, method=method)
    req.add_header("Authorization", _auth)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  [HTTP {e.code}] {path} — {e.read()[:200].decode()}")
        return None
    except Exception as e:
        print(f"  [ERR] {path} — {e}")
        return None


def collect_targets():
    cso  = (api("/api/openvpn/client_overwrites/search", method="POST") or {}).get("rows", [])
    usr  = (api("/api/auth/user/search",                 method="POST") or {}).get("rows", [])
    crt  = (api("/api/trust/cert/search",                method="POST") or {}).get("rows", [])

    cso_targets = [r for r in cso if (r.get("common_name") or "").startswith(PREFIX)]
    usr_targets = [r for r in usr if (r.get("name")        or "").startswith(PREFIX)]
    crt_targets = [r for r in crt if (r.get("descr")       or "").startswith(PREFIX)]
    return cso_targets, usr_targets, crt_targets


def main():
    cso_targets, usr_targets, crt_targets = collect_targets()

    print(f"\n=== Будет удалено ===")
    print(f"  CSO         : {len(cso_targets)}")
    print(f"  Local users : {len(usr_targets)}")
    print(f"  Certs       : {len(crt_targets)}")
    print()

    if not (cso_targets or usr_targets or crt_targets):
        print("Нечего удалять.")
        return

    if not AUTO_YES:
        if input("Продолжить? [y/N]: ").strip().lower() not in ("y", "yes", "д", "да"):
            print("Отменено.")
            return

    # Порядок: CSO → users → certs (на всякий случай — серт может быть привязан к user)
    for r in cso_targets:
        resp = api(f"/api/openvpn/client_overwrites/del/{r['uuid']}", method="POST", body={})
        print(f"  CSO  del {r.get('common_name')} → {resp}")

    for r in usr_targets:
        resp = api(f"/api/auth/user/del/{r['uuid']}", method="POST", body={})
        print(f"  USER del {r.get('name')} → {resp}")

    for r in crt_targets:
        resp = api(f"/api/trust/cert/del/{r['uuid']}", method="POST", body={})
        print(f"  CERT del {r.get('descr')} → {resp}")

    # Применить изменения
    print("\n  Применяем конфиг...")
    api("/api/openvpn/service/reconfigure", method="POST", body={})
    api("/api/auth/user/reconfigure",       method="POST", body={})

    # Проверка
    cso_left, usr_left, crt_left = collect_targets()
    print(f"\n=== После очистки ===")
    print(f"  CSO         : {len(cso_left)}")
    print(f"  Local users : {len(usr_left)}")
    print(f"  Certs       : {len(crt_left)}")


if __name__ == "__main__":
    main()
