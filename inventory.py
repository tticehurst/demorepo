#!/usr/bin/env python3
"""
inventory.py

Dynamic Ansible inventory based on MAC addresses defined in hosts.ini.

Improvements:
- Single arp-scan per run (massive performance boost)
- ARP scan results cached with TTL
- Optional ANSIBLE_ROOM filtering (e.g. E3)
- Warnings include hostname and respect ANSIBLE_ROOM
- Derived vars: room, building, room_number
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import yaml
import configparser

# ----------------------------
# Constants
# ----------------------------

HOSTS_INI = "hosts.ini"

ARP_SCAN_CACHE_FILE = "inventory_cache.json"
ARP_SCAN_CACHE_TTL = 3600  # seconds

VAULT_FILE = "secrets.yml"
VAULT_PASS_FILE = "secrets_pass.txt"

NOW = time.time()

ANSIBLE_ROOM = os.getenv("ANSIBLE_ROOM")

# ----------------------------
# Config
# ----------------------------

config = configparser.ConfigParser()
config.read(HOSTS_INI)

# ----------------------------
# Common Ansible vars
# ----------------------------

COMMON_VARS = {
    "ansible_user": "Administrator",
    "ansible_password": "SETUP",
    "ansible_connection": "psrp",
    "ansible_psrp_protocol": "http",
    "ansible_port": 5985,
}

# ----------------------------
# Helpers
# ----------------------------

def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, "", str(e)


def normalize_mac(mac):
    if not mac:
        return None
    mac = mac.strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", mac.replace(":", "")):
        mac = ":".join(mac.replace(":", "")[i:i+2] for i in range(0, 12, 2))
    return mac


def detect_interface():
    rc, out, _ = run_cmd(["/sbin/ip", "route", "show", "default"])
    if rc == 0:
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            return m.group(1)
    return None


def parse_arp_scan_output(output):
    results = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            ip, mac = parts[0], normalize_mac(parts[1])
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and mac:
                results[mac] = ip
    return results


def scan_with_arpscan(interface):
    arp = shutil.which("arp-scan")
    if not arp:
        return None, "arp-scan not installed"

    rc, out, err = run_cmd(
        [arp, "--interface", interface, "172.16.0.0/23"],
        timeout=90,
    )

    if rc != 0:
        return None, err

    return parse_arp_scan_output(out), None


# ----------------------------
# ARP scan cache
# ----------------------------

def load_scan_cache():
    if not os.path.exists(ARP_SCAN_CACHE_FILE):
        return None
    try:
        with open(ARP_SCAN_CACHE_FILE) as f:
            data = json.load(f)
        if NOW - data.get("timestamp", 0) < ARP_SCAN_CACHE_TTL:
            return data.get("results", {})
    except Exception:
        pass
    return None


def save_scan_cache(results):
    try:
        with open(ARP_SCAN_CACHE_FILE, "w") as f:
            json.dump(
                {"timestamp": NOW, "results": results},
                f,
                indent=2,
            )
    except Exception:
        pass


def resolve_all_macs(macs, iface, force=False):
    if not force:
        cached = load_scan_cache()
        if cached is not None:
            return cached

    results, err = scan_with_arpscan(iface)
    if err:
        print(f"# ERROR: {err}", file=sys.stderr)
        return {}

    save_scan_cache(results)
    return results


# ----------------------------
# Room parsing
# ----------------------------


def parse_room(hostname):
    return hostname.split("-")[0] if "-" in hostname else "UNKNOWN"


# ----------------------------
# Vault
# ----------------------------

def load_domain_creds():
    vault = shutil.which("ansible-vault")
    if not vault:
        return None, None

    rc, out, _ = run_cmd([
        vault, "view", VAULT_FILE,
        "--vault-password-file", VAULT_PASS_FILE
    ])

    if rc != 0:
        return None, None

    try:
        data = yaml.safe_load(out)
        return data.get("secret_domainUser"), data.get("secret_domainPassword")
    except Exception:
        return None, None


# ----------------------------
# Inventory
# ----------------------------

def build_inventory(force_rescan=False, use_domain_creds=False):
    inventory = {"all": {"hosts": []}, "_meta": {"hostvars": {}}}

    iface = detect_interface()
    if not iface:
        return inventory

    macs = [normalize_mac(s) for s in config.sections() if normalize_mac(s)]
    mac_ip_map = resolve_all_macs(macs, iface, force_rescan)

    vault_user, vault_pass = (None, None)
    if use_domain_creds:
        vault_user, vault_pass = load_domain_creds()

    for section in config.sections():
        mac = normalize_mac(section)
        hostname = config[section].get("hostname", fallback="UNKNOWN")
        use_ip = os.getenv("USE_IP") == "1"
        ip = mac_ip_map.get(mac)
        host_key = ip if use_ip or not hostname else hostname

        room = parse_room(hostname)

        # Respect ANSIBLE_ROOM for both inventory AND warnings
        if ANSIBLE_ROOM and room != ANSIBLE_ROOM:
            continue

        if not ip:
            print(
                f"# WARNING: MAC {mac} ({hostname}) not found in ARP scan",
                file=sys.stderr
            )
            continue

        hv = COMMON_VARS.copy()
        hv.update({
            "mac": mac,
            "hostname": hostname,
            "room": room,
            "staff_pc": config[section].getboolean("staff_pc", fallback=False),
            "skip_hostname": config[section].getboolean("skip_hostname", fallback=False),
            "domain_join": config[section].getboolean("domain_join", fallback=True),
            "ou": config[section].get("ou", fallback=None),
            "ansible_psrp_auth": "credssp" if use_domain_creds else "ntlm",
        })

        hv["ansible_host"] = ip

        if vault_user and vault_pass:
            hv["ansible_user"] = vault_user
            hv["ansible_password"] = vault_pass

        inventory["all"]["hosts"].append(host_key)
        inventory["_meta"]["hostvars"][host_key] = hv

    return inventory


# ----------------------------
# CLI
# ----------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--force-rescan", action="store_true")
    parser.add_argument("--use-domain-creds", action="store_true")
    args = parser.parse_args()

    inv = build_inventory(
        force_rescan=args.force_rescan,
        use_domain_creds=args.use_domain_creds or os.getenv("USE_DOMAIN_CREDS") == "1"
    )

    print(json.dumps(inv, indent=2))


if __name__ == "__main__":
    main()
