import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import sys


def windows_gateway(output):
    routes = []
    for line in output.splitlines():
        columns = line.split()
        if len(columns) != 5 or columns[:2] != ["0.0.0.0", "0.0.0.0"]:
            continue
        try:
            gateway = ipaddress.IPv4Address(columns[2])
            metric = int(columns[4])
            if not gateway.is_unspecified:
                routes.append((metric, str(gateway)))
        except ValueError:
            continue
    return min(routes)[1] if routes else ""


def linux_gateway(output):
    routes = []
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 8 or columns[1] != "00000000" or columns[7] != "00000000":
            continue
        try:
            if int(columns[3], 16) & 3 != 3:
                continue
            gateway = socket.inet_ntoa(bytes.fromhex(columns[2])[::-1])
            if gateway != "0.0.0.0":
                routes.append((int(columns[6]), gateway))
        except (ValueError, OSError):
            continue
    return min(routes)[1] if routes else ""


def command(args):
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    return subprocess.run(args, capture_output=True, text=True, errors="replace",
                          timeout=4, check=True, **options).stdout


def default_gateway():
    try:
        if sys.platform == "win32":
            return windows_gateway(command(["route.exe", "print", "-4"]))
        if sys.platform.startswith("linux"):
            try:
                return linux_gateway(Path("/proc/net/route").read_text())
            except OSError:
                routes = json.loads(command(["ip", "-j", "-4", "route", "show", "default"]))
                candidates = [(int(r.get("metric", 0)), str(ipaddress.IPv4Address(r["gateway"])))
                              for r in routes if r.get("gateway") and "linkdown" not in r.get("flags", [])]
                return min(candidates)[1] if candidates else ""
        if sys.platform == "darwin":
            match = re.search(r"^\s*gateway:\s*(\S+)", command(["/sbin/route", "-n", "get", "default"]), re.M)
            return str(ipaddress.IPv4Address(match[1])) if match else ""
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return ""


def connection_defaults():
    gateway = default_gateway()
    return {"gateway": gateway, "address": "http://" + gateway if gateway else ""}
