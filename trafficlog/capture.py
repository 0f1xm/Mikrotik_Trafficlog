from __future__ import annotations

import datetime as dt
import ipaddress
import re
import secrets
import threading
import time

from .router import RouterError
from .storage import DEFAULT_BUFFER_LINES, MAX_BUFFER_LINES, bounded_integer

MARKER = "TrafficLog:"
MARKERS = (MARKER, "TrafficLens:")
SESSION_RE = re.compile(r"^[0-9a-f]{10}$")
STATEFUL = {"limit", "dst-limit", "nth", "random", "psd", "connection-rate"}
READONLY = {".id", "bytes", "packets", "dynamic", "invalid", "disabled", "action",
            "log", "log-prefix", "comment", "reject-with", "jump-target", "hw-offload",
            "address-list", "address-list-timeout", "place-before", "copy-from",
            "creation-time", "last-seen", "active", "limit-accept"}
DECISIONS = {"accept", "drop", "reject"}


def ros_quote(value):
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    escaped = escaped.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return '"' + escaped + '"'


def add_command(path, body):
    if any(not re.fullmatch(r"[a-zA-Z0-9-]+", k) for k in body):
        raise ValueError("Unknown RouterOS parameter in command preview.")
    return "/" + path.replace("/", " ") + " add " + " ".join(k + "=" + ros_quote(v) for k, v in body.items())


def cleanup_commands(session, marker=MARKER):
    if not SESSION_RE.fullmatch(session) or marker not in MARKERS:
        raise ValueError("Invalid session ID")
    marker, buffer, scheduler = marker + session, "tl" + session, "tlstop" + session
    return [
        f'/ip firewall filter remove [find where comment="{marker}" and action=log]',
        f'/system logging remove [find where action="{buffer}"]',
        f'/system logging action remove [find where name="{buffer}"]',
        f'/system scheduler remove [find where name="{scheduler}" and comment="{marker}"]',
    ]


def yes(value):
    return str(value).lower() in {"yes", "true", "1"}


def records(value):
    return value if isinstance(value, list) else [value] if isinstance(value, dict) else []


def eligibility(rule):
    if rule.get("comment", "").startswith(MARKERS):
        return "Temporary capture rule"
    if yes(rule.get("dynamic")):
        return "Dynamic rule"
    if yes(rule.get("disabled")) or yes(rule.get("invalid")):
        return "Disabled or invalid"
    if rule.get("action") not in DECISIONS:
        return "Not a final accept/drop/reject rule"
    unsupported = sorted(k for k in STATEFUL if rule.get(k) not in (None, "", "0", "0/0"))
    if unsupported:
        return "Stateful matcher: " + ", ".join(unsupported)
    return ""


def public_rule(rule, position):
    reason = eligibility(rule)
    states = str(rule.get("connection-state", ""))
    return {
        "id": rule[".id"], "position": position,
        "name": rule.get("comment") or f"Rule {rule['.id']}",
        "chain": rule.get("chain", ""), "action": rule.get("action", ""),
        "source": rule.get("src-address") or rule.get("src-address-list") or "Any",
        "destination": rule.get("dst-address") or rule.get("dst-address-list") or "Any",
        "ports": rule.get("dst-port", ""), "protocol": rule.get("protocol", ""),
        "state": states, "disabled": yes(rule.get("disabled")), "eligible": not reason,
        "reason": reason,
        "selected": not reason and rule.get("action") in {"drop", "reject"},
        "already_logging": yes(rule.get("log")),
        "search_text": " ".join(f"{key}={value}" for key, value in rule.items()),
    }


def make_probe(rule, session, index, new_only=True, source_ip=""):
    reason = eligibility(rule)
    if reason:
        raise ValueError(reason)
    body = {k: str(v) for k, v in rule.items()
            if k not in READONLY and not k.startswith(".") and v not in (None, "")}
    if new_only:
        states = str(rule.get("connection-state", ""))
        if states:
            if "!" in states or "new" not in states.split(","):
                raise ValueError("Does not match new connections mode")
        body["connection-state"] = "new"
    if source_ip:
        host = ipaddress.IPv4Address(source_ip)
        original = str(rule.get("src-address", ""))
        if original:
            negated = original.startswith("!")
            net = ipaddress.IPv4Network(original.lstrip("!"), strict=False)
            inside = host in net
            if inside == negated:
                raise ValueError("Source IP does not match this rule")
        body["src-address"] = f"{host}/32"
    prefix = f"TL{session}_{index:03x}"
    body.update({"action": "log", "log": "no", "log-prefix": prefix,
                 "disabled": "no", "comment": MARKER + session,
                 "place-before": rule[".id"]})
    return prefix, body


def split_endpoint(value):
    value = value.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)\](?::(\d+))?", value)
        if match:
            return match[1], int(match[2]) if match[2] else None
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", value):
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, None


def parse_log(row, probes, router_name):
    message = str(row.get("message", ""))
    matched = next((prefix for prefix in probes
                    if re.search(r"(?<![A-Za-z0-9])" + re.escape(prefix) + r"(?=\s|:|$)", message)), None)
    if not matched:
        return None
    policy = probes[matched]
    interfaces = re.search(r"\bin:(.*?)\sout:(.*?)(?:,\s|$)", message)
    protocol = re.search(r"\bproto\s+(\w+)(?:\s+\(([^)]*)\))?,\s*([^,\s]+)->([^,\s]+)", message)
    if not protocol:
        return {"parse_error": True, "raw": message, "rule_name": policy["name"]}
    source, source_port = split_endpoint(protocol[3])
    destination, destination_port = split_endpoint(protocol[4])
    state = re.search(r"connection-state:([^\s,]+)", message)
    length = re.search(r"\blen\s+(\d+)", message)
    mac = re.search(r"src-mac\s+([0-9a-fA-F:]+)", message)
    return {
        "time": str(row.get("time", "")),
        "received": dt.datetime.now(dt.timezone.utc).isoformat(),
        "router": router_name, "source": source, "source_port": source_port,
        "destination": destination, "destination_port": destination_port,
        "protocol": protocol[1].upper(), "flags": protocol[2] or "",
        "action": policy["action"], "rule_name": policy["name"],
        "rule_id": policy["id"], "rule_position": policy["position"],
        "chain": policy["chain"], "input": interfaces[1] if interfaces else "",
        "output": interfaces[2] if interfaces else "", "state": state[1] if state else "",
        "length": int(length[1]) if length else None, "source_mac": mac[1] if mac else "",
        "raw": message,
    }


def owned_session(row):
    comment = str(row.get("comment", ""))
    for marker in MARKERS:
        if comment.startswith(marker):
            session = comment[len(marker):]
            if SESSION_RE.fullmatch(session):
                return session
    return None


def discover_owned(client):
    return [r for r in records(client.get("ip/firewall/filter"))
            if owned_session(r) and r.get("action") == "log"
            and str(r.get("log-prefix", "")).startswith("TL" + owned_session(r) + "_")]


def cleanup_session(client, session):
    if not SESSION_RE.fullmatch(session):
        raise ValueError("Invalid session ID")
    errors = []
    resources = [
        ("ip/firewall/filter", lambda r: owned_session(r) == session and r.get("action") == "log"
         and str(r.get("log-prefix", "")).startswith("TL" + session + "_")),
        ("system/logging", lambda r: r.get("action") == "tl" + session),
        ("system/logging/action", lambda r: r.get("name") == "tl" + session),
        ("system/scheduler", lambda r: r.get("name") == "tlstop" + session
         and r.get("comment") in {marker + session for marker in MARKERS}),
    ]
    for path, predicate in resources:
        if path == "system/scheduler" and errors:
            continue
        try:
            for row in records(client.get(path)):
                if predicate(row):
                    client.delete(path, row[".id"])
        except RouterError as exc:
            errors.append(str(exc))
    return errors


class Capture:
    def __init__(self, client, router, rules, selected, minutes=15, new_only=True, source_ip="", buffer_lines=DEFAULT_BUFFER_LINES):
        self.client, self.router = client, router
        self.session = secrets.token_hex(5)
        self.buffer = "tl" + self.session
        self.deadline_name = "tlstop" + self.session
        self.minutes = max(1, min(60, int(minutes)))
        self.buffer_lines = bounded_integer(buffer_lines, "Router buffer", 1, MAX_BUFFER_LINES)
        self.new_only, self.source_ip = bool(new_only), source_ip.strip()
        if self.source_ip:
            ipaddress.IPv4Address(self.source_ip)
        self.plan, self.skipped = [], []
        known = {r[".id"]: (i, r) for i, r in enumerate(rules)}
        for rule_id in dict.fromkeys(selected):
            if rule_id not in known:
                raise ValueError("Rule selection is outdated. Reload rules.")
            position, rule = known[rule_id]
            try:
                prefix, body = make_probe(rule, self.session, len(self.plan), self.new_only, self.source_ip)
                self.plan.append((prefix, body, public_rule(rule, position), rule))
            except ValueError as exc:
                self.skipped.append({"name": rule.get("comment", rule_id), "reason": str(exc)})
        if not self.plan:
            raise ValueError("No matching rules selected. Check the selection or capture mode.")
        self.probes = {}
        self.seen = set()
        self.stop_event = threading.Event()
        self.phase, self.message = "starting", "Preparing capture…"
        self.error, self.cleanup_errors = "", []
        self.started = time.time()
        self.expires = self.started + self.minutes * 60
        self.last_heartbeat = time.monotonic()
        self.created_count = 0
        self.parse_errors = 0
        self.buffer_pressure = False
        self.thread = None
        self.deadline_body = None
        self.original_rules = [dict(r) for r in rules if not str(r.get("comment", "")).startswith(MARKERS)]

    def snapshot(self):
        return {"id": self.session, "phase": self.phase, "message": self.message,
                "error": self.error, "cleanup_errors": self.cleanup_errors,
                "started": self.started, "expires": self.expires,
                "probes": self.created_count, "planned": len(self.plan),
                "skipped": self.skipped, "parse_errors": self.parse_errors,
                "buffer_pressure": self.buffer_pressure,
                "buffer_lines": self.buffer_lines,
                "commands": self.commands(), "undo": "\n".join(cleanup_commands(self.session))}

    def deadline_payload(self, clock):
        date = str(clock.get("date", ""))
        fmt = "%Y-%m-%d" if "-" in date else "%b/%d/%Y"
        try:
            now = dt.datetime.strptime(date + " " + clock["time"], fmt + " %H:%M:%S")
        except (ValueError, KeyError):
            raise RouterError("Cannot read the router clock. Auto-stop was not created.") from None
        stop_at = now + dt.timedelta(minutes=self.minutes)
        marker = MARKER + self.session
        cleanup = "; ".join(cleanup_commands(self.session))
        return {
            "name": self.deadline_name, "comment": marker, "interval": "0s",
            "start-date": stop_at.strftime(fmt), "start-time": stop_at.strftime("%H:%M:%S"),
            "policy": "read,write", "on-event": cleanup,
        }

    def resource_plan(self):
        resources = []
        if self.deadline_body:
            resources.append(("system/scheduler", self.deadline_body))
        resources.extend([
            ("system/logging/action", {"name": self.buffer, "target": "memory", "memory-lines": str(self.buffer_lines), "memory-stop-on-full": "no"}),
            ("system/logging", {"action": self.buffer, "topics": "firewall", "regex": "^TL" + self.session + "_"}),
        ])
        resources.extend(("ip/firewall/filter", body) for _, body, _, _ in self.plan)
        return resources

    def commands(self):
        return "\n".join(add_command(path, body) for path, body in self.resource_plan())

    def install_deadline(self):
        self.deadline_body = self.deadline_payload(records(self.client.get("system/clock"))[0])
        self.client.add("system/scheduler", self.deadline_body)

    def prepare(self):
        self.install_deadline()
        self.client.add("system/logging/action", {
            "name": self.buffer, "target": "memory", "memory-lines": str(self.buffer_lines),
            "memory-stop-on-full": "no",
        })
        self.client.add("system/logging", {
            "action": self.buffer, "topics": "firewall", "regex": "^TL" + self.session + "_",
        })
        live = {r[".id"]: r for r in records(self.client.get("ip/firewall/filter"))}
        for prefix, body, policy, original in self.plan:
            if self.stop_event.is_set():
                return
            if time.time() >= self.expires:
                raise RouterError("Time limit reached during setup.")
            current = live.get(original[".id"])
            comparable = lambda r: {k: v for k, v in r.items() if k not in {"bytes", "packets"}}
            if current is None or comparable(current) != comparable(original):
                raise RouterError("Firewall changed during setup. Reload rules.")
            self.message = f"Creating log rule {self.created_count + 1} of {len(self.plan)}…"
            self.client.add("ip/firewall/filter", body)
            self.probes[prefix] = policy
            self.created_count += 1

    def run(self, emit):
        try:
            self.prepare()
            if self.stop_event.is_set():
                return
            self.phase, self.message = "running", "Capture running"
            failures = 0
            last_policy_check = time.monotonic()
            while not self.stop_event.is_set():
                if time.time() >= self.expires:
                    self.message = "Time limit reached"
                    break
                if time.monotonic() - self.last_heartbeat > 30:
                    self.message = "Browser closed or disconnected"
                    break
                try:
                    if time.monotonic() - last_policy_check >= 5:
                        current = [r for r in records(self.client.get("ip/firewall/filter"))
                                   if not str(r.get("comment", "")).startswith(MARKERS)]
                        fingerprint = lambda rows: [{k: v for k, v in r.items()
                                                     if k not in {"bytes", "packets"}} for r in rows]
                        if fingerprint(current) != fingerprint(self.original_rules):
                            raise ValueError("Firewall rules changed. Capture stopped; reload rules.")
                        last_policy_check = time.monotonic()
                    rows = self.client.logs(self.buffer)
                    failures = 0
                    self.message = "Capture running"
                    fresh = [r for r in rows if r.get(".id") not in self.seen]
                    self.buffer_pressure = (len(rows) >= self.buffer_lines * 0.975
                                            and len(fresh) > self.buffer_lines * 0.5)
                    for row in fresh:
                        self.seen.add(row.get(".id"))
                        event = parse_log(row, self.probes, self.router)
                        if event and event.get("parse_error"):
                            self.parse_errors += 1
                        elif event:
                            emit(event)
                    self.seen.intersection_update(r.get(".id") for r in rows)
                except RouterError as exc:
                    failures += 1
                    self.message = f"Reconnecting ({failures}/3)…"
                    if failures >= 3:
                        raise exc
                self.stop_event.wait(1)
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.phase, self.message = "stopping", "Removing temporary rules…"
            try:
                self.cleanup_errors = cleanup_session(self.client, self.session)
            except Exception as exc:
                self.cleanup_errors = [str(exc)]
            if self.cleanup_errors:
                self.phase = "cleanup_required"
                self.message = "Cleanup incomplete. Reconnect and open Router changes."
            elif self.error:
                self.phase, self.message = "error", self.error
            else:
                self.phase, self.message = "stopped", "Capture stopped; temporary rules removed"

    def start(self, emit):
        self.thread = threading.Thread(target=self.run, args=(emit,), daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
