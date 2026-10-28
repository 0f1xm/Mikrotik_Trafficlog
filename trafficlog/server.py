from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .capture import Capture, MARKERS, SESSION_RE, cleanup_commands, cleanup_session, discover_owned, owned_session, public_rule, records
from .network import connection_defaults
from .router import RouterClient, RouterError
from .storage import (EventStore, bounded_integer, DEFAULT_BUFFER_LINES, MAX_BUFFER_LINES,
                      DEFAULT_EVENT_LIMIT, MAX_EVENT_LIMIT, DEFAULT_MEMORY_MIB, MAX_MEMORY_MIB)

WEB = Path(__file__).resolve().parent / "web"
ACTIVE = {"starting", "running", "stopping"}


class Application:
    def __init__(self):
        self.lock = threading.RLock()
        self.control_lock = threading.RLock()
        self.client = None
        self.router = None
        self.rules = []
        self.capture = None
        self.pending_capture = None
        self.pending_options = None
        self.events = EventStore()
        self.sequence = 0
        self.token = secrets.token_urlsafe(32)
        self.notice = ""
        self.cleanup_markers = {}

    def emit(self, event):
        with self.lock:
            self.sequence += 1
            self.events.append(dict(event, sequence=self.sequence))

    def active(self):
        return bool(self.capture and self.capture.phase in ACTIVE)

    def connect(self, payload):
        with self.lock:
            if self.active():
                raise ValueError("Stop capture first.")
            if self.capture and self.capture.cleanup_errors:
                raise ValueError("Clean up the previous capture in Router changes first.")
        client = RouterClient(payload.get("address", ""), payload.get("username", ""),
                              payload.get("password", ""), payload.get("verify_tls", True),
                              payload.get("allow_http", True))
        try:
            identity = records(client.get("system/identity"))[0]
            resource = records(client.get("system/resource"))[0]
            rules = records(client.get("ip/firewall/filter"))
        except Exception:
            client.forget()
            raise
        with self.lock:
            if self.client:
                self.client.forget()
            self.client = client
            self.router = {"name": identity.get("name", "Router"), "address": client.address,
                           "version": resource.get("version", ""),
                           "model": resource.get("board-name", "")}
            self.rules = rules
            self.capture = None
            self.pending_capture = self.pending_options = None
            self.events.clear()
            self.notice = ""
        return self.state()

    def refresh_rules(self):
        if not self.client:
            raise ValueError("Connect to a router first.")
        if self.active():
            raise ValueError("Stop capture before reloading rules.")
        rules = records(self.client.get("ip/firewall/filter"))
        with self.lock:
            self.rules = rules
        return self.state()

    def start(self, payload):
        with self.lock:
            if self.active():
                raise ValueError("A capture is already running.")
            if not self.client:
                raise ValueError("Connect to a router first.")
            if self.capture and self.capture.cleanup_errors:
                raise ValueError("Clean up the previous capture first.")
            if self.orphans():
                raise ValueError("A previous capture needs cleanup. Open Router changes.")
            if payload.get("plan_id"):
                capture = self.pending_capture
                if (not capture or capture.session != payload["plan_id"]
                        or self.pending_options != self.capture_options(payload)):
                    raise ValueError("Refresh the command preview.")
                capture.started = time.time()
                capture.expires = capture.started + capture.minutes * 60
                capture.last_heartbeat = time.monotonic()
            else:
                capture = self.make_capture(payload)
            self.pending_capture = self.pending_options = None
            self.capture = capture
            options = self.capture_options(payload)
            self.events = EventStore(options["event_limit"], options["memory_mib"])
            capture.start(self.emit)
        return {"ok": True}

    @staticmethod
    def capture_options(payload):
        options = {key: payload.get(key, default) for key, default in
                   [("rules", []), ("minutes", 15), ("new_only", True), ("source_ip", ""),
                    ("buffer_lines", DEFAULT_BUFFER_LINES), ("event_limit", DEFAULT_EVENT_LIMIT),
                    ("memory_mib", DEFAULT_MEMORY_MIB)]}
        for key, label, minimum, maximum in [("buffer_lines", "Router buffer", 1, MAX_BUFFER_LINES),
                                             ("event_limit", "Local event limit", 1, MAX_EVENT_LIMIT),
                                             ("memory_mib", "Event memory", 16, MAX_MEMORY_MIB)]:
            bounded_integer(options[key], label, minimum, maximum)
        return options

    def make_capture(self, payload):
        options = self.capture_options(payload)
        return Capture(self.client, self.router["name"], self.rules,
                       options["rules"], options["minutes"], options["new_only"], options["source_ip"], options["buffer_lines"])

    def preview(self, payload):
        if self.active():
            raise ValueError("A capture is already running.")
        if not self.router:
            raise ValueError("Connect router.")
        capture = self.make_capture(payload)
        capture.deadline_body = capture.deadline_payload(records(self.client.get("system/clock"))[0])
        with self.lock:
            self.pending_capture = capture
            self.pending_options = self.capture_options(payload)
        return {"plan_id": capture.session, **capture.snapshot()}

    def stop(self):
        with self.lock:
            if self.capture:
                self.capture.stop()
        return {"ok": True}

    def disconnect(self):
        if self.active():
            raise ValueError("Stop capture and wait for cleanup first.")
        with self.lock:
            if self.capture and self.capture.cleanup_errors:
                raise ValueError("Cleanup incomplete. Open Router changes.")
            if self.client:
                self.client.forget()
            self.client = self.router = self.capture = None
            self.rules = []
        return {"ok": True}

    def orphans(self):
        if not self.client:
            return []
        self.cleanup_markers = {}
        for row in discover_owned(self.client):
            session = owned_session(row)
            self.cleanup_markers[session] = row["comment"][:-len(session)]
        for row in records(self.client.get("system/scheduler")):
            name = str(row.get("name", ""))
            if name.startswith("tlstop") and SESSION_RE.fullmatch(name[6:]):
                for marker in MARKERS:
                    if row.get("comment") == marker + name[6:]:
                        self.cleanup_markers[name[6:]] = marker
        return sorted(self.cleanup_markers)

    def cleanup(self, payload):
        if self.active():
            raise ValueError("Stop capture first.")
        if not self.client:
            raise ValueError("Connect to a router first.")
        found = self.orphans()
        requested = payload.get("sessions", found)
        if not isinstance(requested, list) or any(s not in found for s in requested):
            raise ValueError("Unknown capture session.")
        errors = []
        for session in requested:
            errors.extend(cleanup_session(self.client, session))
        if errors:
            raise RouterError("Cleanup incomplete: " + "; ".join(errors))
        if self.capture:
            self.capture.cleanup_errors = []
            self.capture.phase = "stopped"
            self.capture.message = "Temporary rules removed"
        self.rules = records(self.client.get("ip/firewall/filter"))
        return {"ok": True, "removed_sessions": len(requested)}

    def state(self, since=0, heartbeat=True):
        with self.lock:
            if heartbeat and self.capture:
                self.capture.last_heartbeat = time.monotonic()
            session = self.capture.snapshot() if self.capture else None
            events = self.events.batch(since, self.sequence)
            cursor = events[-1]["sequence"] if events else self.sequence
            return {"router": self.router,
                    "rules": [public_rule(r, i) for i, r in enumerate(self.rules)
                              if not r.get("comment", "").startswith(MARKERS)],
                    "session": session,
                    "events": events, "sequence": cursor, "has_more": cursor < self.sequence,
                    "retained_from": self.events.oldest(self.sequence + 1),
                    "retained": len(self.events), "storage": self.events.snapshot(),
                    "notice": self.notice}

    def close(self):
        self.stop()
        if self.capture and self.capture.thread:
            self.capture.thread.join(timeout=40)
        if self.client:
            self.client.forget()


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app):
        super().__init__(address, Handler)
        self.app = app


class Handler(BaseHTTPRequestHandler):
    server_version = "MikrotikTrafficlog"

    def log_message(self, format, *args):
        pass

    def allowed_host(self):
        return self.headers.get("Host", "") in {
            f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}

    def reply(self, status, content, content_type="application/json; charset=utf-8"):
        if isinstance(content, (dict, list)):
            content = json.dumps(content, ensure_ascii=False).encode("utf-8")
        elif isinstance(content, str):
            content = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if not self.allowed_host():
            return self.reply(403, {"error": "Invalid host"})
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        app = self.server.app
        if path == "/api/bootstrap":
            return self.reply(200, {"token": app.token, "version": "0.3.0", **connection_defaults()})
        if path == "/api/defaults":
            return self.reply(200, connection_defaults())
        if path == "/api/state":
            try:
                since = max(0, int(urllib.parse.parse_qs(parsed.query).get("since", ["0"])[0]))
            except ValueError:
                return self.reply(400, {"error": "Invalid cursor"})
            return self.reply(200, app.state(since))
        if path in {"/", "/index.html", "/app.js", "/filters.mjs", "/events.mjs", "/styles.css"}:
            file = WEB / ("index.html" if path == "/" else path[1:])
            mime = {".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css"}[file.suffix]
            return self.reply(200, file.read_bytes(), mime + "; charset=utf-8")
        return self.reply(404, {"error": "Not found"})

    def do_POST(self):
        with self.server.app.control_lock:
            self.handle_post()

    def handle_post(self):
        if not self.allowed_host():
            return self.reply(403, {"error": "Invalid host"})
        app = self.server.app
        allowed_origins = {f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"}
        if (self.headers.get("X-Local-Token") != app.token
                or self.headers.get("Origin", next(iter(allowed_origins))) not in allowed_origins):
            return self.reply(403, {"error": "Invalid local request"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 65536:
                return self.reply(413, {"error": "Request too large"})
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("Invalid request")
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/connect":
                result = app.connect(payload)
            elif path == "/api/disconnect":
                result = app.disconnect()
            elif path == "/api/rules/refresh":
                result = app.refresh_rules()
            elif path == "/api/capture/start":
                result = app.start(payload)
            elif path == "/api/capture/preview":
                result = app.preview(payload)
            elif path == "/api/capture/stop":
                result = app.stop()
            elif path == "/api/events/clear":
                with app.lock:
                    app.events.clear()
                result = {"ok": True}
            elif path == "/api/sessions/find":
                sessions = app.orphans()
                result = {"sessions": sessions, "cleanup": [
                    {"id": session, "undo": "\n".join(cleanup_commands(session, app.cleanup_markers[session]))} for session in sessions]}
            elif path == "/api/sessions/cleanup":
                result = app.cleanup(payload)
            elif path == "/api/shutdown":
                result = {"ok": True}
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                return self.reply(404, {"error": "Not found"})
            return self.reply(200, result)
        except (ValueError, RouterError) as exc:
            return self.reply(400, {"error": str(exc)})
        except Exception:
            return self.reply(500, {"error": "Unexpected error. Restart the application and check the router connection."})
