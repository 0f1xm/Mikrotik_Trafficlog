import base64
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from trafficlog.router import RouterClient, RouterError


class KeepAliveServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, context=None):
        self.context = context
        self.connections = 0
        self.requests = []
        self.writes = 0
        self.redirect_url = ""
        self.state_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), KeepAliveHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        if self.context:
            try:
                connection = self.context.wrap_socket(connection, server_side=True)
            except OSError:
                connection.close()
                raise
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with self.state_lock:
            self.connections += 1
        return connection, address


class KeepAliveHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass

    def log_message(self, *args):
        pass

    def record(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with self.server.state_lock:
            self.server.requests.append((self.command, self.path, self.headers.get("Authorization"), body))

    def reply(self, value=None, status=200, headers=None, raw=None):
        raw = json.dumps(value).encode() if raw is None else raw
        if status == 204:
            raw = b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(raw)
            self.wfile.flush()
        except OSError:
            pass

    def do_GET(self):
        self.record()
        if self.path == "/rest/close":
            self.reply({"ok": True}, headers={"Connection": "close"})
            self.close_connection = True
        elif self.path == "/rest/stale":
            self.reply({"ok": True})
            self.close_connection = True
        elif self.path == "/rest/error":
            self.reply({"detail": "test failure"}, status=400)
        elif self.path == "/rest/unauthorized":
            self.reply({}, status=401)
        elif self.path == "/rest/redirect":
            self.reply({}, status=302, headers={"Location": self.server.redirect_url})
        elif self.path == "/rest/invalid":
            self.reply(raw=b"not json")
        elif self.path == "/rest/large":
            self.reply(raw=b'"' + b"x" * 128 + b'"')
        else:
            self.reply({"ok": True})

    def do_PUT(self):
        self.record()
        self.server.writes += 1
        if self.path == "/rest/lost":
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
        else:
            self.reply({".id": "*" + str(self.server.writes)}, status=201)

    def do_POST(self):
        self.record()
        self.reply(getattr(self.server,"log_rows",[]))

    def do_DELETE(self):
        self.record()
        self.reply(status=204)


class RouterTestCase(unittest.TestCase):
    def start_server(self, context=None):
        server = KeepAliveServer(context)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.addCleanup(close)
        return server

    def client(self, server, **options):
        scheme = "https" if server.context else "http"
        client = RouterClient(f"{scheme}://127.0.0.1:{server.server_port}", "test", "test", **options)
        self.addCleanup(client.forget)
        return client


class ConnectionTests(RouterTestCase):
    def setUp(self):
        self.server = self.start_server()
        self.router = self.client(self.server)

    def test_large_log_buffers_use_a_separate_bounded_response_limit(self):
        self.server.log_rows=[{".id":str(i),"message":"x"*250} for i in range(20000)]
        self.assertGreater(len(json.dumps(self.server.log_rows)),4*1024*1024)
        self.assertEqual(len(self.router.logs("tlabcdef1234")),20000)
        with patch("trafficlog.router.MAX_LOG_RESPONSE_SIZE",1024):
            with self.assertRaisesRegex(RouterError,"too large"):
                self.router.logs("tlabcdef1234")
        self.assertIsNone(self.router._connection)

    def test_rules_reads_logs_and_delete_reuse_one_connection(self):
        for index in range(20):
            self.assertEqual(self.router.add("ip/firewall/filter", {"comment": str(index)})[".id"], "*" + str(index + 1))
        self.assertEqual(self.router.get("read"), {"ok": True})
        self.assertEqual(self.router.logs("tlabcdef1234"), [])
        self.router.delete("ip/firewall/filter", "*AB")
        self.assertEqual(self.server.connections, 1)
        self.assertEqual(len(self.server.requests), 23)
        self.assertEqual(self.server.requests[-1][1], "/rest/ip/firewall/filter/*AB")
        self.assertTrue(all(row[2] == "Basic " + base64.b64encode(b"test:test").decode() for row in self.server.requests))

    def test_server_requested_close_reconnects_before_next_write(self):
        self.router.get("close")
        self.router.add("create", {})
        self.assertEqual(self.server.connections, 2)
        self.assertEqual(self.server.writes, 1)

    def test_stale_connection_recovers_for_reads(self):
        self.router.get("stale")
        self.assertEqual(self.router.get("read"), {"ok": True})
        self.assertEqual(self.server.connections, 2)

    def test_log_print_can_recover_from_a_stale_connection(self):
        self.router.get("stale")
        self.assertEqual(self.router.logs("tlabcdef1234"), [])
        self.assertEqual(self.server.connections, 2)
        self.assertEqual(sum(row[0] == "POST" for row in self.server.requests), 1)

    def test_lost_write_response_never_repeats_the_write(self):
        self.router.get("read")
        with self.assertRaises(RouterError):
            self.router.add("lost", {"comment": "once"})
        self.assertEqual(self.server.writes, 1)
        self.assertEqual(self.router.get("read"), {"ok": True})
        self.assertEqual(self.server.writes, 1)

    def test_concurrent_callers_share_a_serialized_connection(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: self.router.get("read"), range(20)))
        self.assertEqual(results, [{"ok": True}] * 20)
        self.assertEqual(self.server.connections, 1)

    def test_http_errors_are_consumed_before_reusing_the_connection(self):
        with self.assertRaises(RouterError) as error:
            self.router.get("error")
        self.assertEqual(error.exception.status, 400)
        self.assertIn("test failure", str(error.exception))
        self.assertEqual(self.router.get("read"), {"ok": True})
        self.assertEqual(self.server.connections, 1)

    def test_credentials_are_not_forwarded_to_redirects(self):
        other = self.start_server()
        self.server.redirect_url = f"http://127.0.0.1:{other.server_port}/rest/read"
        with self.assertRaises(RouterError) as error:
            self.router.get("redirect")
        self.assertEqual(error.exception.status, 302)
        self.assertEqual(other.requests, [])
        self.assertEqual(other.connections, 0)

    def test_invalid_json_does_not_break_response_framing(self):
        with self.assertRaisesRegex(RouterError, "not REST JSON"):
            self.router.get("invalid")
        self.assertEqual(self.router.get("read"), {"ok": True})
        self.assertEqual(self.server.connections, 1)

    def test_oversized_response_discards_the_connection(self):
        with patch("trafficlog.router.MAX_RESPONSE_SIZE", 16):
            with self.assertRaisesRegex(RouterError, "too large"):
                self.router.get("large")
            self.assertEqual(self.router.get("read"), {"ok": True})
        self.assertEqual(self.server.connections, 2)

    def test_forget_closes_the_connection_and_blocks_further_requests(self):
        self.router.get("read")
        connection = self.router._connection
        self.router.forget()
        self.assertIsNone(connection.sock)
        self.assertIsNone(self.router._connection)
        with self.assertRaisesRegex(RouterError, "session is closed"):
            self.router.get("read")
        self.assertEqual(len(self.server.requests), 1)

    def test_invalid_addresses_are_rejected(self):
        for address in ["http://127.0.0.1:bad", "http://127.0.0.1:99999", "http://user:pass@127.0.0.1", "http://127.0.0.1/elsewhere"]:
            with self.subTest(address=address), self.assertRaises(RouterError):
                RouterClient(address, "test", "test")


class TLSConnectionTests(RouterTestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which("openssl")
        if not openssl:
            candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/usr/bin/openssl.exe"
            openssl = str(candidate) if candidate.is_file() else None
        if not openssl:
            raise unittest.SkipTest("OpenSSL is needed to generate the temporary test certificate.")
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cert = str(Path(cls.directory.name) / "cert.pem")
        cls.key = str(Path(cls.directory.name) / "key.pem")
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
            "-keyout", cls.key, "-out", cls.cert, "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
            "-addext", "extendedKeyUsage=serverAuth",
        ], check=True, capture_output=True, timeout=20, **options)

    def setUp(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server = self.start_server(context)

    def test_twenty_rule_creates_use_one_tls_handshake(self):
        router = self.client(self.server, verify_tls=False)
        for index in range(20):
            router.add("ip/firewall/filter", {"comment": str(index)})
        self.assertEqual(router.get("read"), {"ok": True})
        self.assertEqual(self.server.writes, 20)
        self.assertEqual(self.server.connections, 1)
        self.assertEqual(len(self.server.requests), 21)

    def test_untrusted_certificate_is_rejected_by_default(self):
        router = self.client(self.server)
        with self.assertRaisesRegex(RouterError, "Untrusted certificate"):
            router.get("read")
        self.assertEqual(self.server.requests, [])
        self.assertIsNone(router._connection)

    def test_trusted_certificate_keeps_verification_and_connection_reuse(self):
        trusted = ssl.create_default_context(cafile=self.cert)
        with patch("trafficlog.router.ssl.create_default_context", return_value=trusted):
            router = self.client(self.server)
        self.assertTrue(router._context.check_hostname)
        self.assertEqual(router._context.verify_mode, ssl.CERT_REQUIRED)
        router.get("read")
        router.get("read")
        self.assertEqual(self.server.connections, 1)

    def test_tls_reads_reconnect_when_the_server_closes_an_idle_connection(self):
        router = self.client(self.server, verify_tls=False)
        router.get("stale")
        self.assertEqual(router.get("read"), {"ok": True})
        self.assertEqual(self.server.connections, 2)
