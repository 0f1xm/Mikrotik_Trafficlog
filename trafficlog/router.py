from __future__ import annotations

import base64
import http.client
import json
import ssl
import threading
import urllib.parse

MAX_RESPONSE_SIZE = 4 * 1024 * 1024


class RouterError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class RouterClient:
    def __init__(self, address: str, username: str, password: str,
                 verify_tls: bool = True, allow_http: bool = True):
        address = address.strip().rstrip("/")
        if "://" not in address:
            address = "http://" + address
        try:
            parsed = urllib.parse.urlsplit(address)
            self._host, self._port = parsed.hostname, parsed.port
        except ValueError:
            raise RouterError("Invalid router address.") from None
        if (parsed.scheme not in {"http", "https"} or not self._host
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path.rstrip("/") not in {"", "/rest"}):
            raise RouterError("Invalid router address.")
        if parsed.scheme == "http" and not allow_http:
            raise RouterError("HTTP is disabled for this connection.")
        if not username or not password:
            raise RouterError("Username and password are required.")
        self.address = f"{parsed.scheme}://{parsed.netloc}"
        self.username = username
        self._authorization = "Basic " + base64.b64encode(
            f"{username}:{password}".encode("utf-8")).decode("ascii")
        self._scheme = parsed.scheme
        self._context = None
        if self._scheme == "https":
            self._context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
            self._context.set_alpn_protocols(["http/1.1"])
        self._connection = None
        self._lock = threading.RLock()

    def _new_connection(self):
        if self._scheme == "https":
            return http.client.HTTPSConnection(self._host, self._port, timeout=7, context=self._context)
        return http.client.HTTPConnection(self._host, self._port, timeout=7)

    def _close_connection(self):
        connection, self._connection = self._connection, None
        if connection:
            connection.close()

    def _exchange(self, method, path, data):
        if self._connection is None:
            self._connection = self._new_connection()
        self._connection.request(method, path, body=data, headers={
            "Authorization": self._authorization,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "keep-alive",
            "User-Agent": "MikrotikTrafficlog/0.3",
        })
        with self._connection.getresponse() as response:
            raw = response.read(MAX_RESPONSE_SIZE + 1)
            if len(raw) > MAX_RESPONSE_SIZE:
                self._close_connection()
                raise RouterError("Router response is too large.")
            status, reason = response.status, response.reason
            if response.will_close:
                self._close_connection()
        return status, reason, raw

    @staticmethod
    def _http_error(status, reason, raw):
        detail = ""
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                detail = str(obj.get("detail") or obj.get("message") or "")[:500]
        except ValueError:
            pass
        if status == 401:
            return RouterError("Login rejected. Check credentials and REST permissions.", status)
        if status == 403:
            return RouterError("Router denied the operation. Check write permissions.", status)
        if status == 404:
            return RouterError("REST resource not found. Check RouterOS and the web service. " + detail, status)
        return RouterError(f"Router returned HTTP {status}: {detail or reason}", status)

    def request(self, method: str, path: str, body=None, query=None):
        path = "/rest/" + "/".join(urllib.parse.quote(part, safe="*")
                                  for part in path.strip("/").split("/"))
        read_only = method == "GET" or (method == "POST" and path == "/rest/log/print")
        if query:
            path += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode("utf-8")
        with self._lock:
            if not self._authorization:
                raise RouterError("Router session is closed.")
            for attempt in range(2):
                reused = self._connection is not None and self._connection.sock is not None
                try:
                    status, reason, raw = self._exchange(method, path, data)
                    break
                except ssl.SSLCertVerificationError:
                    self._close_connection()
                    raise RouterError("Untrusted certificate. Install the CA or disable verification in connection settings.") from None
                except (http.client.HTTPException, OSError) as exc:
                    self._close_connection()
                    # A write may have reached the router even if its response was lost.
                    if read_only and reused and attempt == 0:
                        continue
                    raise RouterError("Router connection interrupted: " + str(exc)[:250]) from None
            if not 200 <= status < 300:
                raise self._http_error(status, reason, raw)
            try:
                return json.loads(raw) if raw.strip() else None
            except ValueError:
                raise RouterError("Response is not REST JSON. Check the router address and web service.") from None

    def get(self, path: str, query=None):
        return self.request("GET", path, query=query)

    def add(self, path: str, body: dict):
        result = self.request("PUT", path, body)
        if isinstance(result, list):
            result = result[0] if result else {}
        if not isinstance(result, dict) or not result.get(".id"):
            raise RouterError("Router returned no ID for the created resource.")
        return result

    def delete(self, path: str, resource_id: str):
        try:
            self.request("DELETE", path + "/" + resource_id)
        except RouterError as exc:
            if exc.status != 404:
                raise

    def logs(self, buffer: str):
        return self.request("POST", "log/print", {
            ".proplist": [".id", "time", "topics", "message", "buffer"],
            ".query": ["buffer=" + buffer],
        }) or []

    def forget(self):
        with self._lock:
            self._authorization = ""
            self._close_connection()
