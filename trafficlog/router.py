from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


class RouterError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RouterClient:
    def __init__(self, address: str, username: str, password: str,
                 verify_tls: bool = True, allow_http: bool = True):
        address = address.strip().rstrip("/")
        if "://" not in address:
            address = "http://" + address
        parsed = urllib.parse.urlsplit(address)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
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
        context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context))

    def request(self, method: str, path: str, body=None, query=None):
        path = "/".join(urllib.parse.quote(part, safe="*") for part in path.strip("/").split("/"))
        url = self.address + "/rest/" + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": self._authorization,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "MikrotikTrafficlog/0.3",
        })
        try:
            with self._opener.open(request, timeout=7) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise RouterError("Router response is too large.")
                return json.loads(raw) if raw.strip() else None
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                obj = json.loads(exc.read(8192))
                detail = str(obj.get("detail") or obj.get("message") or "")[:500]
            except (ValueError, OSError):
                pass
            if exc.code == 401:
                raise RouterError("Login rejected. Check credentials and REST permissions.", 401) from None
            if exc.code == 403:
                raise RouterError("Router denied the operation. Check write permissions.", 403) from None
            if exc.code == 404:
                raise RouterError("REST resource not found. Check RouterOS and the web service. " + detail, 404) from None
            raise RouterError(f"Router returned HTTP {exc.code}: {detail}", exc.code) from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise RouterError("Untrusted certificate. Install the CA or disable verification in connection settings.") from None
            raise RouterError("Router unreachable. Check the address and web service: " + str(exc.reason)[:250]) from None
        except (TimeoutError, OSError) as exc:
            raise RouterError("Router connection interrupted: " + str(exc)[:250]) from None
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
        self._authorization = ""
