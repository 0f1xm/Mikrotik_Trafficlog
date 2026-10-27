import json
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import urllib.error
import urllib.request

from trafficlog.server import Application, LocalServer


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.app=Application()
        self.server=LocalServer(("127.0.0.1",0),self.app)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.url=f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.app.close();self.server.shutdown();self.server.server_close()

    def request(self,path,body=None,token=True,origin=None):
        headers={"Content-Type":"application/json"}
        if token:headers["X-Local-Token"]=self.app.token
        if origin:headers["Origin"]=origin
        req=urllib.request.Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
        return urllib.request.urlopen(req)

    def test_requires_local_token_and_origin(self):
        for token,origin in [(False,None),(True,"https://example.com")]:
            with self.subTest(token=token,origin=origin),self.assertRaises(urllib.error.HTTPError) as caught:
                self.request("/api/capture/start",{},token,origin)
            self.assertEqual(caught.exception.code,403)
        self.assertIsNone(self.app.router)

    def test_events_are_incremental(self):
        with self.request("/api/state") as response:
            self.assertFalse(json.load(response)["events"])
        self.app.emit({"source":"192.0.2.1"})
        cursor=self.app.sequence
        self.app.emit({"source":"192.0.2.2"})
        with self.request(f"/api/state?since={cursor}") as response:
            self.assertEqual([event["source"] for event in json.load(response)["events"]],["192.0.2.2"])
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request("/api/demo",{})
        self.assertEqual(caught.exception.code,404)

    def test_credentials_not_returned_and_static_paths_bounded(self):
        with self.request("/api/bootstrap") as response:
            result=json.load(response)
        self.assertNotIn("password",result)
        with self.assertRaises(urllib.error.HTTPError):
            self.request("/../run.py")
        with self.request("/") as response:
            self.assertIn("frame-ancestors 'none'",response.headers["Content-Security-Policy"])
            self.assertIn(b"MikroTik Traffic Log",response.read())

    def test_incomplete_cleanup_cannot_be_discarded_by_switching_connections(self):
        self.app.capture=SimpleNamespace(phase="cleanup_required",cleanup_errors=["offline"])
        for path in ["/api/connect","/api/disconnect"]:
            with self.subTest(path=path),self.assertRaises(urllib.error.HTTPError) as caught:
                self.request(path,{})
            self.assertEqual(caught.exception.code,400)
        self.app.capture=None

    def test_defaults_endpoint_uses_current_gateway(self):
        with patch("trafficlog.server.connection_defaults", return_value={"gateway":"10.0.4.254","address":"http://10.0.4.254"}):
            with self.request("/api/defaults") as response:
                self.assertEqual(json.load(response)["address"], "http://10.0.4.254")

    def test_preview_is_read_only_and_start_uses_reviewed_session_id(self):
        self.app.client=Mock()
        self.app.client.get.return_value={"date":"2026-10-27","time":"14:00:00"}
        self.app.router={"name":"Test", "address":"http://10.0.4.254"}
        self.app.rules=[{".id":"*A","action":"drop","chain":"input","comment":"Drop"}]
        options={"rules":["*A"],"minutes":15,"new_only":True,"source_ip":""}
        with self.request("/api/capture/preview",options) as response:
            preview=json.load(response)
        self.app.client.add.assert_not_called()
        self.app.client.delete.assert_not_called()
        self.assertIn("/system scheduler add",preview["commands"])
        self.assertIn(preview["plan_id"],preview["undo"])
        with patch.object(self.app,"orphans",return_value=[]),patch("trafficlog.capture.Capture.start"):
            with self.assertRaises(urllib.error.HTTPError):
                self.request("/api/capture/start",dict(options,plan_id=preview["plan_id"],minutes=30))
            with self.request("/api/capture/start",dict(options,plan_id=preview["plan_id"])) as response:
                self.assertTrue(json.load(response)["ok"])
        self.assertEqual(self.app.capture.session,preview["plan_id"])


if __name__ == "__main__":
    unittest.main()
