import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from trafficlog.capture import Capture, MARKER, add_command, cleanup_commands, cleanup_session, make_probe, parse_log
from trafficlog.router import RouterClient, RouterError


def policy(**kwargs):
    return dict({".id": "*AB", "chain": "forward", "action": "drop",
                 "comment": "Block cameras to LAN", "disabled": "false",
                 "in-interface": "VLAN Cams", "src-address": "10.0.5.0/24",
                 "log": "false", "log-prefix": "original"}, **kwargs)


class FakeRouter:
    def __init__(self, rules, failure=None):
        self.tables = {"ip/firewall/filter": copy.deepcopy(rules), "system/scheduler": [],
                       "system/logging": [], "system/logging/action": []}
        self.original = copy.deepcopy(rules)
        self.operations = []
        self.next_id = 100
        self.failure = failure
        self.capture = None

    def get(self, path, query=None):
        if path == "system/clock":
            return {"date": "2026-10-27", "time": "23:55:00"}
        return copy.deepcopy(self.tables[path])

    def add(self, path, body):
        self.operations.append(("add", path, copy.deepcopy(body)))
        self.next_id += 1
        row = dict(body, **{".id": "*" + str(self.next_id)})
        self.tables[path].append(row)
        if self.failure == "lost-response" and path == "ip/firewall/filter":
            # The router created the resource, but the HTTP response was lost.
            raise RouterError("lost response")
        return copy.deepcopy(row)

    def delete(self, path, resource_id):
        self.operations.append(("delete", path, resource_id))
        if self.failure == "cleanup" and path == "ip/firewall/filter":
            raise RouterError("temporary network error")
        self.tables[path] = [r for r in self.tables[path] if r[".id"] != resource_id]

    def logs(self, buffer):
        prefix = next(iter(self.capture.probes))
        return [{".id": "*L1", "time": "2026-10-27 09:00:00", "message":
                 f"{prefix} forward: in:VLAN Cams out:Bridge Bude, connection-state:new src-mac 02:03:04:05:06:07, proto TCP (SYN), 10.0.5.100:51000->10.0.1.24:445, len 60"}]


class CaptureTests(unittest.TestCase):
    def test_probe_preserves_policy_and_cannot_accept_or_drop(self):
        original = policy(**{"dst-address-list": "internal", "reject-with": "tcp-reset"})
        before = copy.deepcopy(original)
        prefix, body = make_probe(original, "abcdef1234", 2, True, "10.0.5.100")
        self.assertEqual(original, before)
        self.assertEqual(body["action"], "log")
        self.assertEqual(body["place-before"], "*AB")
        self.assertEqual(body["src-address"], "10.0.5.100/32")
        self.assertEqual(body["dst-address-list"], "internal")
        self.assertEqual(body["connection-state"], "new")
        self.assertEqual(body["log"], "no")
        self.assertNotIn("reject-with", body)
        self.assertLessEqual(len(prefix), 20)

    def test_source_restriction_never_broadens_original(self):
        for rule, address in [(policy(), "10.0.1.24"),
                              (policy(**{"src-address": "!10.0.5.0/24"}), "10.0.5.100")]:
            with self.assertRaises(ValueError):
                make_probe(rule, "abcdef1234", 0, True, address)

    def test_skip_independently_stateful_matchers(self):
        for matcher in ["limit", "dst-limit", "nth", "random", "psd", "connection-rate"]:
            with self.subTest(matcher=matcher), self.assertRaises(ValueError):
                make_probe(policy(**{matcher: "1"}), "abcdef1234", 0)
        with self.assertRaises(ValueError):
            make_probe(policy(**{"connection-state": "established,related"}), "abcdef1234", 0)

    def test_parser_full_names_interfaces_and_nat(self):
        probes = {"TLabcdef1234_000": {"id": "*AB", "position": 56, "action": "drop",
                  "name": 'VLAN Cams → LAN "gesperrt"', "chain": "forward"}}
        row = {"time": "09:05:00", "message": "TLabcdef1234_000 forward: in:VLAN Cams out:Bridge Bude, connection-state:new src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 10.0.5.100:51234->10.0.1.24:445, NAT 1.1.1.1:1->2.2.2.2:2, len 60"}
        event = parse_log(row, probes, "SG7")
        self.assertEqual((event["source"], event["destination"], event["destination_port"]), ("10.0.5.100", "10.0.1.24", 445))
        self.assertEqual(event["input"], "VLAN Cams")
        self.assertEqual(event["rule_name"], probes["TLabcdef1234_000"]["name"])
        self.assertEqual(event["action"], "drop")
        self.assertIsNone(parse_log({"message": "unrelated connection"}, probes, "SG7"))

    def test_icmp_has_no_fake_ports(self):
        probes = {"TLabcdef1234_000": {"id":"*1","position":1,"action":"accept","name":"ICMP","chain":"input"}}
        event = parse_log({"message":"TLabcdef1234_000 input: in:Bridge MC out:(unknown 0), proto ICMP, 10.0.4.10->10.0.4.254, len 84"}, probes, "SG7")
        self.assertIsNone(event["destination_port"])
        self.assertEqual(event["output"], "(unknown 0)")

    def test_full_capture_returns_router_to_original_state(self):
        router = FakeRouter([policy()])
        cap = Capture(router, "SG7", router.original, ["*AB"])
        router.capture = cap
        emitted = []
        def emit(event):
            emitted.append(event)
            cap.stop()
        cap.run(emit)
        self.assertEqual(cap.phase, "stopped")
        self.assertEqual(len(emitted), 1)
        self.assertEqual(router.tables["ip/firewall/filter"], router.original)
        self.assertTrue(all(not router.tables[path] for path in router.tables if path != "ip/firewall/filter"))
        self.assertEqual(router.operations[0][1], "system/scheduler")
        expiry = router.operations[0][2]
        self.assertEqual(expiry["start-date"], "2026-10-28")
        self.assertEqual(expiry["start-time"], "00:10:00")

    def test_lost_create_response_is_recovered_by_marker(self):
        router = FakeRouter([policy()], "lost-response")
        cap = Capture(router, "SG7", router.original, ["*AB"])
        cap.run(lambda e: None)
        self.assertEqual(cap.phase, "error")
        self.assertEqual(router.tables["ip/firewall/filter"], router.original)
        self.assertFalse(router.tables["system/scheduler"])

    def test_cleanup_retains_deadline_on_failure(self):
        router = FakeRouter([policy()], "cleanup")
        cap = Capture(router, "SG7", router.original, ["*AB"])
        cap.prepare()
        errors = cleanup_session(router, cap.session)
        self.assertTrue(errors)
        self.assertTrue(router.tables["system/scheduler"])
        self.assertEqual(router.tables["ip/firewall/filter"][0], router.original[0])

    def test_cleanup_cannot_delete_unrelated_rules(self):
        router = FakeRouter([policy(), policy(**{".id":"*2","comment":"TrafficLog:not-a-session","action":"log"})])
        cleanup_session(router, "abcdef1234")
        self.assertEqual(router.tables["ip/firewall/filter"], router.original)

    def test_expired_setup_does_not_add_probes(self):
        router = FakeRouter([policy()])
        cap = Capture(router, "SG7", router.original, ["*AB"])
        cap.expires = 0
        cap.run(lambda event: None)
        self.assertEqual(cap.phase, "error")
        self.assertEqual(router.tables["ip/firewall/filter"], router.original)
        self.assertFalse(router.tables["system/scheduler"])

    def test_changed_policy_aborts_and_cleans_setup(self):
        router = FakeRouter([policy()])
        cap = Capture(router, "SG7", router.original, ["*AB"])
        router.tables["ip/firewall/filter"][0]["action"] = "accept"
        cap.run(lambda event: None)
        self.assertEqual(cap.phase, "error")
        self.assertEqual(router.tables["ip/firewall/filter"][0]["action"], "accept")
        self.assertFalse(router.tables["system/logging/action"])

    def test_command_preview_matches_created_resources_and_escapes_values(self):
        router = FakeRouter([policy()])
        cap = Capture(router, "SG7", router.original, ["*AB"])
        cap.prepare()
        created = [(path, body) for op, path, body in router.operations if op == "add"]
        self.assertEqual(cap.resource_plan(), created)
        command = add_command("ip/firewall/filter", {"in-interface": 'VLAN "$test"\\edge\nnext'})
        self.assertIn(r'in-interface="VLAN \"\$test\"\\edge\nnext"', command)
        undo = cleanup_commands(cap.session)
        self.assertEqual(len(undo), 4)
        self.assertIn(MARKER + cap.session, undo[0])
        self.assertIn("tlstop" + cap.session, undo[-1])
        with self.assertRaises(ValueError):
            cleanup_commands('"; /ip firewall filter remove [find]')

    def test_cleanup_handles_legacy_session_markers(self):
        session="abcdef1234"
        router=FakeRouter([policy()])
        router.tables["ip/firewall/filter"].append({".id":"*OLD","comment":"TrafficLens:"+session,"action":"log","log-prefix":"TL"+session+"_000"})
        router.tables["system/scheduler"].append({".id":"*S","name":"tlstop"+session,"comment":"TrafficLens:"+session})
        self.assertEqual(cleanup_session(router,session),[])
        self.assertEqual(router.tables["ip/firewall/filter"],router.original)
        self.assertEqual(router.tables["system/scheduler"],[])


class RESTTests(unittest.TestCase):
    def test_literal_star_in_ids_and_query_body(self):
        captured=[]
        class Handler(BaseHTTPRequestHandler):
            def do_DELETE(self):
                captured.append(self.path)
                self.send_response(204); self.end_headers()
            def do_POST(self):
                captured.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200); self.end_headers(); self.wfile.write(b"[]")
            def log_message(self,*args): pass
        server=HTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            client=RouterClient(f"http://127.0.0.1:{server.server_port}","u","p",allow_http=True)
            client.delete("ip/firewall/filter","*AB")
            client.logs("tlabcdef1234")
            self.assertEqual(captured[0],"/rest/ip/firewall/filter/*AB")
            self.assertEqual(captured[1][".query"],["buffer=tlabcdef1234"])
        finally:
            server.shutdown();server.server_close()


if __name__ == "__main__":
    unittest.main()
