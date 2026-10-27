import unittest
from unittest.mock import patch

from trafficlog.network import connection_defaults, linux_gateway, windows_gateway


class GatewayTests(unittest.TestCase):
    def test_windows_prefers_lowest_active_default_route_and_ignores_persistent_rows(self):
        output = """Aktive Routen:
0.0.0.0 0.0.0.0 192.168.20.1 192.168.20.50 55
0.0.0.0 0.0.0.0 10.19.1.0 10.19.1.9 15
10.0.4.0 255.255.255.0 10.19.1.1 10.19.1.9 1
Ständige Routen:
0.0.0.0 0.0.0.0 10.0.0.1 1
"""
        self.assertEqual(windows_gateway(output), "10.19.1.0")

    def test_linux_gateway_byte_order_and_route_flags(self):
        output = """Iface Destination Gateway Flags RefCnt Use Metric Mask
eth0 00000000 0104A8C0 0003 0 0 100 00000000
tun0 00000000 0100000A 0000 0 0 1 00000000
eth1 00000000 0100000A 0003 0 0 200 00000000
"""
        self.assertEqual(linux_gateway(output), "192.168.4.1")

    def test_no_gateway_does_not_invent_a_router(self):
        self.assertEqual(windows_gateway("0.0.0.0 0.0.0.0 On-link 10.0.0.2 1"), "")
        with patch("trafficlog.network.default_gateway", return_value=""):
            self.assertEqual(connection_defaults(), {"gateway":"", "address":""})

    def test_defaults_are_refreshed_and_http(self):
        with patch("trafficlog.network.default_gateway", side_effect=["10.0.4.254", "192.168.1.1"]):
            self.assertEqual(connection_defaults()["address"], "http://10.0.4.254")
            self.assertEqual(connection_defaults()["address"], "http://192.168.1.1")
