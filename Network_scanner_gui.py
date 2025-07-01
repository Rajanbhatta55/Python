import unittest
from unittest.mock import patch, MagicMock
import network_scanner

class TestNetworkScanner(unittest.TestCase):

    def test_parse_ports_single(self):
        self.assertEqual(network_scanner.parse_ports("80"), [80])

    def test_parse_ports_multiple(self):
        self.assertEqual(network_scanner.parse_ports("22,80,443"), [22, 80, 443])

    def test_parse_ports_range(self):
        self.assertEqual(network_scanner.parse_ports("10-12"), [10, 11, 12])

    def test_parse_ports_mixed(self):
        self.assertEqual(network_scanner.parse_ports("21,22,25-27,80"), [21, 22, 25, 26, 27, 80])

    @patch("network_scanner.socket.socket")
    def test_scan_port_open(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value.__enter__.return_value = mock_socket
        result = network_scanner.scan_port("127.0.0.1", 80, version_detection=False, verbose=False)
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "Open")

    @patch("network_scanner.socket.socket")
    def test_scan_port_closed(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1
        mock_socket_class.return_value.__enter__.return_value = mock_socket
        result = network_scanner.scan_port("127.0.0.1", 12345, version_detection=False, verbose=False)
        self.assertIsNone(result)

    @patch("network_scanner.os.system")
    def test_is_host_up_true(self, mock_system):
        mock_system.return_value = 0
        result = network_scanner.is_host_up("127.0.0.1", verbose=False)
        self.assertTrue(result)

    @patch("network_scanner.os.system")
    def test_is_host_up_false(self, mock_system):
        mock_system.return_value = 1
        result = network_scanner.is_host_up("192.0.2.1", verbose=False)
        self.assertFalse(result)

    @patch("network_scanner.subprocess.run")
    def test_detect_os_windows(self, mock_run):
        mock_run.return_value.stdout = "Reply from 127.0.0.1: bytes=32 time<1ms TTL=128"
        result = network_scanner.detect_os("127.0.0.1", verbose=False)
        self.assertEqual(result, "Windows")

    @patch("network_scanner.subprocess.run")
    def test_detect_os_linux(self, mock_run):
        mock_run.return_value.stdout = "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms"
        result = network_scanner.detect_os("127.0.0.1", verbose=False)
        self.assertEqual(result, "Linux/Unix")

    @patch("network_scanner.subprocess.run")
    def test_detect_os_unknown(self, mock_run):
        mock_run.return_value.stdout = "Reply with strange TTL"
        result = network_scanner.detect_os("127.0.0.1", verbose=False)
        self.assertEqual(result, "Unknown")

if __name__ == "__main__":
    unittest.main()
