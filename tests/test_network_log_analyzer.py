import tempfile
import unittest
from pathlib import Path

from network_log_analyzer import analyze_events, parse_line, read_events


class NetworkLogAnalyzerTests(unittest.TestCase):
    def test_parse_failed_login(self):
        line = (
            "Sep 8 10:00:01 lab sshd[101]: Failed password for invalid user admin "
            "from 192.0.2.10 port 50001 ssh2"
        )
        event = parse_line(line, 7)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "failed_login")
        self.assertEqual(event.ip_address, "192.0.2.10")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.line_number, 7)

    def test_parse_successful_login(self):
        line = (
            "Sep 8 10:02:01 lab sshd[102]: Accepted publickey for hassaan "
            "from 203.0.113.5 port 51000 ssh2"
        )
        event = parse_line(line, 1)
        self.assertEqual(event.event_type, "successful_login")
        self.assertEqual(event.username, "hassaan")

    def test_invalid_ip_is_ignored(self):
        line = "Failed password for root from 999.1.1.1 port 22 ssh2"
        self.assertIsNone(parse_line(line, 1))

    def test_analysis_detects_thresholds(self):
        lines = [
            f"Failed password for root from 192.0.2.44 port {5000 + number} ssh2"
            for number in range(3)
        ]
        events = [parse_line(line, index) for index, line in enumerate(lines, 1)]
        analysis = analyze_events(events, failed_threshold=3, connection_threshold=5)
        self.assertEqual(analysis["failed_login_attempts"], 3)
        self.assertEqual(len(analysis["suspicious_ip_addresses"]), 1)
        self.assertIn("root", analysis["suspicious_ip_addresses"][0]["targeted_usernames"])

    def test_repeated_connections_are_detected(self):
        lines = [
            f"Connection from 198.51.100.8 port {6000 + number} on 10.0.0.4 port 22"
            for number in range(5)
        ]
        events = [parse_line(line, index) for index, line in enumerate(lines, 1)]
        analysis = analyze_events(events, failed_threshold=3, connection_threshold=5)
        item = analysis["suspicious_ip_addresses"][0]
        self.assertEqual(item["connection_attempts"], 5)
        self.assertEqual(item["failed_logins"], 0)

    def test_reader_counts_unrecognized_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(
                "unrelated service message\n"
                "Failed password for root from 192.0.2.9 port 1234 ssh2\n",
                encoding="utf-8",
            )
            events, ignored = read_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(ignored, 1)


if __name__ == "__main__":
    unittest.main()
