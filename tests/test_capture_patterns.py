import unittest

from plimsoll.capture import CONNECT, OPENAT


class CapturePatternTest(unittest.TestCase):
    def test_capture_patterns_accept_monitor_lines(self):
        cases = [
            (OPENAT, "[PID 42] openat: /tmp/file", ("42", "/tmp/file")),
            (CONNECT, "[PID 42] connect: api.example:443", ("42", "api.example:443")),
            (CONNECT, "[PID 42] connect api.example:443", ("42", "api.example:443")),
            (
                CONNECT,
                "[PID 4242] connect sockaddr[0..32]=10.0.0.1:443",
                ("4242", "sockaddr[0..32]=10.0.0.1:443"),
            ),
        ]

        for pattern, line, groups in cases:
            with self.subTest(line=line):
                match = pattern.search(line.strip())
                self.assertIsNotNone(match)
                self.assertEqual(match.groups(), groups)

    def test_capture_patterns_reject_non_monitor_prefixes(self):
        cases = [
            (OPENAT, "prefix [PID 42] openat: /tmp/file"),
            (CONNECT, "prefix [PID 42] connect: api.example:443"),
            (OPENAT, "x" * 100_000),
            (CONNECT, "x" * 100_000),
            (CONNECT, "[PID 42] connection-refused"),
            (CONNECT, "[PID 42] connective.example:443"),
            (CONNECT, "[PID 42] connectx"),
        ]

        for pattern, line in cases:
            with self.subTest(line=line[:80]):
                self.assertIsNone(pattern.search(line.strip()))
