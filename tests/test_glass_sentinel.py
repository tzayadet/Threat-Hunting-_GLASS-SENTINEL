import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta

from glass_sentinel import Event, detect_suspicious_exports, load_events


class GlassSentinelTests(unittest.TestCase):
    def setUp(self):
        base = datetime.fromisoformat("2026-11-06T22:00:00+01:00")
        self.events = [
            Event(base - timedelta(minutes=4), "ana", "198.51.100.24", "login_fail", 0, False),
            Event(base - timedelta(minutes=3), "ana", "198.51.100.24", "login_fail", 0, False),
            Event(base, "ana", "198.51.100.24", "login_success", 0, False),
            Event(base + timedelta(minutes=5), "ana", "198.51.100.24", "export", 74_000_000, False),
        ]

    def test_detects_failed_logins_followed_by_large_export(self):
        alerts = detect_suspicious_exports(self.events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].user, "ana")
        self.assertEqual(alerts[0].failed_logins, 2)

    def test_ignores_approved_export(self):
        events = self.events[:-1] + [
            Event(
                self.events[-1].timestamp,
                "ana",
                "198.51.100.24",
                "export",
                74_000_000,
                True,
            )
        ]
        self.assertEqual(detect_suspicious_exports(events), [])

    def test_ignores_small_export(self):
        events = self.events[:-1] + [
            Event(
                self.events[-1].timestamp,
                "ana",
                "198.51.100.24",
                "export",
                1_000,
                False,
            )
        ]
        self.assertEqual(detect_suspicious_exports(events), [])

    def test_requires_same_user_and_ip(self):
        events = self.events[:-1] + [
            Event(
                self.events[-1].timestamp,
                "ana",
                "203.0.113.50",
                "export",
                74_000_000,
                False,
            )
        ]
        self.assertEqual(detect_suspicious_exports(events), [])

    def test_rejects_invalid_correlation_thresholds(self):
        for kwargs in (
            {"minimum_bytes": 0},
            {"window": timedelta(0)},
            {"minimum_failed_logins": 0},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    detect_suspicious_exports(self.events, **kwargs)

    def test_load_events_requires_timezone_ip_event_and_approval_value(self):
        header = "ts,user,ip,event,bytes,approved\\n"
        invalid_rows = (
            "2026-11-06T22:00:00,ana,198.51.100.24,login_fail,0,no\\n",
            "2026-11-06T22:00:00+01:00,ana,not-an-ip,login_fail,0,no\\n",
            "2026-11-06T22:00:00+01:00,ana,198.51.100.24,unknown,0,no\\n",
            "2026-11-06T22:00:00+01:00,ana,198.51.100.24,export,-1,no\\n",
            "2026-11-06T22:00:00+01:00,ana,198.51.100.24,export,1,maybe\\n",
        )
        for row in invalid_rows:
            with self.subTest(row=row):
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "events.csv"
                    path.write_text(header + row, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_events(path)

    def test_respects_correlation_window(self):
        events = [
            Event(
                self.events[0].timestamp - timedelta(minutes=20),
                "ana",
                "198.51.100.24",
                "login_fail",
                0,
                False,
            ),
            Event(
                self.events[1].timestamp - timedelta(minutes=20),
                "ana",
                "198.51.100.24",
                "login_fail",
                0,
                False,
            ),
            *self.events[2:],
        ]
        self.assertEqual(detect_suspicious_exports(events), [])


if __name__ == "__main__":
    unittest.main()
