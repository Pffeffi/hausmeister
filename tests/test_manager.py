import json
import os
import tempfile
import unittest

from tests.fakes import FakeClient
from manager import MAX_LOG_LINES, Manager, ToolError


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = os.path.join(self.tmp.name, "audit.log")
        self.now = [1000.0]
        self.m = Manager(self.client, ["jellyfin", "Spoolman"], audit_path=self.audit,
                         cooldown_s=60, clock=lambda: self.now[0])

    def tearDown(self):
        self.tmp.cleanup()

    def audit_entries(self):
        if not os.path.exists(self.audit):
            return []
        with open(self.audit, encoding="utf-8") as f:
            return [json.loads(l) for l in f]

    def test_list_marks_whitelist(self):
        rows = {r["name"]: r["manageable"] for r in self.m.list_containers()}
        self.assertEqual(rows, {"cms-db": False, "Jellyfin": True, "Spoolman": True})

    def test_non_whitelisted_is_refused_everywhere(self):
        for fn in (self.m.status, self.m.logs, self.m.start, self.m.stop, self.m.restart):
            with self.assertRaises(ToolError):
                fn("cms-db")
        self.assertEqual([c for c in self.client.calls if c[0] != "logs"], [])
        self.assertEqual(self.client.calls, [])
        denied = [e for e in self.audit_entries() if e["result"] == "denied"]
        self.assertEqual({e["action"] for e in denied}, {"start", "stop", "restart"})

    def test_name_matching_is_case_insensitive(self):
        self.assertEqual(self.m.status("JELLYFIN")["name"], "Jellyfin")
        self.assertEqual(self.m.status("/jellyfin")["name"], "Jellyfin")

    def test_logs_clamped_and_redacted(self):
        out = self.m.logs("Jellyfin", 10000)
        self.assertEqual(self.client.calls[-1], ("logs", "srv:Jellyfin", MAX_LOG_LINES))
        self.assertEqual(out["lines"], MAX_LOG_LINES)
        self.assertNotIn("hunter2", out["log"])
        self.assertEqual(self.m.logs("Jellyfin", "quatsch")["lines"], 200)

    def test_restart_running_is_stop_then_start(self):
        r = self.m.restart("Jellyfin")
        self.assertEqual(r["state"], "RUNNING")
        self.assertEqual(self.client.calls, [("stop", "srv:Jellyfin"), ("start", "srv:Jellyfin")])
        self.assertEqual(self.audit_entries()[-1]["result"], "ok")

    def test_restart_exited_only_starts(self):
        self.m.restart("Spoolman")
        self.assertEqual(self.client.calls, [("start", "srv:Spoolman")])

    def test_start_running_and_stop_exited_are_noops(self):
        self.assertEqual(self.m.start("Jellyfin")["result"], "lief bereits")
        self.assertEqual(self.m.stop("Spoolman")["result"], "war nicht gestartet")
        self.assertEqual(self.client.calls, [])
        # No-op verbraucht keinen Cooldown
        self.m.restart("Jellyfin")
        self.assertEqual(self.client.calls, [("stop", "srv:Jellyfin"), ("start", "srv:Jellyfin")])

    def test_cooldown(self):
        self.m.stop("Jellyfin")
        self.now[0] += 30
        with self.assertRaises(ToolError):
            self.m.start("Jellyfin")
        self.now[0] += 31
        self.m.start("Jellyfin")
        self.assertEqual(self.client.calls, [("stop", "srv:Jellyfin"), ("start", "srv:Jellyfin")])
        # andere Container sind unabhaengig
        self.m.restart("Spoolman")

    def test_api_error_is_audited(self):
        self.client.fail_start = True
        with self.assertRaises(ToolError):
            self.m.start("Spoolman")
        self.assertEqual(self.audit_entries()[-1]["result"], "error")

    def test_metrics_shape(self):
        d = self.m.metrics()
        self.assertEqual(d["cpuPercent"], 12.3)
        self.assertEqual(d["array"]["state"], "STARTED")
        self.assertEqual(d["array"]["totalTB"], 8.0)
        self.assertEqual(d["memory"]["totalGB"], 32.0)


if __name__ == "__main__":
    unittest.main()
