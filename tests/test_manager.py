import json
import os
import tempfile
import unittest

from tests.fakes import FakeClient
from manager import Manager, ToolError
from settings import SettingsStore


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = os.path.join(self.tmp.name, "audit.log")
        self.store = SettingsStore(os.path.join(self.tmp.name, "settings.json"),
                                   seed={"whitelist": ["jellyfin", "Spoolman"], "cooldown_seconds": 60})
        self.now = [1000.0]
        self.m = Manager(self.client, self.store, audit_path=self.audit, clock=lambda: self.now[0])

    def tearDown(self):
        self.tmp.cleanup()

    def audit_entries(self):
        if not os.path.exists(self.audit):
            return []
        with open(self.audit, encoding="utf-8") as f:
            return [json.loads(l) for l in f]

    def set(self, **kw):
        cfg = self.store.load(); cfg.update(kw); self.store.save(cfg)

    def test_seed_from_config_grants_both_rights(self):
        cfg = self.store.load()
        self.assertEqual(cfg["containers"], {"jellyfin": {"manage": True, "logs": True},
                                             "Spoolman": {"manage": True, "logs": True}})
        rows = {r["name"]: (r["manageable"], r["logsReadable"]) for r in self.m.list_containers()}
        self.assertEqual(rows, {"cms-db": (False, False), "Jellyfin": (True, True), "Spoolman": (True, True)})

    def test_not_released_is_refused_everywhere(self):
        for fn in (self.m.status, self.m.logs, self.m.start, self.m.stop, self.m.restart):
            with self.assertRaises(ToolError):
                fn("cms-db")
        self.assertEqual(self.client.calls, [])
        denied = [e for e in self.audit_entries() if e["result"] == "denied"]
        self.assertEqual({e["action"] for e in denied}, {"start", "stop", "restart"})

    def test_logs_right_is_separate_from_manage(self):
        self.set(containers={"Jellyfin": {"manage": False, "logs": True}})
        self.assertEqual(self.m.logs("Jellyfin", 3)["lines"], 3)
        self.m.status("Jellyfin")
        with self.assertRaises(ToolError):
            self.m.restart("Jellyfin")
        self.set(containers={"Jellyfin": {"manage": True, "logs": False}})
        with self.assertRaises(ToolError):
            self.m.logs("Jellyfin")
        self.assertEqual(self.m.restart("Jellyfin")["result"], "ok")

    def test_read_only_blocks_writes_but_not_reads(self):
        self.set(read_only=True)
        self.assertEqual(self.m.status("Jellyfin")["name"], "Jellyfin")
        self.assertTrue(self.m.logs("Jellyfin", 2)["lines"])
        for fn in (self.m.start, self.m.stop, self.m.restart):
            with self.assertRaises(ToolError) as cm:
                fn("Spoolman")
            self.assertIn("Not-Aus", str(cm.exception))
        self.assertEqual(self.client.calls, [c for c in self.client.calls if c[0] == "logs"])
        self.assertFalse(self.m.list_containers()[0]["manageable"])

    def test_settings_change_takes_effect_without_restart(self):
        with self.assertRaises(ToolError):
            self.m.status("cms-db")
        self.set(containers={"cms-db": {"manage": True, "logs": True}})
        self.assertEqual(self.m.status("cms-db")["name"], "cms-db")

    def test_name_matching_is_case_insensitive(self):
        self.assertEqual(self.m.status("JELLYFIN")["name"], "Jellyfin")
        self.assertEqual(self.m.status("/jellyfin")["name"], "Jellyfin")

    def test_logs_clamped_and_redacted(self):
        self.set(max_log_lines=50)
        out = self.m.logs("Jellyfin", 10000)
        self.assertEqual(self.client.calls[-1], ("logs", "srv:Jellyfin", 50))
        self.assertEqual(out["lines"], 50)
        self.assertNotIn("hunter2", out["log"])
        self.assertEqual(self.m.logs("Jellyfin", "quatsch")["lines"], 50)

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
        self.m.restart("Spoolman")   # anderer Container ist unabhaengig

    def test_cooldown_value_comes_from_settings(self):
        self.set(cooldown_seconds=0)
        self.m.stop("Jellyfin")
        self.m.start("Jellyfin")
        self.assertEqual(len(self.client.calls), 2)

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
