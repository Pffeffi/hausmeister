import json
import os
import tempfile
import unittest

from tests import fakes  # noqa: F401  (setzt sys.path)
from settings import DEFAULTS, SettingsStore


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "settings.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_seed_only_on_first_run(self):
        s = SettingsStore(self.path, seed={"whitelist": ["/Jellyfin", " ", "Spoolman"], "cooldown_seconds": 30})
        self.assertEqual(sorted(s.load()["containers"]), ["Jellyfin", "Spoolman"])
        self.assertEqual(s.load()["cooldown_seconds"], 30)
        s.save({"containers": {}, "cooldown_seconds": 10})
        # Neue Instanz auf dieselbe Datei darf den Seed nicht erneut anwenden
        s2 = SettingsStore(self.path, seed={"whitelist": ["Jellyfin"], "cooldown_seconds": 30})
        self.assertEqual(s2.load()["containers"], {})
        self.assertEqual(s2.load()["cooldown_seconds"], 10)

    def test_values_are_clamped_and_typed(self):
        s = SettingsStore(self.path)
        got = s.save({"containers": {"a": {"manage": "ja", "logs": 0}, "": {"manage": True}},
                      "cooldown_seconds": 99999, "max_log_lines": 1, "read_only": "x"})
        self.assertEqual(got["containers"], {"a": {"manage": True, "logs": False}})
        self.assertEqual(got["cooldown_seconds"], 3600)
        self.assertEqual(got["max_log_lines"], 10)
        self.assertIs(got["read_only"], True)

    def test_garbage_file_falls_back_to_defaults(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("kein json {")
        self.assertEqual(SettingsStore(self.path).load(), DEFAULTS)

    def test_external_change_is_picked_up(self):
        s = SettingsStore(self.path, seed={"whitelist": ["Jellyfin"]})
        self.assertIn("Jellyfin", s.load()["containers"])
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        data["containers"] = {"Spoolman": {"manage": True, "logs": True}}
        data["read_only"] = True
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.utime(self.path, (0, 0))   # andere mtime erzwingen
        self.assertEqual(list(s.load()["containers"]), ["Spoolman"])
        self.assertTrue(s.load()["read_only"])

    def test_save_is_atomic_and_leaves_no_temp_files(self):
        s = SettingsStore(self.path)
        s.save({"containers": {"a": {"manage": True, "logs": True}}})
        self.assertEqual(os.listdir(self.tmp.name), ["settings.json"])
        with open(self.path, encoding="utf-8") as f:
            self.assertIs(json.load(f)["containers"]["a"]["manage"], True)


if __name__ == "__main__":
    unittest.main()
