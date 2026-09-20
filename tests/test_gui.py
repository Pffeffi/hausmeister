"""Die Weboberflaeche ueber echtes HTTP: Anmeldung, Trennung vom MCP-Token, Speichern."""
import os
import tempfile
import unittest

import httpx2

from tests.fakes import FakeClient
from tests.live import LiveServer
from gui import build_gui, hash_password
from manager import Manager, ToolError
from settings import SettingsStore
from server import build_app

PW = "ein-sehr-gutes-passwort"
TOKEN = "t" * 40
HDR = {"X-Hausmeister": "1"}


class GuiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.audit = os.path.join(cls.tmp.name, "audit.log")
        cls.store = SettingsStore(os.path.join(cls.tmp.name, "settings.json"),
                                  seed={"whitelist": ["Jellyfin"]})
        cls.fake = FakeClient()
        cls.manager = Manager(cls.fake, cls.store, audit_path=cls.audit)
        cls.gui = LiveServer(build_gui(cls.manager, cls.store, hash_password(PW), cls.audit)).start()
        cls.mcp = LiveServer(build_app(cls.manager, TOKEN)).start()

    @classmethod
    def tearDownClass(cls):
        cls.gui.stop(); cls.mcp.stop(); cls.tmp.cleanup()

    def client(self):
        return httpx2.Client(base_url=self.gui.base, timeout=10)

    def login(self, c, pw=PW):
        return c.post("/api/login", json={"password": pw}, headers=HDR)

    def test_page_is_served_but_data_needs_login(self):
        with self.client() as c:
            self.assertIn("Hausmeister", c.get("/").text)
            self.assertEqual(c.get("/api/state").status_code, 401)
            self.assertEqual(c.get("/api/audit").status_code, 401)
            self.assertEqual(c.post("/api/settings", json={}, headers=HDR).status_code, 401)

    def test_login_and_read_state(self):
        with self.client() as c:
            self.assertEqual(self.login(c, "falsch").status_code, 401)
            self.assertEqual(c.get("/api/state").status_code, 401)
            self.assertEqual(self.login(c).status_code, 200)
            d = c.get("/api/state").json()
            self.assertEqual(d["settings"]["containers"], {"Jellyfin": {"manage": True, "logs": True}})
            self.assertIn("cms-db", [x["name"] for x in d["containers"]])
            c.post("/api/logout", headers=HDR)
            self.assertEqual(c.get("/api/state").status_code, 401)

    def test_mcp_token_does_not_open_the_gui(self):
        with self.client() as c:
            r = c.get("/api/state", headers={"Authorization": "Bearer " + TOKEN})
            self.assertEqual(r.status_code, 401)

    def test_gui_session_does_not_open_the_mcp_port(self):
        with self.client() as c:
            self.login(c)
            cookies = dict(c.cookies)
        r = httpx2.post(self.mcp.base + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                        cookies=cookies, headers={"Accept": "application/json, text/event-stream"}, timeout=10)
        self.assertEqual(r.status_code, 401)

    def test_csrf_header_required_for_writes(self):
        with self.client() as c:
            self.login(c)
            self.assertEqual(c.post("/api/settings", json={"read_only": True}).status_code, 400)
            self.assertEqual(c.post("/api/login", json={"password": PW}).status_code, 400)

    def test_foreign_origin_refused(self):
        with self.client() as c:
            self.login(c)
            r = c.post("/api/settings", json={"read_only": True},
                       headers={**HDR, "Origin": "http://evil.example"})
            self.assertEqual(r.status_code, 400)

    def test_saving_changes_what_the_assistant_may_do(self):
        with self.client() as c:
            self.login(c)
            # Freigabe fuer Spoolman erteilen -> Assistent darf sofort
            cfg = c.get("/api/state").json()["settings"]
            cfg["containers"]["Spoolman"] = {"manage": True, "logs": True}
            self.assertEqual(c.post("/api/settings", json=cfg, headers=HDR).status_code, 200)
            self.assertEqual(self.manager.status("Spoolman")["name"], "Spoolman")
            # Not-Aus setzen -> Schreibaktionen sofort gesperrt
            cfg["read_only"] = True
            c.post("/api/settings", json=cfg, headers=HDR)
            with self.assertRaises(ToolError):
                self.manager.restart("Spoolman")
            # und wieder zuruecknehmen
            cfg["read_only"] = False
            del cfg["containers"]["Spoolman"]
            c.post("/api/settings", json=cfg, headers=HDR)
            with self.assertRaises(ToolError):
                self.manager.status("Spoolman")
            entries = c.get("/api/audit").json()["entries"]
            self.assertEqual(entries[0]["action"], "settings")


class RateLimitTest(unittest.TestCase):
    def test_too_many_wrong_passwords(self):
        tmp = tempfile.TemporaryDirectory()
        store = SettingsStore(os.path.join(tmp.name, "s.json"))
        srv = LiveServer(build_gui(Manager(FakeClient(), store), store, hash_password(PW))).start()
        try:
            with httpx2.Client(base_url=srv.base, timeout=10) as c:
                codes = [c.post("/api/login", json={"password": "x"}, headers=HDR).status_code
                         for _ in range(6)]
                self.assertEqual(codes[:5], [401] * 5)
                self.assertEqual(codes[5], 429)
                # auch das richtige Passwort prallt jetzt ab
                self.assertEqual(c.post("/api/login", json={"password": PW}, headers=HDR).status_code, 429)
        finally:
            srv.stop(); tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
