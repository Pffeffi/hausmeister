import json
import os
import tempfile
import unittest

from tests import fakes  # noqa: F401  (setzt sys.path)
from auth import Credentials
from hashpw import hash_password

PW = "ein-gutes-passwort"


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "auth.json")
        self.now = [1000.0]
        self.c = Credentials(self.path, setup_code="ABCD1234", started=1000.0,
                             window=1800, clock=lambda: self.now[0])

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_run_needs_setup(self):
        self.assertTrue(self.c.needs_setup())
        self.assertTrue(self.c.setup_open())
        self.assertFalse(self.c.verify(PW))

    def test_wrong_code_is_refused(self):
        ok, err = self.c.setup("falsch", PW)
        self.assertFalse(ok)
        self.assertIn("einrichtungscode", err.lower())
        self.assertTrue(self.c.needs_setup())

    def test_short_password_is_refused(self):
        ok, err = self.c.setup("ABCD1234", "kurz")
        self.assertFalse(ok)
        self.assertIn("10 Zeichen", err)
        self.assertTrue(self.c.needs_setup())

    def test_setup_then_login_and_no_second_setup(self):
        ok, err = self.c.setup("ABCD1234", PW)
        self.assertTrue(ok, err)
        self.assertFalse(self.c.needs_setup())
        self.assertTrue(self.c.verify(PW))
        self.assertFalse(self.c.verify("anderes"))
        # Zweiter Versuch mit gueltigem Code prallt ab
        ok, err = self.c.setup("ABCD1234", "noch-ein-passwort")
        self.assertFalse(ok)
        self.assertIn("bereits", err)
        self.assertTrue(self.c.verify(PW))

    def test_window_expires(self):
        self.now[0] += 1801
        self.assertFalse(self.c.setup_open())
        ok, err = self.c.setup("ABCD1234", PW)
        self.assertFalse(ok)
        self.assertIn("Zeitfenster", err)

    def test_hash_is_stored_not_the_password(self):
        self.c.setup("ABCD1234", PW)
        with open(self.path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn(PW, raw)
        self.assertTrue(json.loads(raw)["password"].startswith("scrypt$"))

    def test_change_password(self):
        self.c.setup("ABCD1234", PW)
        self.assertEqual(self.c.change("falsch", "neues-passwort-x")[0], False)
        ok, err = self.c.change(PW, "kurz")
        self.assertFalse(ok)
        self.assertTrue(self.c.change(PW, "neues-passwort-x")[0])
        self.assertTrue(self.c.verify("neues-passwort-x"))
        self.assertFalse(self.c.verify(PW))

    def test_env_hash_wins_and_blocks_setup(self):
        c = Credentials(self.path, env_hash=hash_password(PW), setup_code="ABCD1234")
        self.assertFalse(c.needs_setup())
        self.assertFalse(c.setup_open())
        self.assertTrue(c.verify(PW))
        self.assertIn("vorgegeben", c.setup("ABCD1234", "was-anderes")[1])
        self.assertIn("vorgegeben", c.change(PW, "was-anderes-x")[1])
        self.assertFalse(os.path.exists(self.path))

    def test_survives_restart(self):
        self.c.setup("ABCD1234", PW)
        again = Credentials(self.path, setup_code="NEUERCODE")
        self.assertFalse(again.needs_setup())
        self.assertTrue(again.verify(PW))


if __name__ == "__main__":
    unittest.main()
