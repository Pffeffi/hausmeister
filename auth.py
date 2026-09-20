"""Passwort der Weboberflaeche: Erstinbetriebnahme und spaeteres Aendern.

Beim ersten Start gibt es noch kein Passwort. Damit es nicht der Schnellste im
LAN setzt (der Assistent erreicht den Port ebenfalls), braucht die Einrichtung
einen Code, den der Container beim Start ins eigene Log schreibt. Dieses Log
sieht nur der Besitzer auf dem Unraid-Server.

Zusaetzlich ist das Fenster zeitlich begrenzt; danach hilft nur ein Neustart,
der einen neuen Code erzeugt.
"""
import json
import os
import tempfile
import threading
import time

from hashpw import check_password, hash_password

SETUP_WINDOW = 30 * 60   # Sekunden nach Start, in denen eingerichtet werden darf


class Credentials:
    def __init__(self, path, env_hash=None, setup_code=None, started=None,
                 window=SETUP_WINDOW, clock=time.time):
        self.path = path
        self.env_hash = (env_hash or "").strip() or None
        self.setup_code = setup_code
        self.started = started if started is not None else clock()
        self.window = window
        self.clock = clock
        self._lock = threading.Lock()

    # --- Zustand ------------------------------------------------------------

    def stored_hash(self):
        if self.env_hash:
            return self.env_hash          # fest vorgegeben, Einrichtung entfaellt
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f).get("password") or None
        except (OSError, ValueError):
            return None

    def needs_setup(self):
        return self.stored_hash() is None

    def setup_open(self):
        return (self.needs_setup() and bool(self.setup_code)
                and self.clock() - self.started < self.window)

    def verify(self, password):
        stored = self.stored_hash()
        return bool(stored) and check_password(password, stored)

    # --- Aendern ------------------------------------------------------------

    def _write(self, hashed):
        with self._lock:
            d = os.path.dirname(os.path.abspath(self.path)) or "."
            os.makedirs(d, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".auth-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump({"password": hashed,
                               "changed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
            except Exception:
                os.path.exists(tmp) and os.unlink(tmp)
                raise

    def setup(self, code, password):
        """Erstes Passwort setzen. Gibt (ok, Fehlertext) zurueck."""
        if self.env_hash:
            return False, "Das Passwort ist fest vorgegeben (GUI_PASSWORD_HASH)."
        if not self.needs_setup():
            return False, "Es ist bereits ein Passwort gesetzt."
        if not self.setup_open():
            return False, ("Das Zeitfenster fuer die Einrichtung ist abgelaufen. "
                           "Container neu starten, dann steht ein neuer Code im Log.")
        if not code or not _equal(code.strip(), self.setup_code):
            return False, "Falscher Einrichtungscode. Er steht im Log des Containers."
        ok, err = _check_quality(password)
        if not ok:
            return False, err
        self._write(hash_password(password))
        return True, ""

    def change(self, old, new):
        if self.env_hash:
            return False, ("Das Passwort ist ueber GUI_PASSWORD_HASH fest vorgegeben und "
                           "laesst sich hier nicht aendern.")
        if not self.verify(old):
            return False, "Das bisherige Passwort stimmt nicht."
        ok, err = _check_quality(new)
        if not ok:
            return False, err
        self._write(hash_password(new))
        return True, ""


def _equal(a, b):
    import hmac
    return hmac.compare_digest(str(a), str(b or ""))


def _check_quality(password):
    if not isinstance(password, str) or len(password) < 10:
        return False, "Das Passwort braucht mindestens 10 Zeichen."
    if len(password) > 200:
        return False, "Das Passwort ist zu lang."
    return True, ""
