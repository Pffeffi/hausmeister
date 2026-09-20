"""Schreibbare Einstellungen des Hausmeisters.

Liegen in /data (Volume, dem Container-Benutzer gehoerend), damit die GUI sie
aendern kann, waehrend /config/config.json nur die Startwerte liefert und
schreibgeschuetzt eingebunden bleibt.

Geaendert wird ausschliesslich ueber die GUI (eigenes Passwort). Der MCP-Teil
liest nur. Nach jeder Aenderung liest der Server die Datei neu ein, ein
Neustart ist nicht noetig.
"""
import json
import os
import tempfile
import threading

DEFAULTS = {
    "containers": {},          # name -> {"manage": bool, "logs": bool}
    "cooldown_seconds": 60,
    "max_log_lines": 500,
    "read_only": False,        # Not-Aus: sperrt alle Schreibaktionen
}
LIMITS = {"cooldown_seconds": (0, 3600), "max_log_lines": (10, 2000)}


def _clean(raw, fallback=None):
    """Baut aus beliebigem Eingabe-Dict gueltige Einstellungen."""
    out = dict(DEFAULTS)
    out.update({k: v for k, v in (fallback or {}).items() if k in DEFAULTS})
    raw = raw if isinstance(raw, dict) else {}
    conts = {}
    for name, flags in (raw.get("containers") or {}).items():
        name = str(name).strip().lstrip("/")
        if not name:
            continue
        flags = flags if isinstance(flags, dict) else {}
        conts[name] = {"manage": bool(flags.get("manage", False)),
                       "logs": bool(flags.get("logs", False))}
    if conts or "containers" in raw:
        out["containers"] = conts
    for key, (lo, hi) in LIMITS.items():
        if key in raw:
            try:
                out[key] = max(lo, min(hi, int(raw[key])))
            except (TypeError, ValueError):
                pass
    if "read_only" in raw:
        out["read_only"] = bool(raw["read_only"])
    return out


class SettingsStore:
    def __init__(self, path, seed=None):
        self.path = path
        self._lock = threading.Lock()
        self._mtime = None
        self._data = None
        if not os.path.exists(path) and seed is not None:
            # Erstlauf: aus config.json uebernehmen (Whitelist = beides erlaubt).
            start = {"containers": {str(n).strip().lstrip("/"): {"manage": True, "logs": True}
                                    for n in (seed.get("whitelist") or []) if str(n).strip()},
                     "cooldown_seconds": seed.get("cooldown_seconds", 60),
                     "max_log_lines": seed.get("max_log_lines", 500)}
            self.save(_clean(start))

    def load(self):
        """Aktuelle Einstellungen; liest die Datei nur bei Aenderung neu."""
        with self._lock:
            try:
                mtime = os.path.getmtime(self.path)
            except OSError:
                mtime = None
            if self._data is None or mtime != self._mtime:
                raw = {}
                if mtime is not None:
                    try:
                        with open(self.path, encoding="utf-8") as f:
                            raw = json.load(f)
                    except (OSError, ValueError):
                        raw = {}
                self._data = _clean(raw)
                self._mtime = mtime
            return dict(self._data)

    def save(self, new):
        """Atomar schreiben, damit ein halber Stand nie gelesen werden kann."""
        data = _clean(new)
        with self._lock:
            d = os.path.dirname(os.path.abspath(self.path)) or "."
            os.makedirs(d, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".settings-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
                os.replace(tmp, self.path)
            except Exception:
                os.path.exists(tmp) and os.unlink(tmp)
                raise
            self._data = data
            try:
                self._mtime = os.path.getmtime(self.path)
            except OSError:
                self._mtime = None
            return dict(data)
