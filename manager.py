"""Hausmeister - Fachlogik hinter den MCP-Tools: Whitelist, Bremse, Audit-Log.

Hier - nicht im MCP-Layer und nicht in Claude Code - liegt die eigentliche
Sicherheitsgrenze. Der Unraid-API-Key haette mit DOCKER:UPDATE_ANY z. B. auch
updateContainer/updateAllContainers erlaubt; dieser Server bietet davon nur
start/stop an, und nur fuer Container auf der Whitelist.
"""
import json
import threading
import time
from datetime import datetime, timezone

from mcp.server.mcpserver.exceptions import ToolError as _SdkToolError

from redact import redact
from unraid_api import UnraidError

MAX_LOG_LINES = 500
MAX_LINE_CHARS = 2000


class ToolError(_SdkToolError):
    """Bewusste Ablehnung/Fehler: Text geht an Claude. Alles andere versteckt das SDK."""


class Manager:
    def __init__(self, client, whitelist, audit_path=None, cooldown_s=60, clock=time.monotonic):
        self.client = client
        # Vergleich ohne Gross/Klein, Ausgabe mit dem echten Containernamen.
        self.whitelist = {n.strip().lower() for n in whitelist if n.strip()}
        self.audit_path = audit_path
        self.cooldown_s = cooldown_s
        self.clock = clock
        self._last_write = {}
        self._lock = threading.Lock()        # Cooldown-Tabelle
        self._audit_lock = threading.Lock()  # Audit-Datei

    # --- Hilfen -------------------------------------------------------------

    def _audit(self, action, container, result, detail=""):
        if not self.audit_path:
            return
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "action": action, "container": container, "result": result}
        if detail:
            entry["detail"] = detail
        with self._audit_lock, open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _containers(self):
        try:
            return self.client.containers()
        except UnraidError as e:
            raise ToolError(str(e)) from None

    def _find(self, name, action):
        """Container auf der Whitelist per Name finden, sonst ToolError."""
        key = (name or "").strip().lstrip("/").lower()
        if key not in self.whitelist:
            if action not in ("status", "logs"):
                self._audit(action, name, "denied", "nicht auf der Whitelist")
            raise ToolError("'%s' steht nicht auf der Whitelist dieses Servers. "
                            "Freigegeben: %s" % (name, ", ".join(sorted(self.whitelist)) or "(keine)"))
        for c in self._containers():
            if c["name"].lower() == key:
                return c
        raise ToolError("Container '%s' existiert auf dem Server nicht." % name)

    def _check_cooldown(self, container, action):
        now = self.clock()
        with self._lock:
            last = self._last_write.get(container)
            blocked = last is not None and now - last < self.cooldown_s
            if not blocked:
                self._last_write[container] = now
        if blocked:
            self._audit(action, container, "denied", "Cooldown")
            raise ToolError("Fuer '%s' lief gerade erst eine Aenderung. Bitte in %d s erneut."
                            % (container, int(self.cooldown_s - (now - last)) + 1))

    # --- Lesen --------------------------------------------------------------

    def list_containers(self):
        out = []
        for c in sorted(self._containers(), key=lambda c: c["name"].lower()):
            out.append({"name": c["name"], "state": c["state"], "status": c["status"],
                        "image": c["image"], "manageable": c["name"].lower() in self.whitelist})
        return out

    def status(self, name):
        c = self._find(name, "status")
        return {k: c[k] for k in ("name", "state", "status", "image", "autoStart", "updateAvailable")}

    def logs(self, name, lines=200):
        try:
            lines = int(lines)
        except (TypeError, ValueError):
            lines = 200
        lines = max(1, min(lines, MAX_LOG_LINES))
        c = self._find(name, "logs")
        try:
            raw = self.client.logs(c["id"], lines)
        except UnraidError as e:
            raise ToolError(str(e)) from None
        out = []
        for ln in raw[-lines:]:
            msg = (ln.get("message") or "").rstrip()
            if len(msg) > MAX_LINE_CHARS:
                msg = msg[:MAX_LINE_CHARS] + " ...[gekuerzt]"
            out.append("%s %s" % (ln.get("timestamp", ""), redact(msg)))
        return {"name": c["name"], "lines": len(out), "log": "\n".join(out),
                "note": "Geheimnisse wurden serverseitig geschwaerzt." if out else
                        "Keine Logzeilen geliefert (leeres Log oder anderer Log-Treiber)."}

    def metrics(self):
        try:
            d = self.client.metrics()
        except UnraidError as e:
            raise ToolError(str(e)) from None
        m = d.get("metrics") or {}
        arr = d.get("array") or {}
        kb = ((arr.get("capacity") or {}).get("kilobytes") or {})
        mem = m.get("memory") or {}
        disks = []
        for group in ("parities", "disks", "caches"):
            for dk in arr.get(group) or []:
                disks.append({"name": dk.get("name"), "temp": dk.get("temp"),
                              "status": dk.get("status"), "errors": dk.get("numErrors")})
        sensors = [{"name": s.get("name"), "value": (s.get("current") or {}).get("value")}
                   for s in ((m.get("temperature") or {}).get("sensors") or [])]
        gb = lambda b: round(int(b) / 1e9, 1) if b not in (None, "") else None
        return {
            "cpuPercent": round((m.get("cpu") or {}).get("percentTotal") or 0, 1),
            "memory": {"percent": round(mem.get("percentTotal") or 0, 1), "totalGB": gb(mem.get("total")),
                       "availableGB": gb(mem.get("available")), "swapUsedGB": gb(mem.get("swapUsed"))},
            "uptimeSince": ((d.get("info") or {}).get("os") or {}).get("uptime"),
            "array": {"state": arr.get("state"),
                      "usedTB": round(int(kb["used"]) / 1e9, 2) if kb.get("used") else None,
                      "totalTB": round(int(kb["total"]) / 1e9, 2) if kb.get("total") else None,
                      "disks": disks},
            "temperatures": sensors,
        }

    # --- Schreiben (nur Whitelist, mit Bremse und Audit) ---------------------

    def _write(self, action, name):
        c = self._find(name, action)
        noop = {"start": "lief bereits" if c["state"] == "RUNNING" else None,
                "stop": "war nicht gestartet" if c["state"] != "RUNNING" else None}.get(action)
        if noop:
            self._audit(action, c["name"], "noop", noop)
            return {"name": c["name"], "result": noop, "state": c["state"]}
        self._check_cooldown(c["name"], action)
        try:
            if action == "start":
                r = self.client.start(c["id"])
            elif action == "stop":
                r = self.client.stop(c["id"])
            else:  # restart: die API kennt kein restart -> stop (falls laeuft) + start
                if c["state"] == "RUNNING":
                    self.client.stop(c["id"])
                r = self.client.start(c["id"])
        except UnraidError as e:
            self._audit(action, c["name"], "error", str(e))
            raise ToolError("%s fehlgeschlagen: %s" % (action, e)) from None
        self._audit(action, c["name"], "ok", r.get("status", ""))
        return {"name": c["name"], "result": "ok", "state": r.get("state"), "status": r.get("status")}

    def start(self, name):
        return self._write("start", name)

    def stop(self, name):
        return self._write("stop", name)

    def restart(self, name):
        return self._write("restart", name)
