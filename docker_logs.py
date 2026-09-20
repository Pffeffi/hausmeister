"""Reserve-Quelle fuer Logs: die json-Logdateien von Docker.

Die Unraid-API ruft `docker logs` auf und liest nur **stdout**. Container, die
nach stderr schreiben (bei Python die Voreinstellung von `logging`), liefern
darueber null Zeilen. Docker selbst legt aber beide Stroeme in
`/var/lib/docker/containers/<id>/<id>-json.log` ab.

Ist dieses Verzeichnis **nur lesend** eingebunden, springt diese Klasse ein,
wenn die API nichts liefert. Ohne Mount aendert sich nichts.

Bewusst eng gehalten:
  - oeffnet ausschliesslich Dateien, die auf `-json.log` enden
  - die Container-ID muss 64 Hex-Zeichen sein (kein Pfadwechsel moeglich)
  - liest hoechstens die letzten paar MB vom Dateiende
  - beruehrt nichts anderes im Ordner (dort liegt u. a. config.v2.json
    mit Umgebungsvariablen - die geht diesen Server nichts an)
"""
import json
import os
import re

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_BYTES = 4 * 1024 * 1024      # so weit wird hoechstens zurueckgelesen
ROTATED = 3                      # zusaetzlich gedrehte Dateien (.1, .2, .3)


class DockerLogFiles:
    def __init__(self, base_dir, max_bytes=MAX_BYTES):
        self.base_dir = base_dir
        self.max_bytes = max_bytes

    def available(self):
        return bool(self.base_dir) and os.path.isdir(self.base_dir)

    @staticmethod
    def docker_id(container_id):
        """Aus der Unraid-PrefixedID ('<server>:<docker-id>') die Docker-ID."""
        raw = str(container_id or "").rsplit(":", 1)[-1].strip().lower()
        return raw if HEX64.match(raw) else None

    def _paths(self, did):
        """Aktuelle Logdatei, dann die gedrehten - aeltestes zuerst gelesen."""
        d = os.path.join(self.base_dir, did)
        names = ["%s-json.log.%d" % (did, i) for i in range(ROTATED, 0, -1)]
        names.append("%s-json.log" % did)
        return [os.path.join(d, n) for n in names]

    def _tail_bytes(self, path):
        with open(path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            start = max(0, size - self.max_bytes)
            f.seek(start)
            data = f.read()
        if start:
            data = data.split(b"\n", 1)[-1]   # angeschnittene erste Zeile weg
        return data

    def tail(self, container_id, lines):
        """Letzte Zeilen aus stdout UND stderr. Leere Liste, wenn nichts da ist."""
        did = self.docker_id(container_id)
        if not did or not self.available():
            return []
        out = []
        for path in self._paths(did):
            if not os.path.isfile(path):
                continue
            try:
                data = self._tail_bytes(path)
            except OSError:
                continue
            for raw in data.splitlines():
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                msg = rec.get("log")
                if not isinstance(msg, str):
                    continue
                out.append({"timestamp": rec.get("time", ""), "message": msg.rstrip("\n"),
                            "stream": rec.get("stream", "")})
            out = out[-lines * 2:] if len(out) > lines * 2 else out
        return out[-lines:]
