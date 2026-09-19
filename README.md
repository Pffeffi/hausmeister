# 🧹 Hausmeister

**Ein MCP-Server, mit dem ein KI-Assistent (z. B. Claude Code) auf einem Unraid-Server nach
dem Rechten sehen darf, ohne ihm die Schlüssel zum ganzen Haus zu geben.**

Der Hausmeister hat einen Schlüsselbund, geht durchs Haus und schaut, ob alles läuft. In den
freigegebenen Räumen darf er das Licht an- und ausmachen, und im Notfall ruft er dich an.
Umbauen, Wände einreißen oder neue Mieter einziehen lassen darf er nicht. Alles, was er tut,
steht im Hausbuch.

Übersetzt heißt das: Container und Logs lesen, Server-Zustand prüfen und **nach Rückfrage**
freigegebene Container starten, stoppen oder neu starten. Ohne SSH, ohne Root und ohne
Docker-Socket.

```
KI-Client (PC) ──HTTP + Bearer-Token (nur LAN)──▶ Hausmeister (Container auf Unraid)
                                                     └─▶ Unraid GraphQL-API (eigener, eingeschränkter Key)
```

## Was er darf

| Tool | Art | Einschränkung |
|---|---|---|
| `container_list` | lesen | alle Container; `manageable` = auf der Whitelist |
| `container_status(name)` | lesen | nur Whitelist |
| `container_logs(name, lines)` | lesen | nur Whitelist, max. 500 Zeilen, Secrets serverseitig geschwärzt |
| `server_metrics` | lesen | CPU, RAM, Temperaturen, Array-Zustand, Plattenfehler |
| `container_start/stop/restart(name)` | schreiben | nur Whitelist, 60 s Sperre pro Container, Audit-Log |

Was er bewusst **nicht** kann: Shell, `exec`, Container anlegen, löschen oder aktualisieren,
Array, Shares oder Plugins verwalten.

## Warum die Grenze hier liegt und nicht beim API-Key

Container starten und stoppen braucht in Unraid `DOCKER:UPDATE_ANY` (geprüft gegen unraid/api
v4.35.1). **Dasselbe Recht erlaubt aber auch `updateContainer` und `updateAllContainers`.** Der
Unraid-Key darf den KI-Client deshalb nie erreichen: Er liegt nur in diesem Container, der Client
kennt nur das MCP-Token. Whitelist, Sperrzeit und Audit-Log werden serverseitig erzwungen.
Nachgebaute Aufrufe vom Client aus kommen daran nicht vorbei.

Weitere Schutzmaßnahmen:
- Logs gehen über die Unraid-API. Es gibt keinen Mount von `/var/lib/docker` und keinen Socket-Proxy.
- Der Container läuft ohne Root (uid 10001), mit `read_only`, `cap_drop: ALL` und `no-new-privileges`.
- Das Token wird in konstanter Zeit verglichen, außerdem gibt es eine Host-Header-Prüfung gegen DNS-Rebinding.
- Bewusste Ablehnungen kommen im Klartext beim Client an, unerwartete Fehler bleiben verborgen.
- Die Tool-Beschreibungen sagen dem Modell, dass Logzeilen Daten sind und keine Anweisungen.

## Einrichtung

1. **Unraid-API-Key** mit genau diesen Rechten anlegen. In Unraid 7.3.x zuverlässiger per CLI,
   weil die Weboberfläche teils Ressourcen mit auswählt. Ohne `--roles ""` bricht die CLI mit
   *Invalid data structure* ab:
   ```bash
   unraid-api apikey --create --name "Hausmeister" --roles "" \
     --permissions "DOCKER:READ_ANY,DOCKER:UPDATE_ANY,INFO:READ_ANY,ARRAY:READ_ANY" --json
   ```
2. Projekt auf den Server kopieren. Daneben aus den Vorlagen anlegen:
   - `.env` (aus `.env.example`: IP, Key, Token)
   - `config.json` (aus `config.example.json`: **Whitelist**)
3. Stack starten, z. B. in Compose.Manager mit **Compose Up** oder `docker compose up -d --build`.
4. Prüfen: `curl -X POST http://<unraid-ip>:8765/mcp` muss **401** liefern.

### Absichern (wichtig)
Wenn der Client-Rechner den Deploy-Ordner per SMB erreicht (z. B. ein Share), könnte der Assistent
dort die `.env` lesen oder die Whitelist ändern. Deshalb nach dem Deploy auf dem Server:
```bash
chown -R root:root /pfad/zu/hausmeister && chmod -R u=rwX,go=rX /pfad/zu/hausmeister && chmod 600 /pfad/zu/hausmeister/.env
```
Lag der Key vorher lesbar herum, einen **neuen Key mit neuem Namen** anlegen und den alten
löschen. `--overwrite` behält den alten Key-Wert.

### Claude Code anbinden
Das Token als Umgebungsvariable `HAUSMEISTER_TOKEN` setzen, dann:
```bash
claude mcp add --transport http --scope user hausmeister http://<unraid-ip>:8765/mcp --header 'Authorization: Bearer ${HAUSMEISTER_TOKEN}'
```
Rückfrage vor jeder Änderung, in `~/.claude/settings.json`:
```json
"permissions": {
  "allow": ["mcp__hausmeister__container_list", "mcp__hausmeister__container_status",
            "mcp__hausmeister__container_logs", "mcp__hausmeister__server_metrics"],
  "ask":   ["mcp__hausmeister__container_start", "mcp__hausmeister__container_stop",
            "mcp__hausmeister__container_restart"]
}
```

## Netz
Der Port ist nur an die LAN-IP gebunden. **Keinen** Reverse-Proxy-Eintrag, keine
Cloudflare-Route und kein Port-Forward anlegen. Für unterwegs gehört er ins VPN (Tailscale,
WireGuard), nicht ins Internet.

## Das Hausbuch
```bash
docker exec hausmeister cat /data/audit.log
```
Eine JSON-Zeile pro Schreibaktion, inklusive abgelehnter Versuche (`denied`) und No-ops.

## Entwicklung
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\...
python -m unittest discover -s tests -t .
```
`tests/test_server.py` testet über echtes HTTP mit dem offiziellen MCP-Client: 401 ohne Token,
Host-Header-Prüfung, genau die erlaubten Tools, Ablehnung außerhalb der Whitelist.
Gebaut auf `mcp` 2.x (`MCPServer`), getestet gegen Unraid 7.3.2 / API 4.35.1.

## Lizenz
MIT
