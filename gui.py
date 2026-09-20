"""Weboberflaeche des Hausmeisters (eigener Port, eigene Anmeldung).

Bewusst getrennt vom MCP-Teil: Das MCP-Token gilt hier NICHT. Wer die GUI
bedienen darf, darf die Rechte des Assistenten aendern - das soll nur der
Besitzer koennen, nicht der Assistent selbst.

Passwort steht nie im Klartext im Container, nur als scrypt-Hash in
GUI_PASSWORD_HASH (erzeugen mit `python hashpw.py`).
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

# Das Hashen liegt in hashpw.py, damit `python3 hashpw.py` auch ohne
# installierte Pakete direkt auf dem Unraid-Server laeuft.
from hashpw import check_password, hash_password  # noqa: F401  (Re-Export fuer Tests)

COOKIE = "hausmeister_session"
SESSION_SECONDS = 8 * 3600
MAX_TRIES = 5              # Fehlversuche je IP
TRY_WINDOW = 300           # in diesem Zeitfenster (Sekunden)


class Sessions:
    """Signierte Sitzungstoken. Der Schluessel lebt nur im Arbeitsspeicher,
    ein Neustart meldet also alle ab - das ist gewollt und guenstig."""

    def __init__(self, secret=None):
        self.secret = secret or secrets.token_bytes(32)

    def issue(self, ttl=SESSION_SECONDS):
        exp = str(int(time.time() + ttl))
        sig = hmac.new(self.secret, exp.encode(), hashlib.sha256).digest()
        return exp + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")

    def valid(self, token):
        try:
            exp, sig = (token or "").split(".", 1)
            if int(exp) < time.time():
                return False
        except (ValueError, AttributeError):
            return False
        want = hmac.new(self.secret, exp.encode(), hashlib.sha256).digest()
        want_b64 = base64.urlsafe_b64encode(want).decode().rstrip("=")
        return hmac.compare_digest(sig, want_b64)


def read_audit(path, limit=200):
    """Letzte Eintraege des Hausbuchs, neueste zuerst."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    out.reverse()
    return out


def build_gui(manager, settings, credentials, audit_path=None, sessions=None):
    sessions = sessions or Sessions()
    tries = {}

    def authed(request):
        return sessions.valid(request.cookies.get(COOKIE))

    def same_origin(request):
        """CSRF-Schutz: eigener Header plus Origin-Pruefung, dazu SameSite=Strict."""
        if request.headers.get("x-hausmeister") != "1":
            return False
        origin = request.headers.get("origin")
        if origin:
            host = request.headers.get("host", "")
            if not origin.endswith("//" + host):
                return False
        return True

    async def index(request):
        return HTMLResponse(PAGE)

    async def login(request):
        ip = request.client.host if request.client else "?"
        now = time.time()
        recent = [t for t in tries.get(ip, []) if now - t < TRY_WINDOW]
        tries[ip] = recent
        if len(recent) >= MAX_TRIES:
            return JSONResponse({"error": "Zu viele Fehlversuche. Bitte einige Minuten warten."}, 429)
        if not same_origin(request):
            return JSONResponse({"error": "Ungueltige Anfrage."}, 400)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not credentials.verify(str(body.get("password", ""))):
            tries[ip] = recent + [now]
            return JSONResponse({"error": "Falsches Passwort."}, 401)
        tries[ip] = []
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE, sessions.issue(), max_age=SESSION_SECONDS,
                        httponly=True, samesite="strict", path="/")
        return resp

    async def logout(request):
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    async def state(request):
        if not authed(request):
            return JSONResponse({"error": "not-authenticated"}, 401)
        cfg = settings.load()
        try:
            containers = [{k: c[k] for k in ("name", "state", "status", "image")}
                          for c in manager._containers()]
            error = None
        except Exception as e:
            containers, error = [], str(e)
        known = {c["name"] for c in containers}
        # Freigaben fuer inzwischen geloeschte Container trotzdem zeigen
        for name in cfg["containers"]:
            if name not in known:
                containers.append({"name": name, "state": "FEHLT", "status": "nicht mehr vorhanden",
                                   "image": "-"})
        containers.sort(key=lambda c: c["name"].lower())
        return JSONResponse({"settings": cfg, "containers": containers, "error": error})

    async def save(request):
        if not authed(request):
            return JSONResponse({"error": "not-authenticated"}, 401)
        if not same_origin(request):
            return JSONResponse({"error": "Ungueltige Anfrage."}, 400)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Ungueltige Daten."}, 400)
        saved = settings.save(body)
        if audit_path:
            manager._audit("settings", "-", "saved",
                           "read_only=%s, steuerbar=%d, logs=%d" % (
                               saved["read_only"],
                               sum(1 for f in saved["containers"].values() if f["manage"]),
                               sum(1 for f in saved["containers"].values() if f["logs"])))
        return JSONResponse({"ok": True, "settings": saved})

    async def audit(request):
        if not authed(request):
            return JSONResponse({"error": "not-authenticated"}, 401)
        limit = min(int(request.query_params.get("limit", 200) or 200), 1000)
        return JSONResponse({"entries": read_audit(audit_path, limit) if audit_path else []})

    async def session(request):
        return JSONResponse({"authenticated": authed(request),
                             "needsSetup": credentials.needs_setup(),
                             "setupOpen": credentials.setup_open()})

    async def setup(request):
        """Erstes Passwort setzen - nur mit dem Code aus dem Container-Log."""
        ip = request.client.host if request.client else "?"
        now = time.time()
        recent = [t for t in tries.get(ip, []) if now - t < TRY_WINDOW]
        if len(recent) >= MAX_TRIES:
            return JSONResponse({"error": "Zu viele Fehlversuche. Bitte einige Minuten warten."}, 429)
        if not same_origin(request):
            return JSONResponse({"error": "Ungueltige Anfrage."}, 400)
        try:
            body = await request.json()
        except Exception:
            body = {}
        ok, err = credentials.setup(str(body.get("code", "")), str(body.get("password", "")))
        if not ok:
            tries[ip] = recent + [now]
            manager._audit("gui-setup", "-", "denied", err)
            return JSONResponse({"error": err}, 400)
        tries[ip] = []
        manager._audit("gui-setup", "-", "ok", "Passwort gesetzt")
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE, sessions.issue(), max_age=SESSION_SECONDS,
                        httponly=True, samesite="strict", path="/")
        return resp

    async def change_password(request):
        if not authed(request):
            return JSONResponse({"error": "not-authenticated"}, 401)
        if not same_origin(request):
            return JSONResponse({"error": "Ungueltige Anfrage."}, 400)
        try:
            body = await request.json()
        except Exception:
            body = {}
        ok, err = credentials.change(str(body.get("old", "")), str(body.get("new", "")))
        manager._audit("gui-passwort", "-", "ok" if ok else "denied", "" if ok else err)
        return JSONResponse({"ok": True} if ok else {"error": err}, 200 if ok else 400)

    return Starlette(routes=[
        Route("/", index),
        Route("/api/session", session),
        Route("/api/login", login, methods=["POST"]),
        Route("/api/setup", setup, methods=["POST"]),
        Route("/api/password", change_password, methods=["POST"]),
        Route("/api/logout", logout, methods=["POST"]),
        Route("/api/state", state),
        Route("/api/settings", save, methods=["POST"]),
        Route("/api/audit", audit),
    ])


PAGE = """<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hausmeister</title>
<style>
  :root { color-scheme: light dark;
    --bg:#f4f5f7; --card:#fff; --fg:#1b1d21; --muted:#5f6672; --line:#dcdfe5;
    --accent:#eb6e28; --ok:#1b9e63; --warn:#c8311f; }
  @media (prefers-color-scheme: dark) { :root {
    --bg:#16181d; --card:#1f2229; --fg:#e8eaee; --muted:#9aa2b1; --line:#2e323b; } }
  * { box-sizing:border-box; }
  html,body { max-width:100%; overflow-x:hidden; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { display:flex; align-items:center; gap:12px; padding:14px 16px; border-bottom:1px solid var(--line); background:var(--card); position:sticky; top:0; z-index:5; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; font-weight:650; }
  .grow { flex:1 1 auto; }
  main { max-width:1000px; margin:0 auto; padding:16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; margin-bottom:16px; }
  h2 { font-size:15px; margin:0 0 12px; letter-spacing:.02em; text-transform:uppercase; color:var(--muted); }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:middle; }
  th { font-size:12px; text-transform:uppercase; color:var(--muted); font-weight:600; }
  .wrap { overflow-x:auto; }
  .item { display:flex; gap:12px; align-items:center; flex-wrap:wrap; padding:10px 0; border-bottom:1px solid var(--line); }
  .item .name { flex:1 1 220px; min-width:0; }
  .item .name b, .item .name .muted { overflow-wrap:anywhere; }
  .item .muted { max-width:100%; }
  .item .st { flex:0 1 auto; }
  .flags { display:flex; gap:16px; margin-left:auto; }
  .flags label { display:flex; align-items:center; gap:6px; font-size:13px; color:var(--muted); }
  .state { font-size:12px; padding:2px 8px; border-radius:999px; border:1px solid var(--line); color:var(--muted); }
  .RUNNING { color:var(--ok); border-color:currentColor; }
  .FEHLT { color:var(--warn); border-color:currentColor; }
  .muted { color:var(--muted); font-size:13px; }
  button { font:inherit; padding:8px 14px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--fg); cursor:pointer; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
  button:disabled { opacity:.5; cursor:default; }
  input[type=password], input[type=number] { font:inherit; padding:8px 10px; border-radius:8px; border:1px solid var(--line); background:var(--bg); color:var(--fg); }
  input[type=checkbox] { width:18px; height:18px; accent-color:var(--accent); }
  .row { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
  .danger { border-color:var(--warn); color:var(--warn); }
  .banner { background:var(--warn); color:#fff; padding:10px 16px; font-weight:600; }
  .log { font-family:ui-monospace,Consolas,monospace; font-size:12.5px; }
  #login { max-width:340px; margin:12vh auto; }
  .hide { display:none; }
</style></head><body>
<div id="notaus" class="banner hide">Not-Aus aktiv - der Assistent kann derzeit nichts starten oder stoppen.</div>
<header class="hide" id="bar">
  <h1>🧹 Hausmeister</h1><span class="muted" id="sub"></span><span class="grow"></span>
  <button id="save" class="primary" disabled>Speichern</button>
  <button id="logout">Abmelden</button>
</header>

<main id="login" class="hide">
  <div class="card">
    <h2>Anmeldung</h2>
    <form id="loginform" class="row">
      <input type="password" id="pw" placeholder="Passwort" autocomplete="current-password" required style="flex:1">
      <button class="primary" type="submit">Anmelden</button>
    </form>
    <p class="muted" id="loginerr"></p>
  </div>
</main>

<main id="setup" class="hide">
  <div class="card">
    <h2>Erste Einrichtung</h2>
    <p class="muted">Lege das Passwort für diese Oberfläche fest. Den <b>Einrichtungscode</b>
      findest du im Log des Containers: in Unraid auf das Container-Symbol klicken und „Logs“
      wählen, oder <code>docker logs hausmeister</code>. So kann nur jemand mit Zugriff auf den
      Server das Passwort setzen, nicht der Assistent, der diesen Port ebenfalls erreicht.</p>
    <form id="setupform">
      <div class="row"><input type="text" id="code" placeholder="Einrichtungscode" required style="flex:1" autocomplete="off"></div>
      <div class="row" style="margin-top:10px"><input type="password" id="np1" placeholder="Neues Passwort (mind. 10 Zeichen)" required style="flex:1" autocomplete="new-password"></div>
      <div class="row" style="margin-top:10px"><input type="password" id="np2" placeholder="Wiederholen" required style="flex:1" autocomplete="new-password"></div>
      <div class="row" style="margin-top:12px"><button class="primary" type="submit">Passwort festlegen</button></div>
    </form>
    <p class="muted" id="setuperr"></p>
  </div>
</main>

<main id="app" class="hide">
  <div class="card">
    <h2>Container</h2>
    <p class="muted">„Steuern“ erlaubt Start, Stopp und Neustart. „Logs“ erlaubt das Lesen der
      Logzeilen (Geheimnisse werden dabei immer geschwärzt).</p>
    <div id="containers"></div>
  </div>

  <div class="card">
    <h2>Regeln</h2>
    <div class="row">
      <label class="row"><input type="checkbox" id="readonly"> <b>Not-Aus</b></label>
      <span class="muted">sperrt sofort alle Schreibaktionen, unabhängig von den Haken oben</span>
    </div>
    <div class="row" style="margin-top:12px">
      <label class="row">Sperrzeit <input type="number" id="cooldown" min="0" max="3600" style="width:90px"> Sekunden</label>
      <span class="muted">Mindestabstand zwischen zwei Änderungen am selben Container</span>
    </div>
    <div class="row" style="margin-top:12px">
      <label class="row">Logzeilen höchstens <input type="number" id="maxlines" min="10" max="2000" style="width:90px"></label>
    </div>
  </div>

  <div class="card">
    <h2>Passwort ändern</h2>
    <form id="pwform" class="row">
      <input type="password" id="oldpw" placeholder="Bisher" autocomplete="current-password" required>
      <input type="password" id="newpw" placeholder="Neu (mind. 10 Zeichen)" autocomplete="new-password" required>
      <button type="submit">Ändern</button>
      <span class="muted" id="pwmsg"></span>
    </form>
  </div>

  <div class="card">
    <h2>Hausbuch</h2>
    <p class="muted">Jede Schreibaktion und jeder abgelehnte Versuch, neueste zuerst.</p>
    <div class="wrap"><table class="log"><thead><tr><th>Zeit</th><th>Aktion</th><th>Container</th><th>Ergebnis</th><th>Detail</th></tr></thead>
      <tbody id="audit"></tbody></table></div>
  </div>
</main>

<script>
const $ = s => document.querySelector(s);
const api = (url, opts={}) => fetch(url, {credentials:'same-origin', headers:{'X-Hausmeister':'1','Content-Type':'application/json'}, ...opts});
let cfg = null, dirty = false;

function markDirty(){ dirty = true; $('#save').disabled = false; }

async function boot(){
  const s = await (await api('/api/session')).json();
  if (s.authenticated) return showApp();
  if (s.needsSetup) {
    $('#setup').classList.remove('hide'); $('#code').focus();
    if (!s.setupOpen) $('#setuperr').textContent =
      'Das Zeitfenster für die Einrichtung ist abgelaufen. Container neu starten, dann steht ein neuer Code im Log.';
  } else { $('#login').classList.remove('hide'); $('#pw').focus(); }
}

$('#setupform').addEventListener('submit', async e => {
  e.preventDefault();
  if ($('#np1').value !== $('#np2').value) { $('#setuperr').textContent = 'Die Passwörter stimmen nicht überein.'; return; }
  const r = await api('/api/setup', {method:'POST', body: JSON.stringify({code: $('#code').value.trim(), password: $('#np1').value})});
  const d = await r.json();
  if (r.ok) { $('#setup').classList.add('hide'); showApp(); }
  else $('#setuperr').textContent = d.error || 'Einrichtung fehlgeschlagen.';
});

$('#pwform').addEventListener('submit', async e => {
  e.preventDefault();
  const r = await api('/api/password', {method:'POST', body: JSON.stringify({old: $('#oldpw').value, new: $('#newpw').value})});
  const d = await r.json();
  $('#pwmsg').textContent = r.ok ? 'Passwort geändert.' : (d.error || 'Fehlgeschlagen.');
  if (r.ok) { $('#oldpw').value = ''; $('#newpw').value = ''; }
});

$('#loginform').addEventListener('submit', async e => {
  e.preventDefault();
  const r = await api('/api/login', {method:'POST', body: JSON.stringify({password: $('#pw').value})});
  const d = await r.json();
  if (r.ok) { $('#login').classList.add('hide'); showApp(); }
  else { $('#loginerr').textContent = d.error || 'Anmeldung fehlgeschlagen.'; $('#pw').select(); }
});

$('#logout').addEventListener('click', async () => { await api('/api/logout', {method:'POST'}); location.reload(); });

async function showApp(){
  $('#app').classList.remove('hide'); $('#bar').classList.remove('hide');
  await load(); await loadAudit();
  setInterval(() => { if (!dirty) { load(); loadAudit(); } }, 15000);
}

async function load(){
  const r = await api('/api/state');
  if (r.status === 401) return location.reload();
  const d = await r.json();
  cfg = d.settings;
  $('#sub').textContent = d.error ? ('Unraid: ' + d.error) : (d.containers.length + ' Container');
  $('#readonly').checked = cfg.read_only;
  $('#cooldown').value = cfg.cooldown_seconds;
  $('#maxlines').value = cfg.max_log_lines;
  $('#notaus').classList.toggle('hide', !cfg.read_only);
  const tb = $('#containers'); tb.innerHTML = '';
  for (const c of d.containers){
    const f = cfg.containers[c.name] || {manage:false, logs:false};
    const row = document.createElement('div');
    row.className = 'item';
    row.innerHTML = `<div class="name"><b>${esc(c.name)}</b><div class="muted">${esc(c.image)}</div></div>
      <div class="st"><span class="state ${esc(c.state)}">${esc(c.state)}</span><div class="muted">${esc(c.status)}</div></div>
      <div class="flags">
        <label><input type="checkbox" data-n="${esc(c.name)}" data-k="manage" ${f.manage?'checked':''}> Steuern</label>
        <label><input type="checkbox" data-n="${esc(c.name)}" data-k="logs" ${f.logs?'checked':''}> Logs</label>
      </div>`;
    tb.appendChild(row);
  }
  tb.querySelectorAll('input').forEach(el => el.addEventListener('change', () => {
    const n = el.dataset.n, k = el.dataset.k;
    cfg.containers[n] = cfg.containers[n] || {manage:false, logs:false};
    cfg.containers[n][k] = el.checked;
    if (!cfg.containers[n].manage && !cfg.containers[n].logs) delete cfg.containers[n];
    markDirty();
  }));
}

for (const [id, key, num] of [['#readonly','read_only',false], ['#cooldown','cooldown_seconds',true], ['#maxlines','max_log_lines',true]])
  $(id).addEventListener('change', e => { cfg[key] = num ? parseInt(e.target.value||0,10) : e.target.checked; markDirty(); });

$('#save').addEventListener('click', async () => {
  $('#save').disabled = true;
  const r = await api('/api/settings', {method:'POST', body: JSON.stringify(cfg)});
  if (r.ok) { dirty = false; await load(); await loadAudit(); }
  else { $('#save').disabled = false; alert('Speichern fehlgeschlagen.'); }
});

async function loadAudit(){
  const r = await api('/api/audit?limit=100');
  if (!r.ok) return;
  const d = await r.json();
  $('#audit').innerHTML = d.entries.map(e => `<tr><td>${esc(local(e.ts))}</td><td>${esc(e.action)}</td>
    <td>${esc(e.container)}</td><td>${esc(e.result)}</td><td class="muted">${esc(e.detail||'')}</td></tr>`).join('')
    || '<tr><td colspan="5" class="muted">Noch nichts passiert.</td></tr>';
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const local = ts => { const d = new Date(ts); return isNaN(d) ? ts : d.toLocaleString('de-DE'); };
window.addEventListener('beforeunload', e => { if (dirty) e.preventDefault(); });
boot();
</script></body></html>
"""
