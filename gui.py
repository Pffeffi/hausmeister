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
  :root{
    color-scheme: light dark;
    --bg:#eef0f4; --bg2:#e4e7ee; --card:#fff; --fg:#14161a; --muted:#666e7d;
    --line:#dfe3ea; --line2:#eef1f6; --accent:#ec6a2c; --accent2:#f59f3c;
    --ok:#15a05c; --warn:#d13b28; --shadow:0 1px 2px rgba(16,20,30,.06), 0 8px 24px rgba(16,20,30,.07);
    --r:14px;
  }
  @media (prefers-color-scheme: dark){ :root{
    --bg:#101319; --bg2:#0b0d12; --card:#181c24; --fg:#e9ecf2; --muted:#98a1b2;
    --line:#262c37; --line2:#1e232c; --shadow:0 1px 2px rgba(0,0,0,.4), 0 10px 30px rgba(0,0,0,.35);
  }}
  *{box-sizing:border-box}
  html,body{max-width:100%; overflow-x:hidden}
  body{margin:0; color:var(--fg); font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
       background:radial-gradient(1100px 600px at 12% -10%, color-mix(in srgb, var(--accent) 14%, transparent), transparent 60%), linear-gradient(180deg, var(--bg), var(--bg2));
       background-attachment:fixed; -webkit-font-smoothing:antialiased}

  /* --- Kopfzeile ------------------------------------------------------- */
  header{position:sticky; top:0; z-index:10; display:flex; align-items:center; gap:14px; flex-wrap:wrap;
         padding:12px 18px; background:color-mix(in srgb, var(--card) 82%, transparent);
         backdrop-filter:blur(12px); border-bottom:1px solid var(--line)}
  .brand{display:flex; align-items:center; gap:10px; font-weight:680; font-size:17px; letter-spacing:-.01em}
  .brand svg{width:30px; height:30px; flex:none}
  .pill{font-size:12px; font-weight:600; padding:3px 10px; border-radius:999px; border:1px solid var(--line);
        color:var(--muted); background:var(--line2); white-space:nowrap}
  .pill.ok{color:var(--ok); border-color:color-mix(in srgb, var(--ok) 35%, var(--line)); background:color-mix(in srgb, var(--ok) 10%, transparent)}
  .pill.warn{color:var(--warn); border-color:color-mix(in srgb, var(--warn) 40%, var(--line)); background:color-mix(in srgb, var(--warn) 10%, transparent)}
  .grow{flex:1 1 auto}

  /* --- Bausteine -------------------------------------------------------- */
  main{max-width:940px; margin:0 auto; padding:20px 16px 60px}
  .card{background:var(--card); border:1px solid var(--line); border-radius:var(--r); box-shadow:var(--shadow);
        padding:18px; margin-bottom:18px}
  .card h2{margin:0 0 4px; font-size:14px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; color:var(--muted)}
  .card .sub{margin:0 0 14px; color:var(--muted); font-size:13.5px}
  button{font:inherit; font-weight:600; padding:9px 16px; border-radius:10px; border:1px solid var(--line);
         background:var(--card); color:var(--fg); cursor:pointer; transition:.15s}
  button:hover:not(:disabled){border-color:var(--muted)}
  button.primary{border:0; color:#fff; background:linear-gradient(135deg, var(--accent), var(--accent2));
                 box-shadow:0 6px 16px color-mix(in srgb, var(--accent) 35%, transparent)}
  button.primary:hover:not(:disabled){filter:brightness(1.06)}
  button:disabled{opacity:.45; cursor:default; box-shadow:none}
  input[type=text],input[type=password],input[type=number],input[type=search]{
    font:inherit; padding:9px 12px; border-radius:10px; border:1px solid var(--line);
    background:var(--line2); color:var(--fg); transition:.15s}
  input:focus{outline:none; border-color:var(--accent); background:var(--card);
              box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent)}
  .row{display:flex; gap:12px; align-items:center; flex-wrap:wrap}
  .muted{color:var(--muted); font-size:13px}
  .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}

  /* --- Schalter ---------------------------------------------------------- */
  .sw{position:relative; display:inline-flex; align-items:center; gap:8px; cursor:pointer; user-select:none;
      font-size:13px; color:var(--muted)}
  .sw input{appearance:none; -webkit-appearance:none; margin:0; width:40px; height:23px; border-radius:999px;
            background:var(--line); border:1px solid var(--line); cursor:pointer; transition:.18s; flex:none}
  .sw input::after{content:""; position:absolute; left:3px; top:50%; translate:0 -50%; width:17px; height:17px;
                   border-radius:50%; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,.35); transition:.18s}
  .sw input:checked{background:linear-gradient(135deg, var(--accent), var(--accent2)); border-color:transparent}
  .sw input:checked::after{left:20px}
  .sw input:focus-visible{outline:2px solid var(--accent); outline-offset:2px}
  .sw:has(input:checked){color:var(--fg); font-weight:600}

  /* --- Containerliste ---------------------------------------------------- */
  .item{display:flex; gap:14px; align-items:center; flex-wrap:wrap; padding:12px 10px; border-radius:11px;
        border:1px solid transparent; transition:.15s}
  .item:hover{background:var(--line2); border-color:var(--line)}
  .item + .item{margin-top:2px}
  .dot{width:9px; height:9px; border-radius:50%; background:var(--muted); flex:none; box-shadow:0 0 0 4px color-mix(in srgb, var(--muted) 15%, transparent)}
  .dot.RUNNING{background:var(--ok); box-shadow:0 0 0 4px color-mix(in srgb, var(--ok) 18%, transparent)}
  .dot.FEHLT{background:var(--warn); box-shadow:0 0 0 4px color-mix(in srgb, var(--warn) 18%, transparent)}
  .nm{flex:1 1 210px; min-width:0}
  .nm b{font-weight:640; overflow-wrap:anywhere}
  .nm .meta{color:var(--muted); font-size:12.5px; overflow-wrap:anywhere}
  .flags{display:flex; gap:18px; margin-left:auto}

  /* --- Hausbuch ---------------------------------------------------------- */
  .log{display:grid; gap:2px}
  .entry{display:flex; gap:12px; align-items:baseline; flex-wrap:wrap; padding:9px 10px; border-radius:10px}
  .entry:nth-child(odd){background:var(--line2)}
  .entry .t{color:var(--muted); font-size:12.5px; flex:none; width:132px}
  .tag{font-size:11.5px; font-weight:700; letter-spacing:.03em; text-transform:uppercase; padding:2px 8px;
       border-radius:6px; background:var(--line); color:var(--muted); flex:none}
  .tag.ok{background:color-mix(in srgb, var(--ok) 15%, transparent); color:var(--ok)}
  .tag.denied,.tag.error{background:color-mix(in srgb, var(--warn) 15%, transparent); color:var(--warn)}
  .tag.saved{background:color-mix(in srgb, var(--accent) 15%, transparent); color:var(--accent)}

  /* --- Anmeldung / Einrichtung ------------------------------------------- */
  .gate{max-width:420px; margin:9vh auto 0}
  .gate .card{padding:26px}
  .gate .logo{display:flex; justify-content:center; margin-bottom:14px}
  .gate .logo svg{width:56px; height:56px}
  .gate h1{margin:0 0 6px; text-align:center; font-size:21px; letter-spacing:-.02em}
  .gate .sub{text-align:center}
  .err{color:var(--warn); font-size:13.5px; min-height:20px; margin:10px 0 0}
  .stack{display:grid; gap:10px}
  .stack input{width:100%}
  .banner{padding:11px 18px; font-weight:650; color:#fff;
          background:linear-gradient(135deg, var(--warn), #ef6a4f)}
  .hide{display:none !important}
  svg.hide{position:absolute; width:0; height:0; display:block !important; overflow:hidden}
  @media (max-width:560px){ .entry .t{width:auto} .flags{margin-left:0; width:100%} }
</style></head><body>

<svg class="hide" aria-hidden="true">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#f08b3a"/><stop offset="1" stop-color="#e2571f"/></linearGradient></defs>
  <symbol id="ic" viewBox="0 0 48 48">
  <rect x="2" y="2" width="44" height="44" rx="12" fill="url(#g)"/>
  <g fill="#fff">
    <circle cx="18" cy="18" r="7.4"/><circle cx="18" cy="18" r="2.9" fill="#e2571f"/>
    <rect x="21.4" y="21.4" width="16.5" height="4.6" rx="2.3" transform="rotate(45 21.4 21.4)"/>
    <rect x="28.5" y="26.5" width="4.2" height="7.6" rx="2.1" transform="rotate(45 28.5 26.5)"/>
    <rect x="32.8" y="30.8" width="4.2" height="7.6" rx="2.1" transform="rotate(45 32.8 30.8)"/>
  </g></symbol></svg>

<div id="notaus" class="banner hide">Not-Aus aktiv — der Assistent kann derzeit nichts starten oder stoppen.</div>

<header id="bar" class="hide">
  <span class="brand"><svg><use href="#ic"/></svg> Hausmeister</span>
  <span class="pill" id="sub">lädt …</span>
  <span class="pill warn hide" id="pillNotaus">Not-Aus</span>
  <span class="grow"></span>
  <button id="save" class="primary" disabled>Speichern</button>
  <button id="logout">Abmelden</button>
</header>

<main id="login" class="gate hide">
  <div class="card">
    <div class="logo"><svg><use href="#ic"/></svg></div>
    <h1>Hausmeister</h1>
    <p class="sub muted">Bitte anmelden, um Freigaben und Hausbuch zu sehen.</p>
    <form id="loginform" class="stack">
      <input type="password" id="pw" placeholder="Passwort" autocomplete="current-password" required>
      <button class="primary" type="submit">Anmelden</button>
    </form>
    <p class="err" id="loginerr"></p>
  </div>
</main>

<main id="setup" class="gate hide">
  <div class="card">
    <div class="logo"><svg><use href="#ic"/></svg></div>
    <h1>Erste Einrichtung</h1>
    <p class="sub muted">Lege das Passwort für diese Oberfläche fest. Den <b>Einrichtungscode</b> findest du
      im Log des Containers — in Unraid auf das Container-Symbol klicken und „Logs“ wählen, oder
      <span class="mono">docker logs hausmeister</span>. So kann nur jemand mit Zugriff auf den Server das
      Passwort setzen, nicht der Assistent, der denselben Port erreicht.</p>
    <form id="setupform" class="stack">
      <input type="text" id="code" placeholder="Einrichtungscode" required autocomplete="off" spellcheck="false">
      <input type="password" id="np1" placeholder="Neues Passwort (mind. 10 Zeichen)" required autocomplete="new-password">
      <input type="password" id="np2" placeholder="Wiederholen" required autocomplete="new-password">
      <button class="primary" type="submit">Passwort festlegen</button>
    </form>
    <p class="err" id="setuperr"></p>
  </div>
</main>

<main id="app" class="hide">
  <div class="card">
    <div class="row" style="margin-bottom:10px">
      <div><h2 style="margin:0">Container</h2></div>
      <span class="grow"></span>
      <input type="search" id="filter" placeholder="Filtern …" style="width:180px">
    </div>
    <p class="sub"><b>Steuern</b> erlaubt Start, Stopp und Neustart. <b>Logs</b> erlaubt das Lesen der
      Logzeilen — Geheimnisse werden dabei immer geschwärzt.</p>
    <div id="containers"></div>
  </div>

  <div class="card">
    <h2>Regeln</h2>
    <p class="sub">Gelten sofort, ohne Neustart.</p>
    <div class="row" style="gap:10px">
      <label class="sw"><input type="checkbox" id="readonly"> Not-Aus</label>
      <span class="muted">sperrt alle Schreibaktionen, unabhängig von den Schaltern oben</span>
    </div>
    <div class="row" style="margin-top:14px">
      <label class="row" style="gap:8px">Sperrzeit
        <input type="number" id="cooldown" min="0" max="3600" style="width:92px"> Sekunden</label>
      <span class="muted">Mindestabstand zwischen zwei Änderungen am selben Container</span>
    </div>
    <div class="row" style="margin-top:12px">
      <label class="row" style="gap:8px">Logzeilen höchstens
        <input type="number" id="maxlines" min="10" max="2000" style="width:92px"></label>
    </div>
  </div>

  <div class="card">
    <h2>Passwort ändern</h2>
    <form id="pwform" class="row" style="margin-top:12px">
      <input type="password" id="oldpw" placeholder="Bisher" autocomplete="current-password" required>
      <input type="password" id="newpw" placeholder="Neu (mind. 10 Zeichen)" autocomplete="new-password" required>
      <button type="submit">Ändern</button>
      <span class="muted" id="pwmsg"></span>
    </form>
  </div>

  <div class="card">
    <h2>Hausbuch</h2>
    <p class="sub">Jede Schreibaktion und jeder abgelehnte Versuch, neueste zuerst.</p>
    <div class="log" id="audit"></div>
  </div>
</main>

<script>
const $ = s => document.querySelector(s);
const api = (url, opts={}) => fetch(url, {credentials:'same-origin',
  headers:{'X-Hausmeister':'1','Content-Type':'application/json'}, ...opts});
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const local = ts => { const d = new Date(ts); return isNaN(d) ? ts : d.toLocaleString('de-DE'); };
let cfg = null, dirty = false;
const markDirty = () => { dirty = true; $('#save').disabled = false; };

async function boot(){
  const s = await (await api('/api/session')).json();
  if (s.authenticated) return showApp();
  if (s.needsSetup){
    $('#setup').classList.remove('hide'); $('#code').focus();
    if (!s.setupOpen) $('#setuperr').textContent =
      'Das Zeitfenster für die Einrichtung ist abgelaufen. Container neu starten, dann steht ein neuer Code im Log.';
  } else { $('#login').classList.remove('hide'); $('#pw').focus(); }
}

$('#loginform').addEventListener('submit', async e => {
  e.preventDefault();
  const r = await api('/api/login', {method:'POST', body: JSON.stringify({password: $('#pw').value})});
  const d = await r.json();
  if (r.ok){ $('#login').classList.add('hide'); showApp(); }
  else { $('#loginerr').textContent = d.error || 'Anmeldung fehlgeschlagen.'; $('#pw').select(); }
});

$('#setupform').addEventListener('submit', async e => {
  e.preventDefault();
  if ($('#np1').value !== $('#np2').value){ $('#setuperr').textContent = 'Die Passwörter stimmen nicht überein.'; return; }
  const r = await api('/api/setup', {method:'POST', body: JSON.stringify({code: $('#code').value.trim(), password: $('#np1').value})});
  const d = await r.json();
  if (r.ok){ $('#setup').classList.add('hide'); showApp(); }
  else $('#setuperr').textContent = d.error || 'Einrichtung fehlgeschlagen.';
});

$('#pwform').addEventListener('submit', async e => {
  e.preventDefault();
  const r = await api('/api/password', {method:'POST', body: JSON.stringify({old: $('#oldpw').value, new: $('#newpw').value})});
  const d = await r.json();
  $('#pwmsg').textContent = r.ok ? 'Passwort geändert.' : (d.error || 'Fehlgeschlagen.');
  if (r.ok){ $('#oldpw').value = ''; $('#newpw').value = ''; }
});

$('#logout').addEventListener('click', async () => { await api('/api/logout', {method:'POST'}); location.reload(); });

async function showApp(){
  $('#app').classList.remove('hide'); $('#bar').classList.remove('hide');
  await load(); await loadAudit();
  setInterval(() => { if (!dirty){ load(); loadAudit(); } }, 15000);
}

async function load(){
  const r = await api('/api/state');
  if (r.status === 401) return location.reload();
  const d = await r.json();
  cfg = d.settings;
  const frei = Object.values(cfg.containers).filter(f => f.manage || f.logs).length;
  $('#sub').textContent = d.error ? ('Unraid: ' + d.error)
    : `${d.containers.length} Container · ${frei} freigegeben`;
  $('#sub').className = 'pill' + (d.error ? ' warn' : '');
  $('#readonly').checked = cfg.read_only;
  $('#cooldown').value = cfg.cooldown_seconds;
  $('#maxlines').value = cfg.max_log_lines;
  $('#notaus').classList.toggle('hide', !cfg.read_only);
  $('#pillNotaus').classList.toggle('hide', !cfg.read_only);

  const tb = $('#containers'); tb.innerHTML = '';
  for (const c of d.containers){
    const f = cfg.containers[c.name] || {manage:false, logs:false};
    const row = document.createElement('div');
    row.className = 'item'; row.dataset.name = c.name.toLowerCase();
    row.innerHTML = `<span class="dot ${esc(c.state)}" title="${esc(c.state)}"></span>
      <div class="nm"><b>${esc(c.name)}</b>
        <div class="meta">${esc(c.status)} · <span class="mono">${esc(c.image)}</span></div></div>
      <div class="flags">
        <label class="sw"><input type="checkbox" data-n="${esc(c.name)}" data-k="manage" ${f.manage?'checked':''}> Steuern</label>
        <label class="sw"><input type="checkbox" data-n="${esc(c.name)}" data-k="logs" ${f.logs?'checked':''}> Logs</label>
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
  applyFilter();
}

$('#filter').addEventListener('input', applyFilter);
function applyFilter(){
  const q = $('#filter').value.trim().toLowerCase();
  document.querySelectorAll('#containers .item').forEach(el =>
    el.classList.toggle('hide', !!q && !el.dataset.name.includes(q)));
}

for (const [id, key, num] of [['#readonly','read_only',false], ['#cooldown','cooldown_seconds',true], ['#maxlines','max_log_lines',true]])
  $(id).addEventListener('change', e => {
    cfg[key] = num ? parseInt(e.target.value||0, 10) : e.target.checked;
    if (key === 'read_only'){ $('#notaus').classList.toggle('hide', !cfg.read_only); $('#pillNotaus').classList.toggle('hide', !cfg.read_only); }
    markDirty();
  });

$('#save').addEventListener('click', async () => {
  $('#save').disabled = true;
  const r = await api('/api/settings', {method:'POST', body: JSON.stringify(cfg)});
  if (r.ok){ dirty = false; await load(); await loadAudit(); }
  else { $('#save').disabled = false; alert('Speichern fehlgeschlagen.'); }
});

async function loadAudit(){
  const r = await api('/api/audit?limit=100');
  if (!r.ok) return;
  const d = await r.json();
  $('#audit').innerHTML = d.entries.map(e => `<div class="entry">
      <span class="t">${esc(local(e.ts))}</span>
      <span class="tag ${esc(e.result)}">${esc(e.result)}</span>
      <b>${esc(e.action)}</b>
      <span>${esc(e.container === '-' ? '' : e.container)}</span>
      <span class="muted">${esc(e.detail || '')}</span>
    </div>`).join('') || '<p class="muted">Noch nichts passiert.</p>';
}

window.addEventListener('beforeunload', e => { if (dirty) e.preventDefault(); });
boot();
</script></body></html>
"""
