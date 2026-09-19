"""Duenner Client fuer die Unraid-GraphQL-API (Unraid 7.x, API 4.x).

Nur die Abfragen, die der MCP-Server wirklich braucht. Schema-Stand geprueft
gegen unraid/api v4.35.1 (generated-schema.graphql):
  - docker.containers / docker.logs(id, tail)          -> DOCKER:READ_ANY
  - docker.start(id) / docker.stop(id)                 -> DOCKER:UPDATE_ANY
  - metrics { cpu memory temperature }                 -> INFO:READ_ANY
  - array { state disks ... }                          -> ARRAY:READ_ANY
Es gibt keine restart-Mutation; Restart = stop + start (siehe manager.py).
"""
import json
import ssl
import urllib.error
import urllib.request


class UnraidError(Exception):
    pass


class UnraidClient:
    def __init__(self, url, api_key, verify_tls=False, ca_file=None, timeout=20):
        base = url.rstrip("/")
        self.endpoint = base if base.endswith("/graphql") else base + "/graphql"
        self.api_key = api_key
        self.timeout = timeout
        if ca_file:
            self.ssl_ctx = ssl.create_default_context(cafile=ca_file)
        elif verify_tls:
            self.ssl_ctx = ssl.create_default_context()
        else:
            # Unraid liefert im LAN ein selbstsigniertes Zertifikat.
            self.ssl_ctx = ssl.create_default_context()
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def query(self, query, variables=None):
        body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint, data=body, method="POST",
            headers={"Content-Type": "application/json", "x-api-key": self.api_key,
                     "User-Agent": "hausmeister"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                d = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                d = json.loads(e.read().decode("utf-8"))
            except Exception:
                raise UnraidError("Unraid-API HTTP %s" % e.code) from None
        except Exception as e:
            raise UnraidError("Unraid nicht erreichbar (%s)" % e.__class__.__name__) from None
        if d.get("errors") and not d.get("data"):
            raise UnraidError(d["errors"][0].get("message", "GraphQL-Fehler"))
        return d.get("data") or {}

    # --- Docker -------------------------------------------------------------

    def containers(self):
        data = self.query("{ docker { containers { id names image state status autoStart "
                          "isUpdateAvailable } } }")
        out = []
        for c in (data.get("docker") or {}).get("containers") or []:
            names = c.get("names") or []
            out.append({
                "id": c["id"],
                "name": (names[0] if names else c["id"]).lstrip("/"),
                "image": c.get("image"),
                "state": c.get("state"),
                "status": c.get("status"),
                "autoStart": c.get("autoStart"),
                "updateAvailable": c.get("isUpdateAvailable"),
            })
        return out

    def logs(self, container_id, tail):
        data = self.query(
            "query($id: PrefixedID!, $tail: Int){ docker { logs(id: $id, tail: $tail) "
            "{ lines { timestamp message } } } }",
            {"id": container_id, "tail": tail})
        return ((data.get("docker") or {}).get("logs") or {}).get("lines") or []

    def start(self, container_id):
        data = self.query("mutation($id: PrefixedID!){ docker { start(id: $id) { state status } } }",
                          {"id": container_id})
        return (data.get("docker") or {}).get("start") or {}

    def stop(self, container_id):
        data = self.query("mutation($id: PrefixedID!){ docker { stop(id: $id) { state status } } }",
                          {"id": container_id})
        return (data.get("docker") or {}).get("stop") or {}

    # --- Server -------------------------------------------------------------

    def metrics(self):
        return self.query(
            "{ metrics { cpu { percentTotal } "
            "memory { percentTotal total used available swapTotal swapUsed } "
            "temperature { sensors { name current { value } } } } "
            "info { os { uptime } } "
            "array { state capacity { kilobytes { used total } } "
            "disks { name temp status numErrors } parities { name temp status numErrors } "
            "caches { name temp status numErrors } } }")
