"""Schwaerzt typische Geheimnisse in Logzeilen, bevor sie an Claude gehen.

Bewusst grosszuegig: lieber eine harmlose Zeile zu viel schwaerzen als ein
Passwort durchlassen. Ersetzt wird nur der Wert, der Schluessel bleibt lesbar,
damit die Zeile fuer die Diagnose noch Sinn ergibt.
"""
import re

MASK = "[REDACTED]"

# Farb- und Steuersequenzen (z. B. von Go-Programmen wie Stash) rausnehmen -
# im Chat sind sie nur Rauschen.
_ANSI = re.compile("\x1b\\[[0-9;?]*[A-Za-z]|\x1b\\][^\x07]*\x07|[\x00-\x08\x0b-\x1f\x7f]")

_KEYS = (r"pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
         r"client[_-]?secret|auth(?:orization)?|session(?:id)?|cookie|private[_-]?key|credential")

_PATTERNS = [
    # Authorization: Bearer xyz / Basic xyz
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + MASK),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), MASK),
    # Set-Cookie / Cookie-Header komplett
    (re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*[^\r\n]+"), r"\1: " + MASK),
    # schluessel=wert, schluessel: wert, "schluessel": "wert"
    (re.compile(r"""(?ix)
        (["']?[\w.-]*(?:""" + _KEYS + r""")[\w.-]*["']?\s*[:=]\s*)
        ("[^"]*"|'[^']*'|[^\s,;&}\]]+)"""), r"\1" + MASK),
    # Zugangsdaten in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@"), r"\1" + MASK + "@"),
    # Query-Parameter wie ?token=... / &api_key=...
    (re.compile(r"(?i)([?&](?:" + _KEYS + r")=)[^&\s]+"), r"\1" + MASK),
    # lange Hex-/Base64-Bloecke (typisch fuer API-Keys)
    (re.compile(r"\b[a-fA-F0-9]{32,}\b"), MASK),
]


def redact(text):
    text = _ANSI.sub("", text)
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text
