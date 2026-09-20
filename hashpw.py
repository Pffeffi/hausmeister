"""Passwort-Hash fuer die Weboberflaeche - braucht nur die Standardbibliothek.

    python3 hashpw.py

Die Eingabe wird nicht angezeigt und nirgends gespeichert. Die ausgegebene
Zeile kommt in die .env neben die docker-compose.yml. Im Container liegt
danach nur der Hash, nie das Passwort.
"""
import getpass
import hashlib
import hmac
import secrets
import sys

SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT)
    return "scrypt$%s$%s" % (salt.hex(), dk.hex())


def check_password(password, stored):
    try:
        algo, salt_hex, want = (stored or "").split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), **SCRYPT)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), want)


def main():
    pw = getpass.getpass("Neues GUI-Passwort: ")
    if len(pw) < 10:
        sys.exit("Zu kurz - bitte mindestens 10 Zeichen.")
    if pw != getpass.getpass("Wiederholen: "):
        sys.exit("Die Eingaben stimmen nicht ueberein.")
    print("\nDiese Zeile in die .env eintragen:\n")
    print("GUI_PASSWORD_HASH=" + hash_password(pw))


if __name__ == "__main__":
    main()
