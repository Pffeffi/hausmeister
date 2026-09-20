"""Erzeugt den Passwort-Hash fuer die Weboberflaeche.

    python hashpw.py

Die Eingabe wird nicht angezeigt und nicht gespeichert. Die ausgegebene Zeile
kommt in die .env neben die docker-compose.yml. Im Container liegt danach nur
der Hash, nie das Passwort.
"""
import getpass
import sys

from gui import hash_password


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
