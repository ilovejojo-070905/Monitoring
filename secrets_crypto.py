"""Encryption at rest for credentials (directive sections 9/31).

Uses Fernet (AES-128-CBC + HMAC, from the already-installed `cryptography`
package -- no new dependency). The key lives in its own dotfile, the same
pattern already used for the Flask session secret key (server.py's
_load_or_create_secret_key): outside anything Flask serves, never in the
database, never in source code. Keeping it in a *separate* file from
infrasight.db means a copy of the DB alone (e.g. a backup file) is useless
without also having this key.
"""
import os

from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_KEY_PATH = os.path.join(BASE_DIR, '.infrasight_credentials_key')

_fernet = None


def _load_or_create_key():
    if os.path.exists(_KEY_PATH):
        with open(_KEY_PATH, 'rb') as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(_KEY_PATH, 'wb') as f:
        f.write(key)
    return key


def _get_fernet():
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt(plaintext):
    if plaintext is None:
        return None
    return _get_fernet().encrypt(plaintext.encode('utf-8')).decode('ascii')


def decrypt(ciphertext):
    """Returns None for None/empty input. Raises nothing on a value that
    isn't a valid Fernet token -- returns it unchanged instead, so a row that
    somehow predates encryption (or was hand-edited) degrades to "treated as
    plaintext" rather than a hard error taking down a poll cycle."""
    if not ciphertext:
        return ciphertext
    try:
        return _get_fernet().decrypt(ciphertext.encode('ascii')).decode('utf-8')
    except (InvalidToken, ValueError):
        return ciphertext


def is_encrypted(value):
    if not value:
        return False
    try:
        _get_fernet().decrypt(value.encode('ascii'))
        return True
    except Exception:
        return False
