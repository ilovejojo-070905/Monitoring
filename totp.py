"""RFC 4226 (HOTP) / RFC 6238 (TOTP) implementation for 5-1's 2FA, built on
stdlib only (hmac/struct/base64) -- see requirements.txt's comment on
qrcode==8.0 for why hand-rolling THIS specific piece of math (not the QR
encoding) was the right call: it's ~30 lines, fully specified by the RFCs,
and verified at implementation time against every RFC 4226 Appendix D test
vector (counters 0-9 against the RFC's own secret all match exactly).

Lives at the project root next to secrets_crypto.py/validation.py -- same
"pure function module, no DB/network access, safe to import from anywhere"
shape as those.
"""
import base64
import hmac
import hashlib
import os
import struct
import time
import urllib.parse

DIGITS = 6
PERIOD_SEC = 30
# Clock-drift tolerance: also accept the previous/next time step, so a
# phone's clock being a few seconds off (or the verify request landing just
# after a 30s boundary) doesn't produce a false "invalid code".
WINDOW = 1


def generate_secret():
    """160 bits (RFC 4226's own recommended HOTP secret length), base32
    without padding -- the format every authenticator app expects for
    manual entry and in an otpauth:// URI."""
    return base64.b32encode(os.urandom(20)).decode('ascii').rstrip('=')


def _hotp(secret_b32, counter, digits=DIGITS):
    padded = secret_b32 + '=' * (-len(secret_b32) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_now(secret_b32, at=None):
    counter = int((at if at is not None else time.time()) // PERIOD_SEC)
    return _hotp(secret_b32, counter)


def verify_totp(secret_b32, code, at=None):
    """Constant-time compare against the current step and +-WINDOW steps
    around it. Returns False for anything malformed rather than raising --
    a verify endpoint should treat "garbage input" and "wrong code"
    identically to an attacker."""
    if not secret_b32 or not code:
        return False
    code = code.strip()
    if not code.isdigit() or len(code) != DIGITS:
        return False
    now = at if at is not None else time.time()
    counter = int(now // PERIOD_SEC)
    for step in range(-WINDOW, WINDOW + 1):
        try:
            candidate = _hotp(secret_b32, counter + step)
        except Exception:
            return False
        if hmac.compare_digest(candidate, code):
            return True
    return False


def provisioning_uri(secret_b32, account_name, issuer='InfraSight'):
    """The 'otpauth://' Key URI Format every authenticator app (Google
    Authenticator, Authy, 1Password, ...) scans from a QR code or accepts
    pasted as a link. Both the label and the issuer query param carry the
    issuer, which is the documented convention (older apps only look at the
    label prefix; newer ones prefer the explicit param)."""
    label = urllib.parse.quote(f'{issuer}:{account_name}')
    params = urllib.parse.urlencode({
        'secret': secret_b32, 'issuer': issuer, 'algorithm': 'SHA1',
        'digits': DIGITS, 'period': PERIOD_SEC,
    })
    return f'otpauth://totp/{label}?{params}'
