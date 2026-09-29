"""Central logging setup (directive sections 25/26/33/36).

Before this, InfraSight had no file-based logging at all (confirmed in the
Phase A audit, item #36) -- only whatever a person happened to see scroll by
in the console, gone the moment the window closed. Two rotating files:

  logs/app.log        -- INFO+ from the whole app: startup, collector/
                         scheduler errors, unhandled request exceptions.
  logs/error.log      -- the same stream filtered to ERROR+, so a quick scan
                         doesn't require grepping the full app.log.
  logs/security.log   -- a redundant, append-only trail of every audit_log
                         event (login/logout/lockout/CSRF/authorization/
                         device changes/token reissue/...). storage.write_audit
                         writes here too, so every existing and future call
                         site gets a file trail for free without having to
                         remember to log twice.

None of these three files sit under anything Flask ever serves (static_folder
is None; send_from_directory only ever names index.html/agent.py/dist/*
explicitly) -- so there's no route that could expose them, matching the
"logs/ not web-accessible" requirement without needing one.

Every dynamic value written through these loggers should go through
safe_log_value() first: a username or device name containing a raw \\r or \\n
would otherwise be able to forge what looks like a second, fabricated log
line (directive section 26, log injection) -- e.g. a login attempt for
username "admin\\n2026-01-01 INFO action=LOGIN user=admin" would otherwise
render as two lines, the second indistinguishable from a real successful
login.
"""
import logging
import logging.handlers
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5


def safe_log_value(v):
    if v is None:
        return ''
    return str(v).replace('\r', '\\r').replace('\n', '\\n')


def _rotating_handler(filename, level=logging.INFO):
    handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, filename), maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding='utf-8')
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    return handler


def _make_logger(name):
    logger = logging.getLogger(name)
    if logger.handlers:  # idempotent: importing this module twice must not double-attach handlers
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


app_logger = _make_logger('infrasight.app')
app_logger.addHandler(_rotating_handler('app.log'))
app_logger.addHandler(_rotating_handler('error.log', level=logging.ERROR))

security_logger = _make_logger('infrasight.security')
security_logger.addHandler(_rotating_handler('security.log'))
