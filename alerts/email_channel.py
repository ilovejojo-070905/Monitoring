"""smtplib-based email alert channel (directive section 24)."""
import smtplib
import ssl
from email.mime.text import MIMEText

from alerts.base import AlertChannel


class EmailChannel(AlertChannel):
    def __init__(self, host, port, username, password, use_tls=True):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def send(self, to_addr, subject, body):
        msg = MIMEText(body, _charset='utf-8')
        msg['Subject'] = subject
        msg['From'] = self.username
        msg['To'] = to_addr
        server = None
        # Security hardening Phase C: smtplib's own fallback context
        # (ssl._create_stdlib_context, used when no context= is passed) skips
        # both certificate and hostname verification -- confirmed in the
        # Phase A audit. ssl.create_default_context() is the real "verify
        # like a browser would" context, so the SMTP password in .login()
        # below is only ever sent to a server this machine can actually
        # authenticate, not to whatever answers on host:port.
        context = ssl.create_default_context()
        try:
            if self.port == 465:
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=10, context=context)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=10)
                if self.use_tls:
                    server.starttls(context=context)
            server.login(self.username, self.password)
            server.sendmail(self.username, [to_addr], msg.as_string())
            return True, None
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    pass
