"""smtplib-based email alert channel (directive section 24).

3-3 extended this with attachment support (send_with_attachment) for
scheduled report delivery, reusing the exact same SMTP connect/auth/TLS
logic as the plain-text alert path (send) via the shared _send_message
helper -- "기존 이메일 발송 기능과 공통 모듈을 활용한다" per the ticket."""
import smtplib
import ssl
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from alerts.base import AlertChannel


class EmailChannel(AlertChannel):
    def __init__(self, host, port, username, password, use_tls=True):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def _send_message(self, msg, to_addrs):
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
            server.sendmail(self.username, to_addrs, msg.as_string())
            return True, None
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    pass

    def send(self, to_addr, subject, body):
        msg = MIMEText(body, _charset='utf-8')
        msg['Subject'] = subject
        msg['From'] = self.username
        msg['To'] = to_addr
        return self._send_message(msg, [to_addr])

    def send_with_attachment(self, to_addrs, subject, body, attachment_bytes, attachment_filename, attachment_mimetype):
        """to_addrs: a list (3-3's report schedules can have multiple
        recipients, unlike the single alert_to of the incident-alert path).
        attachment_mimetype: e.g. 'application/pdf' -- split on '/' into
        MIMEApplication's maintype/subtype."""
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = self.username
        msg['To'] = ', '.join(to_addrs)
        msg.attach(MIMEText(body, _charset='utf-8'))
        maintype, _, subtype = attachment_mimetype.partition('/')
        part = MIMEApplication(attachment_bytes, _subtype=subtype or 'octet-stream')
        part.add_header('Content-Disposition', 'attachment', filename=attachment_filename)
        msg.attach(part)
        return self._send_message(msg, to_addrs)
