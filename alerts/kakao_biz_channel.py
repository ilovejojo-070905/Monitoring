"""Kakao Business AlimTalk alert channel (2-4, Method B).

Unlike Method A (kakao_channel.py -- OAuth "나에게 보내기", one recipient,
free), AlimTalk sends to other people and costs money per message, so Kakao
doesn't offer a direct API for it: every integrator goes through one of
Kakao's approved relay partners. This uses Solapi (api.solapi.com), one of
the more commonly used ones for exactly this case (AlimTalk + automatic SMS
fallback in a single call), picked as a reasonable default -- swapping to a
different relay later only means rewriting this one file, since storage.py's
_get_alert_channels() only knows about the (name, channel, destination,
min_severity) tuple shape, not which relay a given channel talks to.

Auth is Solapi's HMAC-SHA256 scheme (API key + secret, no OAuth/token
refresh needed -- the secret itself signs each request), so this is a
simpler shape than kakao_channel.py: a plain (ok, err) return, no token to
hand back to the caller.

Template variables are hardcoded here as #{제목}/#{내용}/#{시각} -- this is
the one part of this module an admin cannot change from InfraSight's
settings screen, because it has to exactly match whatever template text
Kakao actually approved. The 알림 채널 설정 화면이 제출용 템플릿 문구를
그대로 보여주므로 둘이 어긋나지 않는다. A template approved
with different variable names will fail at send time with a Solapi error
that includes which variable it expected -- that error reaches the caller
via this channel's (ok, err) return same as any other failure.

NOT verified against a live Solapi account as of writing -- there was no
account/approved template to test against. Built to match Solapi's
published v4 Messages API as closely as possible; the first real "테스트
발송" against an actual account is the real test.
"""
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
import uuid

from alerts.base import AlertChannel

SEND_URL = 'https://api.solapi.com/messages/v4/send-many/detail'
# Kakao's own AlimTalk template body length limit (long-form templates allow
# more, but this matches the plain/basic template type InfraSight's
# suggested template text below fits comfortably inside).
MAX_CONTENT_LEN = 1000


def _auth_header(api_key, api_secret):
    date = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
    salt = uuid.uuid4().hex
    signature = hmac.new(api_secret.encode('utf-8'), (date + salt).encode('utf-8'), hashlib.sha256).hexdigest()
    return f'HMAC-SHA256 apiKey={api_key}, date={date}, salt={salt}, signature={signature}'


class KakaoBizChannel(AlertChannel):
    def send(self, cfg, subject, body):
        """cfg: {api_key, api_secret, pf_id, template_id, sender_number,
        sms_fallback, recipients}, as built by storage.get_kakaobiz_config().
        Sends the same message to every recipient in one batched request.
        Returns (ok, err) -- ok is True only if every recipient's message
        was accepted; err summarizes failures (recipient count + Solapi's
        own error text) when not."""
        content = body if len(body) <= MAX_CONTENT_LEN else body[:MAX_CONTENT_LEN - 3] + '...'
        when = time.strftime('%Y-%m-%d %H:%M:%S')
        variables = {'#{제목}': subject, '#{내용}': content, '#{시각}': when}
        messages = [{
            'to': phone, 'from': cfg['sender_number'],
            'kakaoOptions': {
                'pfId': cfg['pf_id'], 'templateId': cfg['template_id'], 'variables': variables,
                'disableSms': not cfg.get('sms_fallback', False),
            },
        } for phone in cfg['recipients']]
        payload = {'messages': messages}
        try:
            req = urllib.request.Request(
                SEND_URL, data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json',
                         'Authorization': _auth_header(cfg['api_key'], cfg['api_secret'])},
                method='POST')
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            detail = e.read().decode('utf-8', 'replace')[:300]
            return False, f"HTTP {e.code}: {detail}"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
        # Solapi's send-many/detail response lists a per-message result even
        # on an overall HTTP 200 (e.g. one bad phone number among many
        # shouldn't silently look like full success) -- failCount/
        # failedMessageList follow the shape documented for this endpoint.
        fail_count = data.get('failedMessageCount') or data.get('failCount') or 0
        if fail_count:
            failed = data.get('failedMessageList') or []
            detail = '; '.join(
                f"{m.get('to', '?')}: {m.get('statusMessage') or m.get('status', '')}" for m in failed[:5]
            ) or f"{fail_count}건 실패"
            return False, f"{fail_count}/{len(messages)}건 발송 실패 -- {detail}"
        return True, None
