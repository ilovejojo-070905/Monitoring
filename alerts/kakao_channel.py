"""Kakao '나에게 보내기' (self-message) alert channel (2-4, Method A).

Different shape from Slack/Teams: there's no single webhook URL. Kakao Login
OAuth issues a short-lived access_token (~6h) and a long-lived refresh_token;
sending a message needs a *valid* access_token, so this channel refreshes it
inline when storage.py's copy looks stale, rather than assuming the caller
already did. The refreshed token pair is handed back to the caller (as the
3rd return value) so storage.py can persist it -- this module never imports
storage itself, same constraint as every other alerts/*_channel.py (see
alerts/base.py's docstring: storage.py imports channels, so a channel
importing storage back would be circular).

This only ever reaches the account that did the OAuth consent -- there is no
concept of "recipients" here. Real business 알림톡 (sending to other people)
is a different Kakao product entirely; see storage.py's comment above
get_kakao_config_public().
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from alerts.base import AlertChannel

TOKEN_URL = 'https://kauth.kakao.com/oauth/token'
SEND_URL = 'https://kapi.kakao.com/v2/api/talk/memo/default/send'
# Kakao's default "text" template caps at 200 characters (link preview object
# is required even when empty, per Kakao's own API contract).
MAX_TEXT_LEN = 200


class KakaoChannel(AlertChannel):
    def send(self, cfg, subject, body):
        """cfg: {rest_api_key, client_secret, access_token, refresh_token,
        expires_at}, as built by storage.get_kakao_config(). Returns
        (ok, err, new_tokens) -- new_tokens is None unless a refresh
        happened, in which case it's {access_token, refresh_token,
        expires_in} for the caller to persist via storage.set_kakao_tokens()."""
        new_tokens = None
        access_token = cfg.get('access_token')
        if not access_token or time.time() >= cfg.get('expires_at', 0):
            access_token, new_tokens, err = self._refresh(cfg)
            if not access_token:
                return False, err, None
        ok, err = self._send_message(access_token, subject, body)
        if not ok and new_tokens is None:
            # Our own clock said the token was still fresh but Kakao
            # rejected it anyway (revoked elsewhere, clock skew) -- one
            # forced refresh-and-retry before giving up.
            access_token, new_tokens, refresh_err = self._refresh(cfg)
            if access_token:
                ok, err = self._send_message(access_token, subject, body)
            else:
                err = refresh_err
        return ok, err, new_tokens

    def _refresh(self, cfg):
        if not cfg.get('refresh_token'):
            return None, None, 'refresh_token이 없습니다 (카카오 계정을 다시 연결해주세요)'
        params = {
            'grant_type': 'refresh_token',
            'client_id': cfg['rest_api_key'],
            'refresh_token': cfg['refresh_token'],
        }
        if cfg.get('client_secret'):
            params['client_secret'] = cfg['client_secret']
        try:
            req = urllib.request.Request(
                TOKEN_URL, data=urllib.parse.urlencode(params).encode('utf-8'),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            new_tokens = {
                'access_token': data['access_token'],
                # Kakao only reissues a refresh_token occasionally (when the
                # old one is close to its own ~2 month expiry) -- None here
                # means "keep the one we already have", handled by
                # storage.set_kakao_tokens().
                'refresh_token': data.get('refresh_token'),
                'expires_in': data.get('expires_in', 21599),
            }
            return new_tokens['access_token'], new_tokens, None
        except urllib.error.HTTPError as e:
            detail = e.read().decode('utf-8', 'replace')[:300]
            return None, None, f"토큰 갱신 실패 (HTTP {e.code}): {detail}"
        except Exception as e:
            return None, None, f"토큰 갱신 실패 ({type(e).__name__}): {e}"

    def _send_message(self, access_token, subject, body):
        text = f"{subject}\n{body}"
        if len(text) > MAX_TEXT_LEN:
            text = text[:MAX_TEXT_LEN - 3] + '...'
        template = {'object_type': 'text', 'text': text, 'link': {}}
        params = {'template_object': json.dumps(template, ensure_ascii=False)}
        try:
            req = urllib.request.Request(
                SEND_URL, data=urllib.parse.urlencode(params).encode('utf-8'),
                headers={'Content-Type': 'application/x-www-form-urlencoded',
                         'Authorization': f'Bearer {access_token}'}, method='POST')
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            return True, None
        except urllib.error.HTTPError as e:
            detail = e.read().decode('utf-8', 'replace')[:300]
            return False, f"HTTP {e.code}: {detail}"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
