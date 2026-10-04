"""Slack incoming-webhook alert channel (2-4). stdlib-only (urllib), matching
agent.py's own JSON-POST pattern, so this doesn't add a new dependency
(`requests` isn't in requirements.txt and this project pins its dependency
set deliberately -- see requirements.txt's own comment)."""
import json
import urllib.request

from alerts.base import AlertChannel


class SlackChannel(AlertChannel):
    def send(self, webhook_url, subject, body):
        payload = {'text': f"*{subject}*\n{body}"}
        try:
            req = urllib.request.Request(
                webhook_url, data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            return True, None
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
