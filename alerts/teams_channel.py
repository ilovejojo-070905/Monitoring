"""Microsoft Teams incoming-webhook alert channel (2-4). A classic Office 365
Connector webhook accepts a plain {"text": ...} body same as Slack's does --
no need for the full MessageCard/Adaptive Card schema just to post a line of
text, so this stays as simple as slack_channel.py."""
import json
import urllib.request

from alerts.base import AlertChannel


class TeamsChannel(AlertChannel):
    def send(self, webhook_url, subject, body):
        payload = {'text': f"**{subject}**\n\n{body}"}
        try:
            req = urllib.request.Request(
                webhook_url, data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            return True, None
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"
