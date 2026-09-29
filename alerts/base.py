"""Alert channel interface (directive section 23/24). Only one channel
(email) exists today; this abstract base is what a future channel (Slack,
SMS, ...) would implement so storage._dispatch_alert doesn't need to change
when one is added.

Lives at the project root (not under collector/) deliberately: storage.py is
the single place that knows whether an incident is brand-new or has just
escalated (the only two cases worth alerting on), and storage.py is imported
BY collector/*, so a channel module under collector/ would create a circular
import if storage.py needed to call into it. Channels take plain config
values as arguments and never import storage themselves.
"""


class AlertChannel:
    def send(self, to_addr, subject, body):
        raise NotImplementedError
