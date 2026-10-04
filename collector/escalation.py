"""2-5: 알림 에스컬레이션 -- tick() runs every 60s (scheduler.py's own job
pool, same as maintenance.py and flow_listener.flush). For every currently
OPEN incident at or above the configured minimum severity, it walks a
configured chain of contact tiers (1차/2차/3차...), notifying the next tier
once the current one's timeout has elapsed without the incident leaving
'open'.

The ticket's own distinction -- "담당자의 실제 확인 동작과 단순한 이메일 발송
성공을 구분한다" -- is why this keys entirely off incidents.status (which
only ack_incident(), a person clicking 확인 in the UI, or a recovery event
ever change) rather than off whether _notify_tier()'s send succeeded. A tier
whose email bounces still counts as "not acknowledged": the clock keeps
running and the next tier gets notified on schedule regardless, exactly as
it would if the email had gone through but nobody read it.

Only ever uses email (alerts.email_channel.EmailChannel) -- a named 담당자 is
a person with an address, not a team channel like Slack/Teams, and the
existing SMTP settings (storage.get_smtp_config()) are reused as-is rather
than inventing a second mail configuration just for this.
"""
import time

import storage
from alerts.email_channel import EmailChannel

_SEVERITY_RANK = {'warn': 1, 'crit': 2}


def _notify_tier(incident, tier, smtp_cfg):
    if smtp_cfg:
        channel = EmailChannel(smtp_cfg['host'], smtp_cfg['port'], smtp_cfg['username'], smtp_cfg['password'], smtp_cfg['use_tls'])
        subject = f"[InfraSight 에스컬레이션 {tier['tier_order']}차] {incident['severity'].upper()} - {incident['source']}"
        body = (f"{tier['name']}님, 아래 장애가 {tier['timeout_minutes']}분 이상 확인되지 않았습니다.\n\n"
                f"{incident['message']}\n\nInfraSight에서 확인 후 조치해주세요.")
        ok, err = channel.send(tier['email'], subject, body)
    else:
        ok, err = False, 'SMTP 채널이 설정되어 있지 않습니다'
    storage.record_escalation_notify(incident['id'], tier['tier_order'], tier['name'], tier['email'], ok, err)


def tick():
    if storage.get_setting('escalation_enabled') != '1':
        return
    tiers = sorted([t for t in storage.load_escalation_tiers() if t.get('enabled')], key=lambda t: t['tier_order'])
    if not tiers:
        return
    min_severity = storage.get_setting('escalation_min_severity', 'crit')
    smtp_cfg = storage.get_smtp_config()
    now_ms = int(time.time() * 1000)
    for incident in storage.load_open_incidents():
        if _SEVERITY_RANK.get(incident['severity'], 0) < _SEVERITY_RANK.get(min_severity, 2):
            continue
        state = storage.get_escalation_state(incident['id'])
        if state and state.get('completed'):
            continue
        notified_so_far = state['current_tier'] if state else 0
        if notified_so_far == 0:
            _notify_tier(incident, tiers[0], smtp_cfg)
            storage.upsert_escalation_state(incident['id'], 1, now_ms, len(tiers) <= 1)
            continue
        if notified_so_far >= len(tiers):
            storage.upsert_escalation_state(incident['id'], notified_so_far, state['last_notified_at'], True)
            continue
        current_tier = tiers[notified_so_far - 1]
        elapsed_min = (now_ms - state['last_notified_at']) / 60000.0
        if elapsed_min >= current_tier['timeout_minutes']:
            next_tier = tiers[notified_so_far]
            _notify_tier(incident, next_tier, smtp_cfg)
            new_count = notified_so_far + 1
            storage.upsert_escalation_state(incident['id'], new_count, now_ms, new_count >= len(tiers))
