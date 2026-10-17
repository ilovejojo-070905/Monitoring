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
a person with an address, not a team channel like Slack, and the
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
    all_tiers = storage.load_escalation_tiers()  # 비활성 포함 -- 이미 알린 티어의 timeout_minutes를 나중에도 조회해야 함
    tiers = sorted([t for t in all_tiers if t.get('enabled')], key=lambda t: t['tier_order'])
    tiers_by_order = {t['tier_order']: t for t in all_tiers}
    if not tiers:
        return
    min_severity = storage.get_setting('escalation_min_severity', 'crit')
    smtp_cfg = storage.get_smtp_config()
    now_ms = int(time.time() * 1000)
    for incident in storage.load_open_incidents():
        if _SEVERITY_RANK.get(incident['severity'], 0) < _SEVERITY_RANK.get(min_severity, 2):
            continue
        # Bug found live (2026-10-16): the primary alert channel (add_
        # incident's own dispatch) is held back for a device currently in
        # maintenance, but this loop never checked that at all -- so a
        # device under an active maintenance window still got escalation
        # emails sent to on-call tiers, directly contradicting the
        # suppression the primary channel already applies. Skipping here
        # (not recording any escalation progress) means the timeout clock
        # for this incident simply doesn't start/advance while the window is
        # open; set_maintenance() catches the primary channel back up for
        # real once the window ends, and this loop resumes normally on its
        # next tick.
        device_row = storage.load_device(incident['device_id']) if incident.get('device_id') else None
        if device_row and storage.in_maintenance(device_row):
            continue
        state = storage.get_escalation_state(incident['id'])
        if state and state.get('completed'):
            continue
        # 버그 수정(2026-10-17): last_notified_order는 "몇 번째로 알렸는지"
        # 순번이 아니라 실제로 알린 티어의 tier_order 값이다 -- 중간 티어가
        # 꺼졌다 켜져도(담당자 교체 등) 어긋나지 않으려면 활성 목록에서의
        # "위치"가 아니라 이 안정적인 값으로 "다음은 tier_order가 이보다
        # 큰 것 중 가장 작은 활성 티어"를 매번 다시 찾아야 한다.
        last_notified_order = state['current_tier'] if state else 0
        pending = [t for t in tiers if t['tier_order'] > last_notified_order]
        if not pending:
            storage.upsert_escalation_state(incident['id'], last_notified_order,
                                             state['last_notified_at'] if state else now_ms, True)
            continue
        next_tier = pending[0]
        if last_notified_order == 0:
            _notify_tier(incident, next_tier, smtp_cfg)
            storage.upsert_escalation_state(incident['id'], next_tier['tier_order'], now_ms, len(pending) <= 1)
            continue
        # 마지막으로 알린 티어 자체는 그 사이 비활성화됐을 수도 있으니
        # all_tiers(비활성 포함)에서 조회 -- timeout_minutes는 "그 담당자를
        # 알린 시점에 기다려야 했던 시간"으로 여전히 유효한 참고값. 그마저
        # 삭제됐으면(설정 자체가 없어짐) 더 기다릴 근거가 없으므로 즉시
        # 다음 티어로 넘어간다(0분 대기로 취급).
        last_tier_cfg = tiers_by_order.get(last_notified_order)
        timeout_minutes = last_tier_cfg['timeout_minutes'] if last_tier_cfg else 0
        elapsed_min = (now_ms - state['last_notified_at']) / 60000.0
        if elapsed_min >= timeout_minutes:
            _notify_tier(incident, next_tier, smtp_cfg)
            storage.upsert_escalation_state(incident['id'], next_tier['tier_order'], now_ms, len(pending) <= 1)
