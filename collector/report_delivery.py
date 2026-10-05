"""3-3: 정기 보고서 자동 발송 -- weekly/monthly cron jobs (registered in
collector/scheduler.py) call run_due_schedules('weekly'|'monthly'), which
generates and emails the report for every enabled schedule of that
frequency. Reuses reports.py (3-2) for the file and alerts.email_channel's
EmailChannel.send_with_attachment (extended for 3-3) for delivery -- "기존
이메일 발송 기능과 공통 모듈을 활용한다."

보고서 생성 실패 시 재시도: up to RETRY_ATTEMPTS attempts per schedule per
run, synchronously, before logging a permanent failure for that run -- a
transient SMTP hiccup shouldn't need to wait for next week's/month's cron
to self-heal. Every attempt count and outcome is recorded via
storage.record_report_delivery regardless of success, which is what the
ticket's "발송 이력 및 오류 로그" requirement means in practice.
"""
import datetime
import time

import reports
import storage
from alerts.email_channel import EmailChannel

RETRY_ATTEMPTS = 3


def period_for_frequency(frequency, now_ms=None):
    """The reporting period a schedule covers: the 7 days before today
    (weekly) or the calendar month before this one (monthly) -- both end at
    the most recent local midnight, so "오늘 발송된 주간 보고서" always covers
    a clean, already-complete week/month rather than a partial one."""
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    now_dt = datetime.datetime.fromtimestamp(now_ms / 1000)
    today_midnight = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    if frequency == 'weekly':
        end = today_midnight
        start = end - datetime.timedelta(days=7)
    elif frequency == 'monthly':
        end = today_midnight.replace(day=1)
        prev_month_end = end - datetime.timedelta(days=1)
        start = prev_month_end.replace(day=1)
    else:
        raise ValueError('frequency must be weekly or monthly')
    return int(start.timestamp() * 1000), int(end.timestamp() * 1000)


def send_schedule_now(schedule, smtp_cfg, start_ms=None, end_ms=None):
    """Generates and sends the report for one schedule a single time (no
    retry loop) -- used both by run_due_schedules' per-attempt call and by
    server.py's manual '지금 발송 테스트' button, which wants exactly one
    attempt with an immediate pass/fail, not a multi-try background retry."""
    if start_ms is None or end_ms is None:
        start_ms, end_ms = period_for_frequency(schedule['frequency'])
    data, filename, mimetype = reports.build_report(
        schedule['report_type'], schedule['format'], start_ms, end_ms,
        schedule.get('device_id'), schedule.get('group_name'))
    channel = EmailChannel(smtp_cfg['host'], smtp_cfg['port'], smtp_cfg['username'], smtp_cfg['password'], smtp_cfg['use_tls'])
    period_desc = f"{time.strftime('%Y-%m-%d', time.localtime(start_ms / 1000))} ~ {time.strftime('%Y-%m-%d', time.localtime(end_ms / 1000))}"
    subject = f"[InfraSight] {schedule['name']} ({period_desc})"
    body = f"{schedule['name']} 정기 보고서입니다.\n\n기간: {period_desc}\n\n첨부된 파일을 확인해주세요."
    return channel.send_with_attachment(schedule['recipients'], subject, body, data, filename, mimetype)


def run_due_schedules(frequency):
    schedules = [s for s in storage.load_report_schedules() if s['enabled'] and s['frequency'] == frequency]
    if not schedules:
        return
    smtp_cfg = storage.get_smtp_config()
    now_ms = int(time.time() * 1000)
    start_ms, end_ms = period_for_frequency(frequency, now_ms)
    for sched in schedules:
        if not smtp_cfg:
            storage.record_report_delivery(sched['id'], now_ms, 'failed', 'SMTP 채널이 설정되어 있지 않습니다', 0)
            storage.update_report_schedule_last_run(sched['id'], now_ms, 'failed')
            continue
        ok, err, attempts = False, None, 0
        for attempts in range(1, RETRY_ATTEMPTS + 1):
            try:
                ok, err = send_schedule_now(sched, smtp_cfg, start_ms, end_ms)
            except Exception as e:
                ok, err = False, f"{type(e).__name__}: {e}"
            if ok:
                break
        storage.record_report_delivery(sched['id'], now_ms, 'success' if ok else 'failed', None if ok else err, attempts)
        storage.update_report_schedule_last_run(sched['id'], now_ms, 'success' if ok else 'failed')
        if not ok:
            storage.add_incident('warn', 'InfraSight', 'SYSTEM', f"정기 보고서 발송 실패: {sched['name']} ({err})", _no_alert=True)
