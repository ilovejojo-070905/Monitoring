"""알림 재시도 큐 처리 (버그 수정, 2026-10-16) -- tick()은 scheduler.py의
작업 풀에서 60초마다 돈다 (escalation.py/maintenance.py와 같은 패턴).

storage._dispatch_one_channel()이 즉시 1회 시도하고 실패하면
pending_alert_retries에 넣어두는데, 여기서 그걸 백오프(storage.
ALERT_RETRY_BACKOFF_MIN)를 두고 재시도한다. destination은 큐에 저장하지
않고 매번 storage.resolve_alert_channel()로 현재 설정을 새로 읽어온다 --
재시도 사이에 사용자가 설정을 바꿨으면(토큰 재발급 등) 낡은 destination으로
또 실패하는 것보다 안전하다. 채널이 그새 아예 꺼졌으면(설정 삭제) 더 재시도할
대상이 없으므로 그 줄은 그냥 치운다.
"""
import time

import storage


def tick():
    for retry in storage.load_due_alert_retries():
        resolved = storage.resolve_alert_channel(retry['channel'])
        if not resolved:
            storage.delete_alert_retry(retry['id'])
            continue
        channel, destination, _min_severity = resolved
        ok, err = storage.send_via_channel(
            retry['channel'], channel, destination, retry['severity'], retry['source'], retry['message'])
        attempts = retry['attempts'] + 1  # this attempt, counting the original immediate try as #1
        if ok:
            if retry['channel'] == 'email':
                storage.record_email_alert(int(time.time() * 1000), retry['severity'], retry['source'],
                                            retry['message'], destination, 'success', None, attempts + 1)
            storage.delete_alert_retry(retry['id'])
            continue
        if attempts >= storage.ALERT_RETRY_MAX_ATTEMPTS:
            if retry['channel'] == 'email':
                storage.record_email_alert(int(time.time() * 1000), retry['severity'], retry['source'],
                                            retry['message'], destination, 'failed', err, attempts + 1)
            storage.add_incident(
                'warn', 'InfraSight', 'SYSTEM',
                f"{retry['channel']} 알림 발송 실패 ({attempts + 1}회 시도 후 포기): {err}", _no_alert=True)
            storage.delete_alert_retry(retry['id'])
        else:
            storage.bump_alert_retry(retry['id'], attempts, err)
