"""HTTPS 인증서 만료/갱신 실패 감지 (신규, 2026-10-17 보안 검토).

install.ps1의 [5/10]이 mkcert로 certs\\infrasight.crt/.key를 한 번 발급하고
Caddy가 그걸 그대로 쓰는데, 지금까지 이 인증서의 유효기간을 누구도 확인하지
않았다 -- mkcert leaf 인증서는 보통 장기간 유효하지만(루트 CA 자체가 훨씬
길게 잡혀 있어도), "확인하지 않는다"는 것 자체가 문제다: 인증서 파일이
깨지거나, LAN IP가 바뀌어서(DHCP) 인증서의 SAN과 더 이상 안 맞거나, 누군가
파일을 지우거나 교체하다 실패해도 Caddy가 못 뜨는 것으로만 뒤늦게 드러난다.

collector/scheduler.py의 _run_retention_job과 같은 일일 주기로 돈다.
"""
import os
import time

import storage
from applog import app_logger

CERT_WARN_DAYS = 30  # 이 안으로 남으면 warn 인시던트
CERT_CRIT_DAYS = 7   # 이 안으로 남거나(또는 이미 만료) crit 인시던트

_CERT_PATH = os.path.join(storage.BASE_DIR, 'certs', 'infrasight.crt')


def check_certificate():
    """매일 한 번 호출 -- storage.add_incident의 기존 device_id 없는
    SYSTEM 경고 패턴(백업 실패 인시던트와 동일)을 그대로 따른다: event_type을
    안 주므로 매번 새 행이 생기지만, 심각도가 그대로면(여러 날 연속 warn)
    같은 문제를 매일 또 알리는 셈 -- 이건 백업 실패 알림도 이미 똑같이
    받아들이고 있는 트레이드오프라 여기서 새로 만드는 문제는 아니다."""
    if not os.path.exists(_CERT_PATH):
        # Caddy가 실제로 못 뜬 상태라면 이미 health.record_tick_error 등
        # 다른 경로로도 드러나지만, 이 함수 자체의 책임(인증서 상태 보고)은
        # 파일이 없다는 사실 자체를 명확히 알리는 것.
        storage.add_incident('crit', 'InfraSight', 'SYSTEM',
                              f"HTTPS 인증서 파일이 없습니다 ({_CERT_PATH}) -- Caddy가 정상 기동하지 못할 수 있습니다.")
        app_logger.error('cert_check: certificate file missing at %s', _CERT_PATH)
        return

    try:
        from cryptography import x509
        with open(_CERT_PATH, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        not_after = cert.not_valid_after_utc
    except Exception as e:
        storage.add_incident('crit', 'InfraSight', 'SYSTEM',
                              f"HTTPS 인증서 파일을 읽을 수 없습니다 (손상되었을 수 있음): {e}")
        app_logger.exception('cert_check: failed to parse certificate')
        return

    days_left = (not_after - _utcnow()).total_seconds() / 86400
    if days_left <= 0:
        storage.add_incident('crit', 'InfraSight', 'SYSTEM',
                              f"HTTPS 인증서가 만료되었습니다 ({not_after.strftime('%Y-%m-%d')}). "
                              f"install.ps1의 [5/10] 단계를 다시 실행해 재발급해주세요.")
    elif days_left <= CERT_CRIT_DAYS:
        storage.add_incident('crit', 'InfraSight', 'SYSTEM',
                              f"HTTPS 인증서가 {days_left:.0f}일 후 만료됩니다 ({not_after.strftime('%Y-%m-%d')}). 곧 재발급이 필요합니다.")
    elif days_left <= CERT_WARN_DAYS:
        storage.add_incident('warn', 'InfraSight', 'SYSTEM',
                              f"HTTPS 인증서가 {days_left:.0f}일 후 만료됩니다 ({not_after.strftime('%Y-%m-%d')}).")

    # LAN IP 변경 감지(DHCP 등) -- 인증서 발급 당시의 IP가 SAN에 들어가는데,
    # 지금 이 PC의 LAN IP가 더 이상 그 목록에 없으면 날짜상 안 만료됐어도
    # 브라우저가 이 인증서를 거부한다(Caddy 자체는 뜨지만 접속이 안 됨) --
    # "만료"와는 다른 종류의 실패라 날짜 체크만으로는 못 잡는다.
    try:
        current_ip = storage.get_lan_ip()
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_values = {str(v) for v in san_ext.value.get_values_for_type(x509.IPAddress)} | \
                     {v for v in san_ext.value.get_values_for_type(x509.DNSName)}
        if current_ip not in san_values:
            storage.add_incident('warn', 'InfraSight', 'SYSTEM',
                                  f"이 PC의 현재 LAN IP({current_ip})가 HTTPS 인증서에 등록된 주소 목록에 없습니다 "
                                  f"(IP가 바뀌었을 수 있음, 예: DHCP) -- 다른 PC에서 새 IP로 접속하면 인증서 오류가 날 수 있습니다. "
                                  f"install.ps1의 [5/10] 단계를 다시 실행해 재발급해주세요.")
    except Exception:
        pass  # SAN 파싱 실패는 부가 체크라 날짜 체크 결과에 영향 주지 않음


def _utcnow():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)
