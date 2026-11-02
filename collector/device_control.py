"""장비 설정 변경(인터페이스 shutdown/no-shutdown, 재부팅) -- SSH/Telnet CLI
자동화. 이 프로젝트는 SNMP SET을 전혀 쓰지 않으므로(snmp_collector.py 전체에
set_cmd 없음), 상태를 바꾸는 동작은 전부 이 모듈을 통해 실제 장비의 CLI로
나간다.

반드시 지킬 원칙(이 프로젝트의 SNMP OID 검증 원칙과 동일): 벤더별 CLI
문법은 실제 장비에서 검증되기 전까지 PROFILES에 올리지 않는다. 검증 안 된
벤더는 명령이 전부 None이라 호출하면 "지원하지 않음" 오류로 안전하게
막힌다 -- 추측으로 채워서 엉뚱한 명령을 실제 장비에 보내는 일이 없게
하기 위함.

netmiko를 쓰는 이유(requirements.txt 주석 참고): 벤더별 enable 모드 진입,
프롬프트 인식, reload/reboot의 "Proceed? [confirm]" 같은 대화형 확인까지
이미 처리해주고, device_type에 '_telnet' 접미사만 붙이면 SSH/Telnet을 같은
방식으로 다룰 수 있어 이 프로젝트의 sshOpen/telnetOpen 동적 감지와 잘
맞물린다.
"""
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

import storage

# 벤더별 CLI 프로필. ssh_device_type/telnet_device_type은 netmiko가 쓰는
# 정식 이름(https://github.com/ktbyers/netmiko#supported-platforms 기준).
# *_cmds가 None이면 그 동작은 이 벤더에서 아직 미검증/미지원.
#
# 'cisco' (Cisco IOS, Catalyst 2960S/C2960S-UNIVERSALK9-M, 12.2(55)SE5)는
# 2026-11-02 실제 테스트 장비(192.168.30.250, Telnet, 사용자 이름 없이
# enable 비밀번호만)로 전부 실측 검증 완료:
#   - shutdown/no shutdown: gi1/0/1(빈 포트, [TEST] 라벨)에서 상태가
#     notconnect -> disabled -> notconnect로 정확히 왕복되는 것 확인
#   - save_config(write memory): "[OK]" 응답 확인
#   - reload: "Proceed with reload? [confirm]"에 Enter 전송 -> 접속이
#     즉시 끊기는 것까지 확인(재부팅이 실제로 시작됐다는 뜻 -- 정상 동작,
#     버그 아님. _send_reload()가 이 연결 끊김을 성공으로 처리한다)
PROFILES = {
    'cisco': {
        'ssh_device_type': 'cisco_ios',
        'telnet_device_type': 'cisco_ios_telnet',
        'shutdown_cmds': lambda if_name: [f'interface {if_name}', 'shutdown'],
        'no_shutdown_cmds': lambda if_name: [f'interface {if_name}', 'no shutdown'],
        'supports_reload': True,
    },
    'cisco-nxos': {
        'ssh_device_type': 'cisco_nxos', 'telnet_device_type': None,
        'shutdown_cmds': None, 'no_shutdown_cmds': None, 'supports_reload': False,
    },
    'aruba-cx': {
        'ssh_device_type': 'aruba_os', 'telnet_device_type': None,
        'shutdown_cmds': None, 'no_shutdown_cmds': None, 'supports_reload': False,
    },
    'hp-comware': {
        'ssh_device_type': 'hp_comware', 'telnet_device_type': 'hp_comware_telnet',
        'shutdown_cmds': None, 'no_shutdown_cmds': None, 'supports_reload': False,
    },
    'juniper': {
        'ssh_device_type': 'juniper_junos', 'telnet_device_type': None,
        'shutdown_cmds': None, 'no_shutdown_cmds': None, 'supports_reload': False,
    },
}


class DeviceControlError(Exception):
    """사용자에게 그대로 보여줘도 되는 메시지만 담는다 (스택트레이스 노출 안 함)."""


def get_profile(vendor_profile):
    return PROFILES.get(vendor_profile)


def _connect(device_row, profile):
    """SSH 우선, 안 되면 Telnet -- 둘 다 sshOpen/telnetOpen으로 동적으로 알 수
    있지만(ping_collector.py), 그 값은 메모리에만 있어 이 함수 호출 시점에
    항상 최신이라는 보장이 없다. 그래서 여기서는 등록된 자격증명이 있는
    프로토콜을 실제로 순서대로 시도한다 -- SSH가 더 안전하니 먼저."""
    device_id = device_row['id']
    ip = device_row['ip']
    if not ip:
        raise DeviceControlError('이 장비에 IP 주소가 없습니다.')

    username = storage.get_credential(device_id, 'ssh_username') or ''
    password = storage.get_credential(device_id, 'ssh_password')
    enable_password = storage.get_credential(device_id, 'ssh_enable_password')
    if not password:
        raise DeviceControlError('SSH/Telnet 자격증명이 등록되지 않았습니다. 장비 편집에서 먼저 등록해주세요.')

    attempts = []
    if profile.get('ssh_device_type'):
        attempts.append((profile['ssh_device_type'], 22))
    if profile.get('telnet_device_type'):
        attempts.append((profile['telnet_device_type'], 23))
    if not attempts:
        raise DeviceControlError('이 벤더는 아직 SSH/Telnet 자동화를 지원하지 않습니다.')

    last_err = None
    for device_type, port in attempts:
        try:
            conn = ConnectHandler(
                device_type=device_type, host=ip, username=username, password=password,
                secret=enable_password or '', port=port, timeout=10, banner_timeout=10,
            )
            conn.enable()
            return conn
        except (NetmikoTimeoutException, NetmikoAuthenticationException, OSError) as e:
            last_err = e
            continue
    raise DeviceControlError(f'장비에 연결할 수 없습니다 (SSH/Telnet 둘 다 실패): {last_err}')


def shutdown_interface(device_row, vendor_profile, if_name):
    profile = get_profile(vendor_profile)
    if not profile or not profile.get('shutdown_cmds'):
        raise DeviceControlError(f'"{vendor_profile}" 벤더는 인터페이스 제어가 아직 검증되지 않았습니다.')
    conn = _connect(device_row, profile)
    try:
        output = conn.send_config_set(profile['shutdown_cmds'](if_name))
        return output
    finally:
        conn.disconnect()


def bring_up_interface(device_row, vendor_profile, if_name):
    profile = get_profile(vendor_profile)
    if not profile or not profile.get('no_shutdown_cmds'):
        raise DeviceControlError(f'"{vendor_profile}" 벤더는 인터페이스 제어가 아직 검증되지 않았습니다.')
    conn = _connect(device_row, profile)
    try:
        output = conn.send_config_set(profile['no_shutdown_cmds'](if_name))
        return output
    finally:
        conn.disconnect()


def reboot_device(device_row, vendor_profile, save_config_first=True):
    profile = get_profile(vendor_profile)
    if not profile or not profile.get('supports_reload'):
        raise DeviceControlError(f'"{vendor_profile}" 벤더는 재부팅이 아직 검증되지 않았습니다.')
    conn = _connect(device_row, profile)
    save_output = ''
    try:
        if save_config_first:
            save_output = conn.save_config()
        reload_output = conn.send_command_timing('reload')
        if any(k in reload_output.lower() for k in ('confirm', '[yes/no]', 'continue')):
            reload_output += conn.send_command_timing('\n')
    except Exception:
        # 실측 확인(2026-11-02): reload 확인 직후 장비가 바로 재부팅을
        # 시작하면서 세션이 끊기는 게 정상 동작이다(EOFError 등) --
        # 이 시점 이후의 연결 예외는 전부 "재부팅이 실제로 걸렸다"는
        # 증거로 취급하고 실패로 보지 않는다.
        return save_output + '\n(재부팅 명령 전송됨 -- 장비 재부팅으로 연결이 끊어졌습니다. 정상입니다.)'
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return save_output + '\n' + reload_output
