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
프롬프트 인식까지 이미 처리해주고, device_type에 '_telnet' 접미사만
붙이면 SSH/Telnet을 같은 방식으로 다룰 수 있어 이 프로젝트의 sshOpen/
telnetOpen 동적 감지와 잘 맞물린다. 다만 reload/reboot의 대화형 확인
("[confirm]", "(y/n)?" 등)은 벤더마다 명령어/프롬프트 문구/확인 응답이
전부 달라서(아래 _send_reboot_sequence) netmiko의 자동 처리에 기대지
않고 직접 write_channel + 폴링으로 구현한다 -- 실측 중 send_command_timing
한 번으로는 "please wait......" 같은 중간 메시지 뒤에 몇 초 늦게 나오는
진짜 확인 프롬프트를 놓치는 문제를 겪어서(최초엔 Comware에서 놓쳐서
재부팅이 전혀 안 걸렸었음), 여러 번 짧게 폴링하며 누적하는 방식으로
바꿨다.

인터페이스 shutdown/no-shutdown 명령이 벤더마다 다른 것도 실측으로
직접 확인한 것 -- 추측 아님:
  - Cisco IOS: shutdown / no shutdown
  - HP Comware(H3C): shutdown / undo shutdown ("no shutdown" 아님)
  - ArubaOS-Switch(클래식, ProCurve 계열): disable / enable
    ("shutdown"류 명령 자체가 없음)
"""
import time

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

import storage

# 벤더별 CLI 프로필. ssh_device_type/telnet_device_type은 netmiko가 쓰는
# 정식 이름. *_cmds가 None이면 그 동작은 이 벤더에서 아직 미검증/미지원.
# reboot_* 필드가 없으면(reboot_cmd 없음) 재부팅 미지원.
PROFILES = {
    # Cisco IOS -- 2026-11-02, 실제 테스트 장비(192.168.30.250, Catalyst
    # 2960S/C2960S-UNIVERSALK9-M 12.2(55)SE5, Telnet·사용자 이름 없이
    # enable 비밀번호만)로 전부 실측 검증 완료:
    #   - shutdown/no shutdown: gi1/0/1(빈 포트, [TEST] 라벨)에서 상태가
    #     notconnect -> disabled -> notconnect로 정확히 왕복
    #   - save_config(write memory): "[OK]" 응답 확인
    #   - reload: "Proceed with reload? [confirm]"에 Enter 전송 -> 접속이
    #     즉시 끊기는 것까지 확인(재부팅이 실제로 시작됐다는 뜻). 이후 핑으로
    #     약 3~4분 뒤 장비가 실제로 재부팅 후 복구되는 것까지 확인.
    'cisco': {
        'ssh_device_type': 'cisco_ios',
        'telnet_device_type': 'cisco_ios_telnet',
        'shutdown_cmds': lambda if_name: [f'interface {if_name}', 'shutdown'],
        'no_shutdown_cmds': lambda if_name: [f'interface {if_name}', 'no shutdown'],
        'reboot_pre_cmds': [],
        'reboot_cmd': 'reload',
        'reboot_confirm_keys': ('confirm',),
        'reboot_confirm_response': '',
    },
    'cisco-nxos': {
        'ssh_device_type': 'cisco_nxos', 'telnet_device_type': None,
        'shutdown_cmds': None, 'no_shutdown_cmds': None,
    },
    'aruba-cx': {
        'ssh_device_type': 'aruba_os', 'telnet_device_type': None,
        'shutdown_cmds': None, 'no_shutdown_cmds': None,
    },
    # HP A-series(Comware/H3C OEM) -- 2026-11-02, 실제 테스트 장비
    # (192.168.30.251, HP A5500-24G-4SFP HI, Comware 5.20.99, Telnet만
    # 응답(SSH 포트 22는 닫혀있음), admin 계정)으로 전부 실측 검증 완료:
    #   - shutdown/undo shutdown: GE1/0/2(빈 포트)에서 Link 상태가
    #     DOWN -> ADM(관리자 비활성화) -> DOWN으로 정확히 왕복
    #   - save_config(netmiko 기본 "save force"): 저장 성공 메시지 확인
    #   - reboot: system-view 안에서는 "Unrecognized command"로 거부됨 ->
    #     반드시 'return'으로 user view로 나온 뒤에 'reboot'를 보내야 함
    #     (reboot_pre_cmds로 처리). "Start to check configuration...
    #     please wait......DONE! This command will reboot the device.
    #     Continue? [Y/N]:" 확인 프롬프트가 몇 초 늦게 나오는 것까지 실측
    #     확인(그래서 send_command_timing 한 번이 아니라 폴링 방식 사용) ->
    #     'Y' 응답 후 핑으로 약 2분 뒤 정상 복구 확인.
    'hp-comware': {
        'ssh_device_type': 'hp_comware', 'telnet_device_type': 'hp_comware_telnet',
        'shutdown_cmds': lambda if_name: [f'interface {if_name}', 'shutdown'],
        'no_shutdown_cmds': lambda if_name: [f'interface {if_name}', 'undo shutdown'],
        'reboot_pre_cmds': ['return'],
        'reboot_cmd': 'reboot',
        'reboot_confirm_keys': ('y/n',),
        'reboot_confirm_response': 'Y',
    },
    # ArubaOS-Switch(클래식, ProCurve 계열 -- ArubaOS-CX와는 다른 OS/프로필,
    # snmp_profiles.py의 'hp' 벤더와 동일 계열) -- 2026-11-02, 실제 테스트
    # 장비(192.168.30.252, HP-2530-24G, YA.16.06.0006, admin 계정+빈
    # 비밀번호)로 전부 실측 검증 완료. SSH(22)는 이 장비의 구형 SSH가
    # paramiko와 키교환 알고리즘이 안 맞아 실패(Incompatible ssh peer) --
    # 신형 장비는 될 수도 있어 ssh_device_type은 남겨두되(시도만 하고 안
    # 되면 자동으로 Telnet 폴백), 실제 검증은 Telnet으로만 함:
    #   - disable/enable: 포트 2(빈 포트, Down)에서 Enabled 컬럼이
    #     Yes -> No -> Yes로 정확히 왕복(이 장비는 "shutdown"류 명령 자체가
    #     없고 disable/enable을 씀)
    #   - save_config(netmiko 기본 "write memory"): 저장 확인
    #   - reload: "This will reboot the system from the primary image.
    #     Continue (y/n)? "에 'y' 응답 -> 접속 끊김(EOFError, 정상) -> 핑으로
    #     확인 결과 확인 명령 후 약 45초 뒤 실제로 꺼지고, 이후 정상 복구까지
    #     확인.
    'hp': {
        'ssh_device_type': 'hp_procurve', 'telnet_device_type': 'hp_procurve_telnet',
        'shutdown_cmds': lambda if_name: [f'interface {if_name}', 'disable'],
        'no_shutdown_cmds': lambda if_name: [f'interface {if_name}', 'enable'],
        'reboot_pre_cmds': [],
        'reboot_cmd': 'reload',
        'reboot_confirm_keys': ('y/n',),
        'reboot_confirm_response': 'y',
    },
    # Juniper(Junos) -- 2026-11-03, 실제 테스트 장비(192.168.30.253, root
    # 계정, SSH 정상 응답)로 전부 실측 검증 완료. Junos는 Cisco/Comware/
    # ArubaOS-Switch와 근본적으로 다른 패러다임(line-mode 즉시 적용이
    # 아니라 set/delete로 "후보 설정"을 쌓은 뒤 commit으로 한 번에 반영) --
    #   - disable/활성화: set interfaces {if}/delete interfaces {if}
    #     disable을 commit과 "같은 config 세션"에서 함께 보내야 함(실측으로
    #     발견: netmiko의 send_config_set()과 별도로 conn.commit()을 나중에
    #     호출하면 commit 자체는 성공해도 설정 모드를 제대로 못 빠져나와
    #     이후 명령이 전부 꼬이는 netmiko 쪽 한계가 있었음 -- 그래서 commit도
    #     shutdown_cmds/no_shutdown_cmds 리스트 안에 같이 넣어 한 번에
    #     처리). ge-0/0/9(빈 포트)에서 show interfaces terse 기준 Admin이
    #     up -> down -> up으로 정확히 왕복하는 것 확인.
    #   - 재부팅: "request system reboot" -> "Reboot the system ?
    #     [yes,no] (no)"에 'yes' 응답 -> "System going down IMMEDIATELY"
    #     확인, 핑으로 실제 꺼지는 것까지 확인. Junos는 commit 자체가 이미
    #     "저장"이라 Cisco류의 별도 write-memory 개념이 없음(skip_save_config
    #     로 reboot_device()가 generic save_config() 호출 자체를 건너뛰게
    #     함 -- 안 그러면 netmiko가 뭘 보낼지 검증 안 된 채로 호출하게 됨).
    'juniper': {
        'ssh_device_type': 'juniper_junos', 'telnet_device_type': 'juniper_junos_telnet',
        'shutdown_cmds': lambda if_name: [f'set interfaces {if_name} disable', 'commit'],
        'no_shutdown_cmds': lambda if_name: [f'delete interfaces {if_name} disable', 'commit'],
        'skip_save_config': True,
        'reboot_pre_cmds': [],
        'reboot_cmd': 'request system reboot',
        'reboot_confirm_keys': ('yes,no',),
        'reboot_confirm_response': 'yes',
    },
}


def _safe_port(v):
    try:
        p = int(v)
        return p if 1 <= p <= 65535 else None
    except (TypeError, ValueError):
        return None


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
    # 실측 확인: 빈 비밀번호로 로그인하는 실제 장비가 있다(Aruba 등) --
    # get_credential은 "등록된 적 없음"이면 None, "빈 비밀번호로 등록됨"이면
    # ''을 돌려주므로(storage.py), 여기서는 None만 "미등록"으로 취급해야
    # 한다. `not password`로 체크하면 ''도 걸러져서 실제로 등록한 빈
    # 비밀번호가 "등록 안 됨"으로 잘못 막히는 버그가 있었다.
    if password is None:
        raise DeviceControlError('SSH/Telnet 자격증명이 등록되지 않았습니다. 장비 편집에서 먼저 등록해주세요.')

    # SSH 포트가 22가 아닌 장비 대비(사용자 요청) -- fields.sshPort는 비밀값이
    # 아니라 snmpPort와 같은 설정값이라 credentials가 아니라 fields JSON에
    # 그대로 둔다. 비워두면 기존처럼 22(SSH)/23(Telnet) 기본값을 그대로 씀.
    ssh_port = _safe_port((device_row.get('fields') or {}).get('sshPort')) or 22

    attempts = []
    if profile.get('ssh_device_type'):
        attempts.append((profile['ssh_device_type'], ssh_port))
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


def _build_bulk_cmds(cmds_fn, if_names):
    """인터페이스 여러 개를 한 config 세션으로 묶어서 보낼 명령 목록을 만든다.
    Juniper 프로필은 인터페이스 1개당 cmds 끝에 'commit'이 붙어있어(위
    PROFILES 주석) 그대로 이어붙이면 커밋이 여러 번 들어간다 -- 중복
    제거하고 맨 끝에 한 번만 커밋되게 한다. 다른 벤더는 cmds에 'commit'을
    아예 안 써서 이 처리가 영향을 주지 않는다."""
    all_cmds = []
    for if_name in if_names:
        all_cmds.extend(cmds_fn(if_name))
    if all_cmds.count('commit') > 1:
        all_cmds = [c for c in all_cmds if c != 'commit']
        all_cmds.append('commit')
    return all_cmds


def shutdown_interface(device_row, vendor_profile, if_name):
    return shutdown_interfaces(device_row, vendor_profile, [if_name])


def bring_up_interface(device_row, vendor_profile, if_name):
    return bring_up_interfaces(device_row, vendor_profile, [if_name])


def shutdown_interfaces(device_row, vendor_profile, if_names):
    profile = get_profile(vendor_profile)
    if not profile or not profile.get('shutdown_cmds'):
        raise DeviceControlError(f'"{vendor_profile}" 벤더는 인터페이스 제어가 아직 검증되지 않았습니다.')
    conn = _connect(device_row, profile)
    try:
        return conn.send_config_set(_build_bulk_cmds(profile['shutdown_cmds'], if_names))
    finally:
        conn.disconnect()


def bring_up_interfaces(device_row, vendor_profile, if_names):
    profile = get_profile(vendor_profile)
    if not profile or not profile.get('no_shutdown_cmds'):
        raise DeviceControlError(f'"{vendor_profile}" 벤더는 인터페이스 제어가 아직 검증되지 않았습니다.')
    conn = _connect(device_row, profile)
    try:
        return conn.send_config_set(_build_bulk_cmds(profile['no_shutdown_cmds'], if_names))
    finally:
        conn.disconnect()


def _send_reboot_sequence(conn, profile):
    """벤더마다 다른 reload/reboot 확인 흐름을 공통 처리. send_command_timing
    한 번으로는 Comware의 "please wait......" 같은 중간 메시지 뒤에 몇 초
    늦게 나오는 진짜 확인 프롬프트를 놓치는 걸 실측으로 겪어서, 짧은 간격
    (1.5초)으로 여러 번 폴링하며 출력을 누적하는 방식으로 구현한다."""
    for cmd in profile.get('reboot_pre_cmds') or []:
        conn.write_channel(cmd + '\n')
        time.sleep(1.5)
        conn.read_channel()

    conn.write_channel(profile['reboot_cmd'] + '\n')
    confirm_keys = profile.get('reboot_confirm_keys') or ()
    collected = ''
    for _ in range(10):
        time.sleep(1.5)
        chunk = conn.read_channel()
        if chunk:
            collected += chunk
        if confirm_keys and any(k in collected.lower() for k in confirm_keys):
            break

    if confirm_keys and any(k in collected.lower() for k in confirm_keys):
        conn.write_channel(profile.get('reboot_confirm_response', '') + '\n')
        time.sleep(2)
        try:
            collected += conn.read_channel()
        except Exception:
            # 실측 확인(Cisco/ArubaOS-Switch 둘 다, 2026-11-02): 확인 응답
            # 직후 장비가 바로 재부팅을 시작하면서 세션이 끊기는 게 정상
            # 동작이다(EOFError 등) -- 이건 실패가 아니라 재부팅이 실제로
            # 걸렸다는 증거다.
            pass
    return collected


def reboot_device(device_row, vendor_profile, save_config_first=True):
    profile = get_profile(vendor_profile)
    if not profile or not profile.get('reboot_cmd'):
        raise DeviceControlError(f'"{vendor_profile}" 벤더는 재부팅이 아직 검증되지 않았습니다.')
    conn = _connect(device_row, profile)
    save_output = ''
    try:
        # Junos는 commit 자체가 이미 "저장"이라 별도 write-memory 개념이
        # 없다(위 'juniper' 프로필 주석 참고) -- skip_save_config인 벤더는
        # netmiko의 범용 save_config()를 아예 호출하지 않는다(뭘 보낼지
        # 실측 검증 안 된 채로 호출하는 걸 피하기 위함).
        if save_config_first and not profile.get('skip_save_config'):
            save_output = conn.save_config()
        reboot_output = _send_reboot_sequence(conn, profile)
    except Exception:
        return save_output + '\n(재부팅 명령 전송됨 -- 장비 재부팅으로 연결이 끊어졌습니다. 정상입니다.)'
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return save_output + '\n' + reboot_output
