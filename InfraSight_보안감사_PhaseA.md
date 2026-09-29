# InfraSight 보안 감사 보고서 (Phase A — 감사 전용, 코드 수정 없음)

- 감사일: 2026-09-26
- 대상: `D:\Agent\Claude\infrasight-dashboard\` (server.py, storage.py, index.html, agent.py, collector/, alerts/, requirements.txt, start.bat, infrasight.db, .infrasight_secret_key, backups/, dist/)
- 방법: 소스 전체 정독 + 읽기 전용 실측 점검(헤더/쿠키/미인증 접근/정적파일 노출/CORS/ACL/방화벽/의존성 조회)
- 변경 사항: **코드·DB·설정 수정 없음.** 점검을 위해 서버를 기동했고(꺼져 있었음), 점검용 로그인 3회/로그아웃 1회가 audit_log에 추가되었습니다(삭제·초기화 없음).
- 표기: SAFE / NEEDS_REVIEW / VULNERABLE / NOT_IMPLEMENTED. "실측"은 실제로 요청/조회해서 확인한 것, "코드"는 소스 읽기로만 확인한 것입니다.

## 1. 한눈에 보는 결론

| 구분 | 건수 |
|---|---|
| VULNERABLE | 17 |
| NEEDS_REVIEW | 8 |
| NOT_IMPLEMENTED | 4 |
| SAFE | 7 |

(36개 항목 기준. §5의 추가 발견 10건은 별도이며 위 집계에 포함하지 않았습니다.)

가장 시급한 5가지 (사내망 운영 기준):

1. **Windows 방화벽이 Domain/Private/Public 전부 꺼져 있고**, 서버가 `0.0.0.0:5057`(HTTP)로 열려 있음 → 같은 LAN의 누구나 로그인 화면·에이전트 API·설치 파일에 접근 가능. (실측)
2. **Session 폐기 불가**: 로그아웃해도 이전 쿠키로 계속 `200`(관리자) 접근 가능, 만료 31일, `Secure`/`SameSite` 없음. (실측)
3. **비밀정보 평문 저장**: SNMP community, SMTP 비밀번호(DB `credentials` 테이블), Agent Token(`devices.token`) 전부 평문. 백업 파일에도 그대로 들어감. (실측)
4. **파일 ACL**: `infrasight.db`, `.infrasight_secret_key`, `backups/`에 `Authenticated Users: Modify` 상속 → 이 PC의 아무 로그인 사용자가 DB를 읽고 세션 서명 키로 관리자 세션을 위조할 수 있음. (실측)
5. **XSS + 설치 스크립트 명령 주입**: 장비 이름/에이전트가 보낸 프로세스 이름이 `innerHTML`에 이스케이프 없이 삽입되고, 장비 이름이 그대로 `InfraSight-Install.bat`에 들어가 원격 PC에서 실행됨. (코드)

추가 발견 (지시서에 없던 항목): SMTP TLS 인증서 검증이 꺼져 있음(실측), 외부 CDN 스크립트에 SRI 없음, 관리자·SMTP 비밀번호가 이 대화창에 평문으로 오갔음(→ 교체 권장).

## 2. 36개 항목 감사 결과

| # | 항목 | 상태 | 근거 (파일·함수 / 실측) |
|---|---|---|---|
| 1 | 인증 구조 | NEEDS_REVIEW | `server.py: api_login`, `storage.verify_login`. 단일 `admin`, scrypt 검증. 비밀번호 변경·정책·잠금 없음. |
| 2 | Session 구조 | VULNERABLE | Flask 기본 서명 쿠키(서버 저장소 없음). **실측**: 로그아웃 후 이전 쿠키로 `/api/auth/me` → `200 ADMIN`. `PERMANENT_SESSION_LIFETIME` 미설정 → 31일, idle timeout 없음. |
| 3 | Cookie 설정 | VULNERABLE | **실측** Set-Cookie: `HttpOnly; Path=/; Expires=+31일`. `Secure`·`SameSite` 없음. |
| 4 | API 인증 구조 | SAFE | **실측** 미인증 `/api/state, /health, /settings/smtp, /topology/links, /metrics, POST /devices, DELETE, POST /backup` 전부 401. 공개는 의도된 4개뿐(`/`, `/download/*`, `/api/agent/report`, `/api/auth/login`). |
| 5 | API별 권한 검사 | NEEDS_REVIEW | 전 API가 `@login_required`(로그인 여부)만 검사. 역할(`ADMIN/OPERATOR/VIEWER`) 검사 함수 없음 → 로그인만 되면 SMTP 설정·삭제·백업 모두 가능. 단일 관리자 전제라 현재는 동등. (§3 표 참조) |
| 6 | CSRF 방어 | VULNERABLE | CSRF 토큰·Origin/Referer 검사 없음. 모든 POST/PUT/DELETE 대상. |
| 7 | 비밀번호 저장 | SAFE | `storage.create_admin_if_missing` → `generate_password_hash(method='scrypt')` (실측: `scrypt:32768:8:1`), 사용자별 salt. 프로젝트 파일에 평문 비밀번호 없음(실측 grep 0건). |
| 8 | Secret Key 저장 | VULNERABLE | `server.py: _load_or_create_secret_key` → `.infrasight_secret_key`(hex 64자) 평문 파일. 웹 노출 없음(실측 404), 하드코딩 아님, git 없음. 그러나 **ACL이 `Authenticated Users:Modify`(실측)** → 로컬 사용자가 읽어 관리자 세션 위조 가능. |
| 9 | SNMP Credential 저장 | VULNERABLE | `storage.set_credential` 평문 저장. **실측**: `credentials`의 `snmp_community`, `smtp_password` 모두 평문 형태. 테이블 분리만 되어 있고 암호화 없음. |
| 10 | Agent Token 저장/전송 | VULNERABLE | 토큰 `uuid4().hex[:16]`(64비트, 난수 자체는 안전). 그러나 `devices.token` 평문, 에이전트 `%LOCALAPPDATA%\InfraSightAgent\config.json` 평문(`agent.py: save_config`), JSON 본문으로 HTTP 전송. 에이전트별 고유 토큰은 분리되어 있음(SAFE 부분). 재발급·폐기 API 없음. `/api/state`에는 토큰 미노출(실측). |
| 11 | Agent 통신 암호화 | NOT_IMPLEMENTED | `agent.py: run`이 `urllib`로 `http://`에 POST. 설치기도 `http://{lan_ip}:5057`. |
| 12 | HTTP/HTTPS 구조 | NOT_IMPLEMENTED | `server.py: serve(app, host='0.0.0.0', port=5057)`. HTTPS·리버스 프록시 없음. **실측** `netstat`: `0.0.0.0:5057 LISTENING`. |
| 13 | CORS 설정 | SAFE | CORS 코드 없음. **실측** 다른 Origin preflight에 `Access-Control-Allow-Origin` 응답 없음. |
| 14 | 로그 민감정보 | NEEDS_REVIEW | 앱 로깅 모듈 미사용(코드 grep 0건). 잔존 `server.log`(203KB, 9/23 Flask 개발서버 시절 접근 로그)에서 token/password/community 문자열 0건(실측). `audit_log.details`에 장비 이름·`user@host:port`·SMTP 오류문이 검증 없이 저장됨. |
| 15 | DB 접근 권한 | VULNERABLE | **실측 ACL** `infrasight.db`: `Authenticated Users:(M)`, `Users:(RX)` 상속. 웹 다운로드는 불가(실측 404). |
| 16 | Backup 접근 권한 | VULNERABLE | `backups/` 동일 ACL(상속). 웹 노출 없음(실측 404). 백업은 DB 통째 복사라 평문 자격증명·토큰 포함, 암호화 없음. |
| 17 | 입력값 검증 | VULNERABLE | `api_register_device`는 category/mode/name 비어있음만 검사. IP 형식·hostname·port(1–65535)·name 길이·`fields` 키/크기 무검증. SMTP 설정 `port/host/alertTo` 무검증. `api_device_metrics`의 `limit` 음수 허용. |
| 18 | OS 명령 실행 | NEEDS_REVIEW | 전체에서 `subprocess`는 `collector/ping_collector.py: ping_host` 1곳, 리스트 인자+`shell=False`(쉘 주입은 불가). 단 IP 무검증 → `-t` 같은 선행 `-` 값이 ping 옵션으로 해석되는 **인자 주입** 가능. `os.system`/`shell=True`/`eval`/`exec`/`pickle` 없음. |
| 19 | Path Traversal | SAFE | 파일 제공은 `send_from_directory`에 고정 파일명(`index.html`, `dist/InfraSightAgent.exe`, `agent.py`)만. 백업 파일명은 서버 생성. **실측** `../`, `%2f` 변형 프로브 전부 404. |
| 20 | SQL Injection | SAFE | 사용자 입력은 모두 `?` 바인딩. f-string SQL은 `storage.py:194,198`(하드코딩 컬럼 목록), `:443`(고정 테이블명·상수)뿐, 테이블명은 화이트리스트(`'5m'/'1h'`). |
| 21 | XSS | VULNERABLE | `index.html`의 `innerHTML` 26곳 중 미이스케이프: `${s.name}`(L899), `${d.name}`(L968), `${n.name}`(L1023), `${f.name}/${f.type}/${f.role}`(L1080), `${i.source}`(L754,1096,1138), 토폴로지 `${n.label}`(L778,815), **에이전트가 보낸 `${p.name}`**(L1439, 토큰 보유자가 주입 가능), `data-id="${s.id}"`(L897…, `fields`가 `id`를 덮어쓸 수 있음). 이스케이프 적용은 8곳(이벤트 message, sysDescr, 인터페이스명 등). |
| 22 | 인증 우회 | NEEDS_REVIEW | 코드/실측상 우회 경로 없음(#4). 단 #8의 키 유출 시 세션 위조로 우회 가능. |
| 23 | 권한 상승 | NOT_IMPLEMENTED | 다중 역할 없음(Phase 3에서 단일 관리자로 결정). 역할 검사 자체가 없어 상승할 계층도 없음. |
| 24 | Login Brute Force | VULNERABLE | 실패 횟수 제한·잠금·rate limit 없음. `login_required` 앞단에 지연도 없음. (실측 시도는 하지 않음 — 잠금 부재는 코드로 확인) |
| 25 | Session Fixation | NEEDS_REVIEW | 세션 ID가 서버에 없어 고정 자체는 어려움. 다만 `api_login`이 기존 세션을 `clear()` 하지 않고 값만 설정(server.py:74). |
| 26 | Session 탈취 위험 | VULNERABLE | HTTP 평문 + `Secure` 없음 + 폐기 불가(#2) + 31일. LAN 스니핑 시 쿠키 재사용 가능. |
| 27 | CSRF 가능성 | VULNERABLE | **실측** 외부 `Origin` + `Content-Type: text/plain` POST가 통과(`get_json(force=True)`), 인증·핸들러까지 도달. 브라우저 SameSite 기본값에 의존하는 상태(Firefox는 기본 Lax 아님). |
| 28 | SSRF/임의 IP | NEEDS_REVIEW | 로그인 사용자는 임의 IP/포트로 ping·TCP·SNMP 가능(의도된 기능). 허용 대역·loopback/링크로컬 정책 없음. SMTP 설정·테스트도 임의 host:port로 접속. |
| 29 | Dependency 취약점 | SAFE | 설치 버전 16개를 OSV.dev로 조회 → 알려진 advisory 0건(§4). pip-audit는 미설치라 이번엔 OSV로 대체. 시점 기준 결과. |
| 30 | Agent 보안 | VULNERABLE | HTTP 전송, EXE 무결성 검증 없음(§5), 설치 스크립트 명령 주입(§5), `/api/agent/report` 무제한 시도(토큰 오라클: 없는 토큰 404 vs 정상 200, rate limit 없음), 보고 값 검증 없음(`float()` 실패 시 500, `procs` 이름 XSS). |
| 31 | SNMPv3 Credential 보안 | VULNERABLE | `snmpv3_auth_password`/`priv_password`도 `credentials` 평문(#9와 동일 함수). |
| 32 | 파일 권한 | VULNERABLE | #8/#15/#16의 ACL 결과. 프로젝트 폴더 전체가 `Authenticated Users: Modify` 상속 — 코드 변조(server.py 교체)도 가능. |
| 33 | Debug Mode | SAFE | Flask `debug` 미사용, 운영 서버는 waitress. **실측** 404/405/400 응답이 일반 HTML, traceback 없음. |
| 34 | 에러 메시지 정보 노출 | NEEDS_REVIEW | 대부분 일반 메시지. 단 `api_trigger_backup`(server.py:343)와 `api_test_smtp`(:331)가 예외 문자열(`str(e)`, smtplib 오류)을 그대로 반환. |
| 35 | 백업 보안 | VULNERABLE | 암호화 없음, ACL 상속, 평문 자격증명 포함. 웹 직접 접근은 불가(SAFE 부분). 백업 다운로드 API는 없음. |
| 36 | 로그 보안 | NOT_IMPLEMENTED | `logs/` 없음, 로그 로테이션·`security.log` 없음. `audit_log` 테이블만 존재(조회 API 없음, 무한 증가, 아래 §6 이벤트 누락). |

## 3. API 엔드포인트 분류 (server.py 기준)

| Endpoint | 현재 보호 | 권장 등급 |
|---|---|---|
| GET `/` | PUBLIC (정적 셸) | PUBLIC |
| GET `/download/agent` | PUBLIC | PUBLIC(+해시 제공) |
| GET `/download/installer/<token>` | PUBLIC(토큰 조회) | PUBLIC(토큰 게이트), 이름 이스케이프 필수 |
| POST `/api/agent/report` | PUBLIC(에이전트 토큰) | PUBLIC(토큰), rate limit 필요 |
| POST `/api/auth/login` | PUBLIC | PUBLIC (+잠금) |
| POST `/api/auth/logout` | 인증 확인 없음 | AUTHENTICATED |
| GET `/api/auth/me`, `/api/state`, `/api/system/health` | AUTHENTICATED | VIEWER+ |
| GET `/api/devices/<id>/metrics`, `/api/topology/links` | AUTHENTICATED | VIEWER+ |
| POST `/api/incidents/<id>/ack` | AUTHENTICATED | OPERATOR+ |
| PUT `/api/devices/<id>/maintenance`, `/vendor-profile` | AUTHENTICATED | OPERATOR+ |
| POST `/api/devices`, DELETE `/api/devices/<id>` | AUTHENTICATED | ADMIN |
| GET·PUT `/api/settings/smtp`, POST `/smtp/test` | AUTHENTICATED | ADMIN |
| POST `/api/system/backup` | AUTHENTICATED | ADMIN |
| 장비 수정, 사용자 관리, SNMP credential 변경, Agent 토큰 재발급/폐기, 백업 다운로드, 로그 조회 | **없음(NOT_IMPLEMENTED)** | ADMIN |

IDOR/BOLA: 단일 테넌트·단일 관리자라 “다른 사용자의 장비” 개념이 없어 현재는 문제 없음(**실측** 임의 `device_id` 접근은 로그인 사용자에게 허용). 다중 역할을 도입하면 그때 재검토 필요.

## 4. 의존성 (실제 설치 버전 기록)

Flask 3.1.3 · Werkzeug 3.1.8 · waitress 3.0.2 · APScheduler 3.11.3 · psutil 7.2.2 · pysnmp 7.1.29 · cryptography 50.0.1 · pycryptodomex 3.23.0 · itsdangerous 2.2.0 · Jinja2 3.1.6 · MarkupSafe 3.0.3 · pyasn1 0.6.4 · cffi 2.1.1 · click 8.4.2 · blinker 1.9.0 · tzlocal 5.4.4

- OSV.dev 조회(패키지명·버전만 전송): 16개 모두 알려진 advisory 0건.
- `requirements.txt`는 버전 미고정(NOT_IMPLEMENTED: lock, SBOM). 현재 동작 버전을 그대로 lock 하는 것이 안전(업그레이드 금지).
- 참고: 이 환경에서 SNMPv3 MD5+DES는 동작하지 않음(SHA+AES만 검증됨) — 지시서 27항대로 우회하지 않고 유지.

## 5. 지시서에 없었지만 감사 중 발견한 항목

| 항목 | 상태 | 근거 |
|---|---|---|
| Windows Firewall 전 프로필 비활성 | VULNERABLE | **실측** `Get-NetFirewallProfile`: Domain/Private/Public 모두 `Enabled=False`. python.exe 허용 규칙 2개(Private) 존재. |
| SMTP TLS 인증서 검증 꺼짐 | VULNERABLE | **실측** `alerts/email_channel.py`가 `SMTP_SSL(host, port)`/`starttls()`를 context 없이 호출 → Python 3.14.5 기본 `ssl._create_stdlib_context()`가 `verify_mode=0(CERT_NONE)`, `check_hostname=False`. 중간자가 SMTP 비밀번호·알림 내용을 가로챌 수 있음. |
| 설치 스크립트(.bat) 명령 주입 | VULNERABLE | `server.py: download_installer`가 장비 이름을 `title`·`echo` 줄에 그대로 삽입(L380,385). 이름에 `&`, `|`, `%`, 줄바꿈이 들어가면 에이전트 PC에서 임의 명령 실행(이름은 무검증 등록, #17). CSRF(#6)와 결합 가능. 코드로 확인(실제 주입은 데이터 보호를 위해 시도하지 않음). |
| Agent EXE 무결성 | NOT_IMPLEMENTED | `curl`로 HTTP 다운로드 후 무검증 실행. 참고용 SHA-256: `9cb2f05c…9a89e4`(`dist/InfraSightAgent.exe`, 8,699,013 B). 버전·빌드일자·서명 없음. |
| `fields` 덮어쓰기(mass assignment) | NEEDS_REVIEW | `serialize_device`가 `base.update(f)`로 사용자 `fields`를 `id/name/mode/ip` 뒤에 병합 → 응답의 `id` 등이 바뀔 수 있고 XSS(#21)를 증폭. |
| 외부 CDN 의존 | NEEDS_REVIEW | `index.html` L4–7: cdnjs Chart.js, Google Fonts를 SRI 없이 로드. 로그인 화면이 외부 CDN 스크립트를 실행. 관제망이 폐쇄망이면 화면도 깨짐. |
| 보안 헤더 전무 | VULNERABLE | **실측** 응답에 CSP/XFO/nosniff/Referrer/Permissions/HSTS 없음 → 클릭재킹 가능(21항 요구사항). |
| 로그인 시간차 | NEEDS_REVIEW | 없는 사용자는 해시 연산 없이 즉시 반환(`storage.verify_login`) → 계정 존재 여부를 응답 시간으로 추측 가능. |
| 요청 크기 제한 없음 | NEEDS_REVIEW | `MAX_CONTENT_LENGTH` 미설정, waitress 기본 본문 제한(1GB) 그대로. |
| 이 대화에 노출된 비밀번호 | 조치 권장 | 관리자·SMTP 비밀번호가 채팅에 평문으로 오갔음. 프로젝트 파일에는 없음(실측). 보안 강화 완료 시점에 두 비밀번호 모두 교체 권장. |

## 6. Audit Log 커버리지 (지시서 24항 대비)

- 기록됨: LOGIN, LOGIN_FAILED, LOGOUT, REGISTER_DEVICE, DELETE_DEVICE, SET_MAINTENANCE, SET_VENDOR_PROFILE, SET_SMTP_SETTINGS, TEST_SMTP, MANUAL_BACKUP, ACK_INCIDENT (실측 테이블: 11종)
- 누락: ACCOUNT_LOCKED/UNLOCKED, SESSION_EXPIRED, CSRF_FAILURE, AUTHORIZATION_FAILURE(401 미기록), DEVICE_EDIT(수정 API 자체 없음), SNMP_CREDENTIAL_CHANGE, AGENT_TOKEN_REISSUE/REVOKE, BACKUP_FAILURE(이벤트로만 기록), MAINTENANCE_START/END 구분(`SET_MAINTENANCE` 하나로 통합)
- `LOGIN_FAILED`의 사용자명은 공격자 입력 그대로 저장(길이 제한 없음). 조회 API가 없어 아직 화면 삽입 위험은 없으나 향후 조회 화면은 반드시 이스케이프 필요.

## 7. 실행 환경

- 실행 계정: `SOODOGYUN\ilove`(대화형 사용자, Administrators 그룹은 UAC 필터로 “deny only”, 중간 무결성) — 관리자 권한으로 실행 중이 아님. 서비스가 아니라 로그인 세션에서 `start.bat`/`python server.py`로 실행.
- Waitress: `0.0.0.0:5057`. 별도 스레드/연결 제한 미설정.
- `start.bat`: 파이썬 경로 하드코딩, 브라우저는 `http://localhost:5057`.

## 8. 조치 전에 사용자 결정이 필요한 사항 (영향도·롤백 포함)

1. **HTTPS 방식 (Phase E)** — 사용 가능한 리버스 프록시(Caddy/nginx/IIS 등)와 인증서(사내 CA/자체서명)가 있는가?
   - 영향: `127.0.0.1` 바인딩으로 바꾸면 **다른 PC의 기존 에이전트 4대(`http://IP:5057` 고정)가 즉시 끊김**. 따라서 (a) 프록시를 먼저 세우고 (b) 에이전트에 HTTPS 주소를 재설정한 뒤 (c) 바인딩을 좁히는 3단계 이행을 권장. 롤백: `serve(host='0.0.0.0')`로 복귀.
2. **ACL 변경 (Phase C/F)** — 프로젝트 폴더에서 `Authenticated Users` 쓰기 권한 제거, DB/키/백업은 실행 계정+Administrators만 허용. 지시서대로 **변경 전 목록 보고 후 별도 승인**을 받겠습니다. 롤백: `icacls /restore` 용 ACL 백업 파일을 먼저 저장.
3. **Windows Firewall 활성화** — 현재 꺼져 있음. 켜면서 TCP 5057은 지정 대역만 허용해야 기존 접속이 유지됩니다. 허용할 사내 대역(예: 192.168.30.0/24)을 알려주세요.
4. **역할 모델** — 지시서 40항 테스트에 Viewer 권한이 언급됩니다. 지금처럼 단일 관리자 유지(권장, 단순)인지, Viewer/Operator를 추가할지 결정 필요.
5. **비밀정보 암호화 키 보관** — `cryptography`(Fernet) + 키를 DB 밖에 보관. 이 PC 전용이므로 Windows DPAPI 보호 키 파일을 권장. 이미 저장된 SNMP community/SMTP 비밀번호는 **값을 바꾸지 않고 암호화 형태로만 이전**(원본 백업 후 진행, 롤백 가능).

## 9. 제안 진행 순서 (지시서 43항 그대로, 각 Phase 시작 전 백업)

- **Phase B** 인증·Session·CSRF·API 권한: 로그인 잠금(5회/10분)+IP rate limit, 서버 측 세션 폐기(세션 저장소), idle timeout, 쿠키 `HttpOnly/SameSite=Lax`(+HTTPS일 때 `Secure`), CSRF 토큰, 비밀번호 변경 API(현재 비번 확인), 감사 이벤트 보강, 보안 헤더 최소 세트.
- **Phase C** Secret/Credential/Agent: 자격증명 Fernet 암호화 이전, 에이전트 토큰 해시 저장·재발급/폐기, SMTP TLS 검증 활성화, 시크릿 키 ACL(승인 후).
- **Phase D** 입력 검증·XSS·명령 주입: IP/port/이름/interval 검증, ping 선행 `-` 차단, `innerHTML` 전수 이스케이프(`textContent`화), `fields` 화이트리스트, .bat 이름 이스케이프.
- **Phase E** HTTPS/쿠키 Secure/CSP/방화벽(위 결정 1·3 필요).
- **Phase F** 로깅(로테이션·줄바꿈 이스케이프)·백업 암호화/ACL.
- **Phase G** 의존성 lock·SBOM(CycloneDX)·보안 테스트 20종·회귀 테스트.

## 10. 최종 점검 표 (지시서 45항 형식, Phase A 시점)

| 영역 | 상태 | 위험 | 조치 |
|---|---|---|---|
| HTTPS | NOT_IMPLEMENTED | 높음 | Phase E, 프록시 결정 필요 |
| Session | VULNERABLE | 높음 | Phase B (서버측 폐기·idle timeout) |
| Login | VULNERABLE | 높음 | Phase B (잠금·rate limit·비밀번호 변경) |
| CSRF | VULNERABLE | 중간 | Phase B (토큰) |
| API Authorization | NEEDS_REVIEW | 중간 | Phase B (역할 결정 후) |
| Secret Key | VULNERABLE | 높음 | Phase C (ACL 승인 후) |
| SNMP Credential | VULNERABLE | 높음 | Phase C (암호화 이전) |
| Agent | VULNERABLE | 높음 | Phase C/D/E |
| XSS | VULNERABLE | 높음 | Phase D |
| SQL Injection | SAFE | 낮음 | 유지 (Phase G 테스트로 회귀 확인) |
| Command Injection | NEEDS_REVIEW | 낮음~중간 | Phase D (ping 인자·.bat 이름) |
| Path Traversal | SAFE | 낮음 | 유지 |
| SSRF | NEEDS_REVIEW | 낮음 | Phase D/E (ALLOWED_NETWORKS 준비) |
| Logging | NOT_IMPLEMENTED | 중간 | Phase F |
| Backup | VULNERABLE | 중간~높음 | Phase F |
| Firewall | VULNERABLE | 높음 | Phase E (허용 대역 결정 필요) |
| Dependency | SAFE | 낮음 | Phase G (lock만, 업그레이드 금지) |
| SBOM | NOT_IMPLEMENTED | 낮음 | Phase G |

## 11. 이번 감사의 한계

- 로그인 잠금 부재는 코드로 확인했고 실제 반복 시도는 하지 않았습니다.
- XSS·설치 스크립트 주입은 코드 경로로 확인했고, 실제 페이로드를 등록하지는 않았습니다(운영 데이터 보호).
- 에이전트 PC(원격)의 `config.json` 권한은 이 PC에 에이전트 설정이 없어 확인하지 못했습니다.
- 의존성은 OSV.dev 조회 기준이며 zero-day/미등록 취약점은 알 수 없습니다.
