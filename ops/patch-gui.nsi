; InfraSight 패치 마법사 (NSIS)
; =============================
; 패치적용.ps1이 하는 실제 작업(git bundle fast-forward/원격접속 재구성/
; 에이전트 파일 갱신/백엔드 재시작)은 그대로 두고, 그 바깥을 감싸는 그래픽
; 마법사 UI만 이 스크립트가 제공한다 (installer.nsi와 완전히 같은 패턴).
;
; installer.nsi와의 차이: 설치 위치를 "새로" 고르는 게 아니라 "이미 설치된
; 곳"을 찾아야 한다 -- 로그온 자동 시작용 "InfraSight Supervisor" 예약
; 작업(설치 시 항상 자동 등록됨)의 WorkingDirectory에 실제 설치 경로가 그대로
; 들어있으므로, .onInit에서 미리 조회해 디렉터리 선택 페이지의 기본값으로
; 채워 넣는다 (패치적용.ps1 자신의 자동 탐지 로직과 동일한 방식 -- 이 파일이
; 실패해도 패치적용.ps1이 같은 조회를 한 번 더 시도하므로 이중 안전망).
; "다음" 누르기 전에 그 경로가 실제 설치 폴더가 맞는지 확인해서, 아니면
; 넘어가지 못하게 막는다 (잘못된 경로로 nsExec를 실행해 패치적용.ps1의
; 콘솔 입력 프롬프트에 걸려 멈추는 상황을 원천적으로 막기 위함 -- GUI
; 마법사 안에서는 콘솔 입력을 받을 방법이 없다).
;
; 빌드: ops\build-release.ps1이 /DVERSION=<date>-<sha> /DPATCH_PS1_PATH=<치환된
; 임시 패치적용.ps1 경로>로 makensis를 호출한다.
; 수동 빌드: makensis /DVERSION=dev ops\patch-gui.nsi

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef VERSION
  !define VERSION "dev"
!endif
; build-release.ps1이 패치적용.ps1 원본 대신, git bundle + 에이전트 exe가
; base64로 치환된 임시 복사본 경로를 넘겨준다 (installer.nsi의
; INSTALL_PS1_PATH와 동일한 이유/패턴 -- 수동 빌드 때는 원본을 그대로 써서
; 플레이스홀더 미치환 분기로 건너뛰게 된다).
!ifndef PATCH_PS1_PATH
  !define PATCH_PS1_PATH "..\패치적용.ps1"
!endif

Name "InfraSight 패치"
OutFile "..\setup\InfraSight-Patch-GUI-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\InfraSight"
; 패치적용.ps1 자신이 관리자 권한을 요구하지 않는다 (방화벽/예약 작업 등록
; 같은 건 install.ps1 쪽 일이고, 여기선 git/파일 복사/사용자 소유 프로세스
; 재시작뿐) -- 콘솔판 Patch.exe(ps2exe -requireAdmin:$false)와 동일하게
; UAC 창 없이 바로 진행된다.
RequestExecutionLevel user
ShowInstDetails show

; ------------------------------------------------------------- 아이콘/이미지 --
!define MUI_ICON "assets\installer.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "assets\header.bmp"

; ------------------------------------------------------------------- 페이지 --
!define MUI_WELCOMEPAGE_TITLE "InfraSight 패치 적용"
!define MUI_WELCOMEPAGE_TEXT "이 마법사가 설치된 InfraSight를 최신 버전으로 업데이트합니다.$\r$\n$\r$\n코드 업데이트, 원격 접속(SSH/Telnet) 설정 갱신, 에이전트 설치 파일 갱신, 백엔드 재시작까지 전부 자동으로 처리됩니다.$\r$\n$\r$\n계속하려면 다음을 클릭하세요."
!insertmacro MUI_PAGE_WELCOME

!define MUI_DIRECTORYPAGE_TEXT_TOP "InfraSight가 설치된 폴더를 확인해주세요 (자동으로 찾아서 채워 넣었습니다 -- 다르면 직접 바꿔주세요)."
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE CheckInstallDir
!insertmacro MUI_PAGE_DIRECTORY

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "패치 적용 완료"
!define MUI_FINISHPAGE_TEXT "브라우저에서 강력 새로고침(Ctrl+F5)을 해주시면 됩니다."
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "Korean"

; ----------------------------------------------------------- 설치 경로 자동 탐지 --
Function .onInit
    ; 주의: PowerShell 쪽 변수(아래 $$t)는 NSIS에게 "리터럴 $t로 출력해라"는
    ; 뜻의 $$ 이스케이프가 꼭 필요하다 -- NSIS는 따옴표 종류와 무관하게 $로
    ; 시작하는 토큰을 전부 "자기 변수"로 해석하려고 시도해서, $$ 없이 그냥
    ; $t라고 쓰면 NSIS가 (존재하지 않는) 변수 t를 찾다가 조용히 빈 문자열로
    ; 치환해버린다 -- 실측으로 겪음("unknown variable/constant 't'" 경고와
    ; 함께 PowerShell 커맨드 텍스트에서 $t가 통째로 사라져 있었음).
    nsExec::ExecToStack `powershell -NoProfile -ExecutionPolicy Bypass -Command "$$t = Get-ScheduledTask -TaskName 'InfraSight Supervisor' -ErrorAction SilentlyContinue; if ($$t -and $$t.Actions -and $$t.Actions[0].WorkingDirectory) { [Console]::Write($$t.Actions[0].WorkingDirectory) }"`
    Pop $0
    Pop $1
    StrCmp $1 "" doneDetect
    IfFileExists "$1\server.py" 0 doneDetect
    StrCpy $INSTDIR $1
    doneDetect:
FunctionEnd

; 디렉터리 선택 페이지에서 "다음"을 눌렀을 때, 그 폴더가 진짜 InfraSight
; 설치 폴더가 맞는지 확인한다 -- 아니면 되돌려보낸다 (틀린 경로로 넘어가면
; 패치적용.ps1이 콘솔 입력을 기다리며 멈추는데, GUI 안에서는 그걸 받을
; 방법이 없어 마법사가 그대로 먹통이 되어버리기 때문에 여기서 미리 막는다).
Function CheckInstallDir
    IfFileExists "$INSTDIR\server.py" dirOk
        MessageBox MB_OK|MB_ICONEXCLAMATION "이 폴더는 InfraSight 설치 폴더가 아닌 것 같습니다 (server.py가 없습니다).$\r$\n$\r$\n실제 설치된 폴더를 선택해주세요."
        Abort
    dirOk:
FunctionEnd

; ------------------------------------------------------------------- 적용 --
Section "Patch" SecPatch
    SectionIn RO

    StrCpy $1 "$TEMP\InfraSightPatcher"
    CreateDirectory "$1"
    SetOutPath "$1"
    File "/oname=패치적용.ps1" "${PATCH_PS1_PATH}"

    ; installer.nsi와 동일한 이유 -- $INSTDIR 끝 백슬래시 제거
    StrCpy $2 "$INSTDIR"
    StrCpy $3 $2 1 -1
    ${If} $3 == "\"
        StrCpy $2 $2 -1
    ${EndIf}

    DetailPrint "InfraSight를 최신 버전으로 패치하는 중입니다..."
    nsExec::ExecToLog '"powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$1\패치적용.ps1" -InstallDir "$2"'
    Pop $0

    RMDir /r "$1"

    ${If} $0 != 0
        MessageBox MB_OK|MB_ICONSTOP "패치 적용 중 문제가 발생했습니다 (종료 코드 $0). 위 로그 내용을 확인해주세요."
        Abort
    ${EndIf}
SectionEnd
