; InfraSight 제거 마법사 (NSIS)
; ============================
; uninstall.ps1이 하는 실제 작업(프로세스 종료/예약 작업 해제/방화벽 규칙
; 제거/원격접속 등록 해제/DB 백업/설치 폴더 삭제)은 그대로 두고, 그 바깥을
; 감싸는 그래픽 마법사 UI만 이 스크립트가 제공한다 (installer.nsi와 같은
; 패턴).
;
; uninstall.ps1 자신의 "정확히 삭제를 입력하세요" 콘솔 확인 프롬프트는 GUI
; 마법사 안에서는 받을 방법이 없으므로(nsExec에 콘솔 입력을 연결할 수 없음),
; 그 확인을 NSIS의 MessageBox(예/아니오)로 대신하고 -Force로 넘겨서
; uninstall.ps1 쪽 프롬프트 자체를 건너뛰게 한다.
;
; 빌드: ops\build-release.ps1이 /DVERSION=<date>-<sha>로 makensis를 호출한다.
; 수동 빌드: makensis /DVERSION=dev ops\uninstall-gui.nsi

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef VERSION
  !define VERSION "dev"
!endif
!ifndef UNINSTALL_PS1_PATH
  !define UNINSTALL_PS1_PATH "..\uninstall.ps1"
!endif

Name "InfraSight 제거"
OutFile "..\setup\InfraSight-Uninstall-GUI-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\InfraSight"
; uninstall.ps1은 예약 작업 해제/방화벽 규칙 제거에 관리자 권한이 필요하다
; (install.ps1과 동일한 이유) -- 여기서 미리 요청해두면 uninstall.ps1
; 자신의 자가 승격(UAC 재실행) 로직은 이미 관리자인 걸 보고 건너뛰어서
; UAC 창이 두 번 뜨지 않는다.
RequestExecutionLevel admin
ShowInstDetails show

; ------------------------------------------------------------- 아이콘/이미지 --
!define MUI_ICON "assets\installer.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "assets\header.bmp"

; ------------------------------------------------------------------- 페이지 --
!define MUI_WELCOMEPAGE_TITLE "InfraSight 제거"
!define MUI_WELCOMEPAGE_TEXT "이 마법사가 이 PC에 설치된 InfraSight를 제거합니다.$\r$\n$\r$\n실행 중인 프로세스 종료, 자동 시작 해제, 방화벽 규칙 제거, 원격 접속 등록 해제, 설치 폴더 삭제까지 자동으로 처리됩니다.$\r$\n$\r$\n등록된 장비/알림 이력/계정이 담긴 데이터베이스는 삭제 전 바탕화면에 자동으로 백업됩니다.$\r$\n$\r$\n계속하려면 다음을 클릭하세요."
!insertmacro MUI_PAGE_WELCOME

!define MUI_DIRECTORYPAGE_TEXT_TOP "제거할 InfraSight가 설치된 폴더를 확인해주세요 (자동으로 찾아서 채워 넣었습니다 -- 다르면 직접 바꿔주세요)."
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE CheckInstallDir
!insertmacro MUI_PAGE_DIRECTORY

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "제거 완료"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "Korean"

; ----------------------------------------------------------- 설치 경로 자동 탐지 --
Function .onInit
    ; patch-gui.nsi와 동일한 이유 -- NSIS는 $로 시작하는 토큰을 전부 자기
    ; 변수로 해석하려 하므로, PowerShell 쪽 변수 $t는 $$t로 이스케이프해야
    ; 리터럴 $t로 출력된다 (안 그러면 조용히 빈 문자열로 치환되어 버림).
    nsExec::ExecToStack `powershell -NoProfile -ExecutionPolicy Bypass -Command "$$t = Get-ScheduledTask -TaskName 'InfraSight Supervisor' -ErrorAction SilentlyContinue; if ($$t -and $$t.Actions -and $$t.Actions[0].WorkingDirectory) { [Console]::Write($$t.Actions[0].WorkingDirectory) }"`
    Pop $0
    Pop $1
    StrCmp $1 "" doneDetect
    IfFileExists "$1\server.py" 0 doneDetect
    StrCpy $INSTDIR $1
    doneDetect:
FunctionEnd

; patch-gui.nsi와 동일한 이유 -- 틀린 폴더로 넘어가면 uninstall.ps1이 콘솔
; 입력을 기다리며 멈추므로 여기서 미리 막는다.
Function CheckInstallDir
    IfFileExists "$INSTDIR\server.py" dirOk
        MessageBox MB_OK|MB_ICONEXCLAMATION "이 폴더는 InfraSight 설치 폴더가 아닌 것 같습니다 (server.py가 없습니다).$\r$\n$\r$\n실제 설치된 폴더를 선택해주세요."
        Abort
    dirOk:
FunctionEnd

; ------------------------------------------------------------------- 제거 --
Section "Uninstall InfraSight" SecUninstall
    SectionIn RO

    ; uninstall.ps1 자신의 "삭제"를 입력하세요 콘솔 프롬프트 대신, GUI다운
    ; 예/아니오 확인창으로 대체한다 (-Force로 그 프롬프트 자체를 건너뛰게 함).
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "정말로 InfraSight를 제거하시겠습니까?$\r$\n$\r$\n설치 경로: $INSTDIR$\r$\n$\r$\n이 작업은 되돌릴 수 없습니다 (데이터베이스는 바탕화면에 자동 백업됩니다)." IDYES proceed
    Abort
    proceed:

    StrCpy $1 "$TEMP\InfraSightUninstaller"
    CreateDirectory "$1"
    SetOutPath "$1"
    File "/oname=uninstall.ps1" "${UNINSTALL_PS1_PATH}"

    ; installer.nsi와 동일한 이유 -- $INSTDIR 끝 백슬래시 제거
    StrCpy $2 "$INSTDIR"
    StrCpy $3 $2 1 -1
    ${If} $3 == "\"
        StrCpy $2 $2 -1
    ${EndIf}

    DetailPrint "InfraSight를 제거하는 중입니다..."
    nsExec::ExecToLog '"powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$1\uninstall.ps1" -InstallDir "$2" -Force'
    Pop $0

    RMDir /r "$1"

    ${If} $0 != 0
        MessageBox MB_OK|MB_ICONSTOP "제거 중 문제가 발생했습니다 (종료 코드 $0). 위 로그 내용을 확인해주세요."
        Abort
    ${EndIf}
SectionEnd
