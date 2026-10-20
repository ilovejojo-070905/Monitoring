; InfraSight 에이전트 제거 마법사 (NSIS)
; ========================================
; uninstall-agent.ps1이 하는 실제 작업(프로세스 종료/자동 시작 해제/설치
; 폴더 삭제)은 그대로 두고, 그 바깥을 감싸는 그래픽 마법사 UI만 이
; 스크립트가 제공한다 (uninstall-gui.nsi와 같은 패턴). 다만 이쪽은
; 관리자 권한도 설치 경로 선택도 필요 없다 -- 에이전트 설치 자체가 전부
; 현재 사용자 범위(%LOCALAPPDATA%)안에서만 동작하고, 경로도 항상
; 고정이기 때문(uninstall-gui.nsi의 서버 쪽은 사용자가 설치 위치를
; 고를 수 있어 경로 확인 페이지가 필요했지만, 에이전트는 그런 선택지가
; 애초에 없다).
;
; uninstall-agent.ps1 자신의 "정확히 삭제를 입력하세요" 콘솔 확인
; 프롬프트는 GUI 마법사 안에서는 받을 방법이 없으므로, 그 확인을 NSIS의
; MessageBox(예/아니오)로 대신하고 -Force로 넘겨서 ps1 쪽 프롬프트 자체를
; 건너뛰게 한다.
;
; 빌드: ops\build-release.ps1이 /DVERSION=<date>-<sha>로 makensis를 호출한다.
; 수동 빌드: makensis /DVERSION=dev ops\uninstall-agent-gui.nsi

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef VERSION
  !define VERSION "dev"
!endif
!ifndef UNINSTALL_PS1_PATH
  !define UNINSTALL_PS1_PATH "..\uninstall-agent.ps1"
!endif

Name "InfraSight 에이전트 제거"
OutFile "..\setup\InfraSightAgent-Uninstall-GUI-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\InfraSightAgent"
RequestExecutionLevel user
ShowInstDetails show

; ------------------------------------------------------------- 아이콘/이미지 --
!define MUI_ICON "assets\installer.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "assets\header.bmp"

; ------------------------------------------------------------------- 페이지 --
!define MUI_WELCOMEPAGE_TITLE "InfraSight 에이전트 제거"
!define MUI_WELCOMEPAGE_TEXT "이 마법사가 이 PC에서 돌아가는 InfraSight 에이전트를 제거합니다.$\r$\n$\r$\n실행 중인 에이전트 프로세스 종료, 로그온 자동 시작 해제, 설치 폴더 삭제까지 자동으로 처리됩니다.$\r$\n$\r$\n관리자 권한이 필요 없습니다.$\r$\n$\r$\n계속하려면 다음을 클릭하세요."
!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "제거 완료"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "Korean"

; ------------------------------------------------------------------- 제거 --
Section "Uninstall InfraSight Agent" SecUninstall
    SectionIn RO

    MessageBox MB_YESNO|MB_ICONEXCLAMATION "정말로 이 PC의 InfraSight 에이전트를 제거하시겠습니까?$\r$\n$\r$\n이 작업은 되돌릴 수 없습니다." IDYES proceed
    Abort
    proceed:

    StrCpy $1 "$TEMP\InfraSightAgentUninstaller"
    CreateDirectory "$1"
    SetOutPath "$1"
    File "/oname=uninstall-agent.ps1" "${UNINSTALL_PS1_PATH}"

    DetailPrint "InfraSight 에이전트를 제거하는 중입니다..."
    nsExec::ExecToLog '"powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$1\uninstall-agent.ps1" -Force'
    Pop $0

    RMDir /r "$1"

    ${If} $0 != 0
        MessageBox MB_OK|MB_ICONSTOP "제거 중 문제가 발생했습니다 (종료 코드 $0). 위 로그 내용을 확인해주세요."
        Abort
    ${EndIf}
SectionEnd
