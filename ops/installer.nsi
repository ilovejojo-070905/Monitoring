; InfraSight 설치 마법사 (NSIS)
; =============================
; install.ps1이 하는 실제 작업(도구 설치/클론/인증서/DB/계정/자동시작/방화벽/
; 원격접속 구성)은 그대로 두고, 그 바깥을 감싸는 그래픽 설치 마법사 UI만
; 이 스크립트가 제공한다 (환영 -> 설치 위치 선택 -> 설치 진행 -> 완료,
; Angry IP Scanner 같은 전형적인 NSIS Modern UI 스타일).
;
; 실제 설치 단계는 install.ps1을 임시 폴더에 풀어놓고 nsExec::ExecToLog로
; 실행해서, 그 콘솔 출력을 설치 진행 페이지의 로그 창에 그대로 흘려보낸다
; (install.ps1 자체를 NSIS 스크립트로 다시 짜지 않는다 -- 이미 여러 번
; 실전에서 고친 그 로직을 또 하나 따로 유지하면 둘이 어긋날 위험만 커진다).
;
; 빌드: ops\build-release.ps1이 /DVERSION=<date>-<sha> 로 makensis를 호출한다.
; 수동 빌드: makensis /DVERSION=dev ops\installer.nsi

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef VERSION
  !define VERSION "dev"
!endif

Name "InfraSight"
OutFile "..\setup\InfraSight-Setup-GUI-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\InfraSight"
RequestExecutionLevel admin
ShowInstDetails show

; ------------------------------------------------------------- 아이콘/이미지 --
!define MUI_ICON "assets\installer.ico"
!define MUI_UNICON "assets\installer.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "assets\header.bmp"

; ------------------------------------------------------------------- 페이지 --
!define MUI_WELCOMEPAGE_TITLE "InfraSight 설치를 시작합니다"
!define MUI_WELCOMEPAGE_TEXT "이 마법사가 InfraSight 설치를 안내합니다.$\r$\n$\r$\n설치 중 필요한 구성 요소(Git, Python, Caddy, mkcert, PuTTY)가 없으면 자동으로 함께 설치됩니다. 계속 진행하기 전에 다른 프로그램을 종료하는 것을 권장합니다.$\r$\n$\r$\n계속하려면 다음을 클릭하세요."
!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_DIRECTORY

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "지금 바로 InfraSight 열기 (https://localhost:8443)"
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchInfraSight"
; 설치 진행 중(InstFiles 페이지)에 탐색기 창이 끼어들지 않도록, 원격 접속
; 확장 프로그램 폴더 열기는 설치가 전부 끝나고 "마침" 버튼을 누르는 바로 그
; 순간으로 미뤄둔다 (ops\setup-remote-access.ps1의 같은 자리 주석 참고).
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE "OnFinishLeave"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "Korean"

Function LaunchInfraSight
    ExecShell "open" "https://localhost:8443"
FunctionEnd

Function OnFinishLeave
    # 매번 열어도 그냥 탐색기 창 하나 뜨는 정도라 해롭지 않다 -- 최초 1회인지
    # 판단하는 로직은 setup-remote-access.ps1 안에만 있고 그걸 여기로 끌어올
    # 뾰족한 방법이 없어서, 간단하게 항상 연다.
    ExecShell "open" "$LOCALAPPDATA\InfraSight\extension"
FunctionEnd

; ------------------------------------------------------------------- 설치 --
Section "InfraSight" SecInstall
    SectionIn RO

    ; install.ps1 자신이 $INSTDIR에 git clone을 하므로, install.ps1 파일
    ; 자체는 $INSTDIR 밖(임시 폴더)에 풀어놓아야 한다 -- 안 그러면
    ; "설치 위치가 이미 있고 비어있지 않은데 git 저장소도 아닙니다" 에러로
    ; install.ps1이 스스로 중단해버린다 (이미 한 번 겪은 문제 패턴).
    StrCpy $1 "$TEMP\InfraSightInstaller"
    CreateDirectory "$1"
    SetOutPath "$1"
    File "..\install.ps1"

    ; $INSTDIR 끝에 백슬래시가 붙어 있으면(드라이브 루트 바로 아래를 고르면
    ; 흔히 이렇게 됨 -- 실측: "D:\InfraSight" 선택 시 재현됨) 아래처럼 따옴표로
    ;감싼 커맨드라인에 그대로 넣었을 때 그 trailing \"가 "이스케이프된 따옴표"로
    ; 해석되어 인자 전체가 깨진다(윈도우 커맨드라인 파싱의 전형적인 함정) --
    ; install.ps1이 PowerShell의 $InstallDir 매개변수로 받는 값 자체가
    ; 뒤섞여버려서 "경로의 형식이 잘못되었습니다" 같은 전혀 다른 에러로 나타났다.
    ; 넘기기 전에 끝의 백슬래시 하나를 미리 떼어낸다.
    StrCpy $2 "$INSTDIR"
    StrCpy $3 $2 1 -1
    ${If} $3 == "\"
        StrCpy $2 $2 -1
    ${EndIf}

    DetailPrint "InfraSight를 설치하는 중입니다 -- 네트워크 상황에 따라 몇 분 정도 걸릴 수 있습니다..."
    nsExec::ExecToLog '"powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$1\install.ps1" -InstallDir "$2"'
    Pop $0

    RMDir /r "$1"

    ${If} $0 != 0
        MessageBox MB_OK|MB_ICONSTOP "설치 중 문제가 발생했습니다 (종료 코드 $0). 위 로그 내용을 확인해주세요."
        Abort
    ${EndIf}
SectionEnd
