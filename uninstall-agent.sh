#!/usr/bin/env bash
# InfraSight 에이전트 제거 스크립트 (Linux)
# ==========================================
# 이 PC에서 돌아가는 InfraSight 에이전트를 깨끗하게 제거한다:
#   - 실행 중인 에이전트 프로세스 종료 (cmdline에 InfraSightAgent.py가
#     들어있는 프로세스 전부 -- agent.py의 _find_agent_processes와 같은
#     판단 기준)
#   - crontab @reboot 자동 시작 등록 해제 (agent.py의 _CRON_MARKER와
#     정확히 같은 문자열로 그 줄만 골라 지움)
#   - 설치 폴더 삭제 (~/.config/InfraSightAgent -- 복사된 InfraSightAgent.py
#     + 설정 파일, agent.py의 config_path()/_agent_install_dir()가 쓰는
#     바로 그 폴더)
#
# root 권한이 필요 없다 -- 설치 자체가 처음부터 전부 현재 사용자 범위
# (crontab -e는 호출한 사용자 자신의 crontab만, ~/.config도 홈 디렉터리
# 안쪽)에서만 동작했기 때문에 동일하게 일반 사용자로 실행한다.
#
# 사용법:
#   bash uninstall-agent.sh
#   bash uninstall-agent.sh --force   # 확인 없이 바로 삭제

set -u

FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
  esac
done

INSTALL_DIR="$HOME/.config/InfraSightAgent"
MARKER="# InfraSightAgent (auto-added -- do not edit this line by hand)"

echo "============================================================"
echo " InfraSight 에이전트 제거"
echo "============================================================"

if [ "$FORCE" -ne 1 ]; then
  echo ""
  echo "  이 PC에서 InfraSight 에이전트를 제거합니다:"
  echo "    - 실행 중인 에이전트 프로세스 종료"
  echo "    - crontab 자동 시작(@reboot) 등록 해제"
  echo "    - 설치 폴더 삭제: $INSTALL_DIR"
  echo ""
  read -r -p '계속하려면 정확히 "삭제"를 입력하세요 (다른 입력은 모두 취소): ' CONFIRM
  if [ "$CONFIRM" != "삭제" ]; then
    echo "취소되었습니다."
    exit 0
  fi
fi

echo ""
echo "==> [1/3] 실행 중인 프로세스 종료"
PIDS=$(pgrep -f "InfraSightAgent\.py" || true)
if [ -n "$PIDS" ]; then
  # shellcheck disable=SC2086
  kill $PIDS 2>/dev/null || true
  sleep 1
  echo "    종료됨"
else
  echo "    실행 중인 프로세스가 없습니다."
fi

echo "==> [2/3] crontab 자동 시작 해제"
if command -v crontab >/dev/null 2>&1; then
  CURRENT=$(crontab -l 2>/dev/null || true)
  if echo "$CURRENT" | grep -qF "$MARKER"; then
    echo "$CURRENT" | grep -vF "$MARKER" | crontab -
    echo "    등록 해제됨"
  else
    echo "    등록된 자동 시작이 없습니다."
  fi
else
  echo "    crontab 명령을 찾을 수 없습니다 (건너뜁니다)."
fi

echo "==> [3/3] 설치 폴더 삭제"
if [ -d "$INSTALL_DIR" ]; then
  rm -rf "$INSTALL_DIR"
  echo "    삭제 완료: $INSTALL_DIR"
else
  echo "    설치 폴더가 이미 없습니다."
fi

echo ""
echo "============================================================"
echo " 에이전트 제거가 완료되었습니다."
echo "============================================================"
