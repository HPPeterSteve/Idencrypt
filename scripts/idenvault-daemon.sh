#!/usr/bin/env bash
# idenvault-daemon.sh — start/stop/restart/status wrapper to run IdenVault in background
# Usage: sudo ./scripts/idenvault-daemon.sh start|stop|restart|status|fg

set -euo pipefail
BIN_ENV=${IDENVAULT_BIN:-}
PID_FILE=${IDENVAULT_PID:-/var/run/idenvault.pid}
LOG_FILE=${IDENVAULT_LOG:-/var/log/idenvault.log}

# Resolve binary: prefer explicit env, then /usr/local/bin, then project release build
if [[ -n "$BIN_ENV" && -x "$BIN_ENV" ]]; then
  BIN="$BIN_ENV"
elif [[ -x "/usr/local/bin/IdenVault" ]]; then
  BIN="/usr/local/bin/IdenVault"
elif [[ -x "/usr/bin/IdenVault" ]]; then
  BIN="/usr/bin/IdenVault"
elif [[ -x "./target/release/IdenVault" ]]; then
  BIN="$(pwd)/target/release/IdenVault"
else
  echo "IdenVault binary not found. Set IDENVAULT_BIN or build project." >&2
  exit 1
fi

start() {
  if [[ -f "$PID_FILE" ]] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
    echo "IdenVault already running (PID=$(cat $PID_FILE))."; return 0
  fi
  echo "Starting IdenVault: $BIN"
  mkdir -p "$(dirname "$PID_FILE")"
  mkdir -p "$(dirname "$LOG_FILE")" || true
  nohup "$BIN" >> "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 0.2
  echo "Started (PID=$(cat $PID_FILE)), logging to $LOG_FILE"
}

stop() {
  if [[ ! -f "$PID_FILE" ]]; then
    echo "No PID file ($PID_FILE) found. Is IdenVault running?"
    return 1
  fi
  pid=$(cat "$PID_FILE")
  if ! kill -0 $pid 2>/dev/null; then
    echo "Process $pid not running; removing stale PID file."; rm -f "$PID_FILE"; return 0
  fi
  echo "Stopping IdenVault (PID=$pid)..."
  kill $pid
  # wait up to 10s
  for i in {1..100}; do
    if kill -0 $pid 2>/dev/null; then
      sleep 0.1
    else
      break
    fi
  done
  if kill -0 $pid 2>/dev/null; then
    echo "PID $pid did not exit, sending SIGKILL"; kill -9 $pid || true
  fi
  rm -f "$PID_FILE"
  echo "Stopped.";
}

status() {
  if [[ -f "$PID_FILE" ]]; then
    pid=$(cat "$PID_FILE")
    if kill -0 $pid 2>/dev/null; then
      echo "IdenVault running (PID=$pid), log: $LOG_FILE"
      return 0
    else
      echo "Stale PID file ($PID_FILE)."; return 1
    fi
  else
    echo "IdenVault not running."; return 3
  fi
}

fg() {
  echo "Running in foreground: $BIN"
  exec "$BIN"
}

case "${1:-}" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop || true
    start
    ;;
  status)
    status
    ;;
  fg)
    fg
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|fg}"; exit 2
    ;;
esac
