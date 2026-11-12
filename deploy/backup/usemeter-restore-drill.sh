#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'usemeter-restore-drill: %s\n' "$1" >&2
  exit 1
}

if (( EUID == 0 )); then fail 'must run unprivileged as non-root user'; fi
[[ $# == 1 ]] || fail 'usage: usemeter-restore-drill.sh BACKUP_FILE'

BACKUP_FILE="$1"
[[ -f "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] || fail 'candidate must be a regular, non-symlink file'
BACKUP_FILE="$(realpath -e -- "$BACKUP_FILE")"
[[ "$(stat -c '%u' -- "$BACKUP_FILE")" == "$(id -u)" ]] || fail 'candidate is not owned by current user'
[[ "$(stat -c '%a' -- "$BACKUP_FILE")" == '600' ]] || fail 'candidate must have mode 0600'
case "$BACKUP_FILE" in *,*|*:* ) fail 'candidate path cannot contain comma or colon characters' ;; esac

PROJECT_DIR="${USEMETER_PROJECT_DIR:-${HOME}/usemeter}"
COMPOSE_FILE="${USEMETER_COMPOSE_FILE:-${PROJECT_DIR}/compose.yaml}"
COMPOSE_SERVICE="${USEMETER_COMPOSE_SERVICE:-usemeter}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -d "$PROJECT_DIR" ]] || fail 'Compose project directory is missing'
if [[ "$COMPOSE_FILE" != /* ]]; then COMPOSE_FILE="$PROJECT_DIR/$COMPOSE_FILE"; fi
[[ -f "$COMPOSE_FILE" ]] || fail 'Compose file is missing'
[[ "$COMPOSE_SERVICE" =~ ^[A-Za-z0-9_.-]+$ ]] || fail 'invalid Compose service name'
[[ -x '/usr/bin/docker' ]] || command -v docker >/dev/null 2>&1 || fail 'Docker CLI is unavailable'
DOCKER=(sudo -n /usr/bin/docker)

IMAGE_ID="${USEMETER_DRILL_IMAGE:-}"
if [[ -z "$IMAGE_ID" ]]; then
  CONTAINER_LIST="$("${DOCKER[@]}" compose --project-directory "$PROJECT_DIR" --file "$COMPOSE_FILE" ps -q "$COMPOSE_SERVICE")" || fail 'could not find a running useMeter container'
  CONTAINER_ID=''
  IFS= read -r CONTAINER_ID <<< "$CONTAINER_LIST"
  [[ -n "$CONTAINER_ID" ]] || fail 'no running useMeter container; set USEMETER_DRILL_IMAGE to a built image'
  IMAGE_ID="$("${DOCKER[@]}" inspect --format '{{.Image}}' "$CONTAINER_ID")" || fail 'could not inspect the useMeter image'
fi
[[ "$IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'USEMETER_DRILL_IMAGE must be an image digest'

# This container has no network, no writable root filesystem, no production volume,
# and only read-only mounts for the candidate and validator source.
"${DOCKER[@]}" run --rm \
  --user "$(id -u):$(id -g)" \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,nosuid,size=32m \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --pids-limit 64 \
  --mount "type=bind,src=$BACKUP_FILE,dst=/app/.restore-candidate.sqlite,readonly" \
  --mount "type=bind,src=$SCRIPT_DIR/restore-drill.ts,dst=/app/.restore-drill.ts,readonly" \
  --entrypoint bun "$IMAGE_ID" \
  run /app/.restore-drill.ts /app/.restore-candidate.sqlite
