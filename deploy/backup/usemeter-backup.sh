#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() {
  printf 'usemeter-backup: %s\n' "$1" >&2
  exit 1
}

if (( EUID == 0 )); then fail 'must run unprivileged as murat'; fi
[[ "$(id -un)" == 'murat' ]] || fail 'must run as the murat account'

PROJECT_DIR="${USEMETER_PROJECT_DIR:-${HOME}/useMeter-deploy}"
COMPOSE_FILE="${USEMETER_COMPOSE_FILE:-${PROJECT_DIR}/compose.yaml}"
COMPOSE_SERVICE="${USEMETER_COMPOSE_SERVICE:-usemeter}"
BACKUP_DIR="${USEMETER_BACKUP_DIR:-${HOME}/usemeter-backups}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

[[ -d "$PROJECT_DIR" ]] || fail 'Compose project directory is missing'
if [[ "$COMPOSE_FILE" != /* ]]; then COMPOSE_FILE="$PROJECT_DIR/$COMPOSE_FILE"; fi
[[ -f "$COMPOSE_FILE" ]] || fail 'Compose file is missing'
[[ "$COMPOSE_SERVICE" =~ ^[A-Za-z0-9_.-]+$ ]] || fail 'invalid Compose service name'
[[ -x '/usr/bin/docker' ]] || command -v docker >/dev/null 2>&1 || fail 'Docker CLI is unavailable'
command -v realpath >/dev/null 2>&1 || fail 'realpath is unavailable'

[[ ! -L "$BACKUP_DIR" ]] || fail 'backup directory must not be a symlink'
mkdir -p -- "$BACKUP_DIR"
chmod 0700 -- "$BACKUP_DIR"
BACKUP_DIR="$(realpath -e -- "$BACKUP_DIR")"
[[ "$(stat -c '%u' -- "$BACKUP_DIR")" == "$(id -u)" ]] || fail 'backup directory is not owned by murat'
[[ "$(stat -c '%a' -- "$BACKUP_DIR")" == '700' ]] || fail 'backup directory must have mode 0700'

DOCKER=(sudo -n /usr/bin/docker)
COMPOSE=("${DOCKER[@]}" compose --project-directory "$PROJECT_DIR" --file "$COMPOSE_FILE")
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FINAL_NAME="usemeter-${STAMP}-${BASHPID}-${RANDOM}.sqlite"
FINAL_PATH="$BACKUP_DIR/$FINAL_NAME"
TEMP_DB="/app/data/.usemeter-backup-${BASHPID}-${RANDOM}.sqlite"
CONTAINER_NAME="usemeter-backup-${BASHPID}-${RANDOM}"
CONTAINER_ID=''
WORK_DIR=''
CLEAN_TEMP=0
CLEAN_CONTAINER=0

remove_volume_temp() {
  "${COMPOSE[@]}" run --rm --no-deps \
    --volume "$SCRIPT_DIR/snapshot.ts:/run/usemeter-backup-snapshot.ts:ro" \
    --env "USEMETER_BACKUP_TEMP_PATH=$TEMP_DB" \
    --env "USAGE_MASTER_KEY=" \
    --env "GOOGLE_OAUTH_CLIENT_SECRET=" \
    --env "ZAI_OAUTH_CLIENT_SECRET=" \
    --entrypoint bun "$COMPOSE_SERVICE" \
    run /run/usemeter-backup-snapshot.ts remove >/dev/null
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if (( CLEAN_TEMP == 1 )); then
    if ! remove_volume_temp; then
      printf 'usemeter-backup: could not remove its temporary volume snapshot\n' >&2
      if (( status == 0 )); then status=1; fi
    fi
  fi
  if (( CLEAN_CONTAINER == 1 )); then "${DOCKER[@]}" rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true; fi
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then rm -rf -- "$WORK_DIR"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ ! -e "$FINAL_PATH" ]] || fail 'backup filename collision; retry the run'
WORK_DIR="$(mktemp -d "$BACKUP_DIR/.work.XXXXXXXX")"
chmod 0700 -- "$WORK_DIR"

CONTAINER_ID="$("${COMPOSE[@]}" run --detach --no-deps --name "$CONTAINER_NAME" \
  --volume "$SCRIPT_DIR/snapshot.ts:/run/usemeter-backup-snapshot.ts:ro" \
  --env "USEMETER_BACKUP_TEMP_PATH=$TEMP_DB" \
  --env "USAGE_MASTER_KEY=" \
  --env "GOOGLE_OAUTH_CLIENT_SECRET=" \
  --env "ZAI_OAUTH_CLIENT_SECRET=" \
  --entrypoint bun "$COMPOSE_SERVICE" \
  run /run/usemeter-backup-snapshot.ts create)" || fail 'could not start the snapshot container'
[[ "$CONTAINER_ID" =~ ^[0-9a-f]{12,64}$ ]] || fail 'snapshot container did not return an ID'
CLEAN_CONTAINER=1
CONTAINER_STATUS="$("${DOCKER[@]}" wait "$CONTAINER_ID")" || fail 'could not wait for the snapshot container'
if [[ "$CONTAINER_STATUS" != '0' ]]; then
  "${DOCKER[@]}" logs "$CONTAINER_ID" >&2 || true
  fail 'SQLite snapshot creation or validation failed'
fi
CLEAN_TEMP=1
"${DOCKER[@]}" logs "$CONTAINER_ID"

TEMP_BASE="${TEMP_DB##*/}"
"${DOCKER[@]}" cp "$CONTAINER_ID:$TEMP_DB" - | tar --no-same-owner --no-same-permissions -xf - -C "$WORK_DIR"
[[ -f "$WORK_DIR/$TEMP_BASE" && ! -L "$WORK_DIR/$TEMP_BASE" ]] || fail 'extracted snapshot file is missing or invalid'
mv -- "$WORK_DIR/$TEMP_BASE" "$WORK_DIR/$FINAL_NAME"
chmod 0600 -- "$WORK_DIR/$FINAL_NAME"
[[ "$(stat -c '%u' -- "$WORK_DIR/$FINAL_NAME")" == "$(id -u)" ]] || fail 'copied backup is not owned by murat'
[[ "$(stat -c '%a' -- "$WORK_DIR/$FINAL_NAME")" == '600' ]] || fail 'copied backup does not have mode 0600'
DRILL_IMAGE="$("${DOCKER[@]}" inspect --format '{{.Image}}' "$CONTAINER_ID")" || fail 'could not resolve the snapshot image'
[[ "$DRILL_IMAGE" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'snapshot image digest is invalid'
USEMETER_DRILL_IMAGE="$DRILL_IMAGE" "$SCRIPT_DIR/usemeter-restore-drill.sh" "$WORK_DIR/$FINAL_NAME"
mv -- "$WORK_DIR/$FINAL_NAME" "$FINAL_PATH"

if ! remove_volume_temp; then fail 'verified host backup exists, but temporary volume copy cleanup failed'; fi
CLEAN_TEMP=0
"${DOCKER[@]}" rm "$CONTAINER_ID" >/dev/null
CLEAN_CONTAINER=0
CONTAINER_ID=''

prune_retention() {
  local now modified name epoch age week path
  local -A retained_week=()
  now="$(date +%s)"
  while IFS=' ' read -r modified name; do
    [[ "$name" =~ ^usemeter-[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9-]+\.sqlite$ ]] || continue
    path="$BACKUP_DIR/$name"
    [[ -f "$path" && ! -L "$path" ]] || continue
    epoch="${modified%%.*}"
    [[ "$epoch" =~ ^[0-9]+$ ]] || continue
    age=$((now - epoch))
    if (( age < 0 )); then age=0; fi
    if (( age <= 604800 )); then
      continue
    elif (( age <= 2419200 )); then
      week="$(date -u -d "@$epoch" +%G-%V)"
      if [[ -n "${retained_week[$week]+present}" ]]; then
        rm -f -- "$path"
      else
        retained_week[$week]=1
      fi
    else
      rm -f -- "$path"
    fi
  done < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type f -name 'usemeter-*.sqlite' -printf '%T@ %f\n' | sort -rn)
}

prune_retention
printf 'Backup verified: %s\n' "$FINAL_PATH"
