#!/usr/bin/env bash
# ==============================================================================
#  deploy.sh — установка свода правил auditd на хост РЕД ОС
#
#  Что делает:
#   1. Определяет архитектуру и выбирает файл из rules/ (или берёт --rules).
#   2. Проверяет файл ДО того, как трогать ядро: CRLF, BOM, мусор в строках,
#      syscall, которых нет на aarch64, правила subj_type без SELinux.
#   3. Делает резервную копию rules.d, audit.rules и текущего auditctl -l.
#   4. Ставит файл в /etc/audit/rules.d/ и загружает через augenrules --load.
#   5. Сверяет число загруженных правил с числом правил в файле.
#      При ошибке — откатывает прежний набор (если не указан --no-rollback).
#
#  Использование:
#   sudo ./deploy/deploy.sh                 # автовыбор по архитектуре
#   sudo ./deploy/deploy.sh --dry-run       # только проверка файла
#   sudo ./deploy/deploy.sh --rules FILE    # явный файл правил
# ==============================================================================
set -Eeuo pipefail

# --- Пути и команды (переопределяются через окружение — нужно для тестов) -----
RULES_D="${AUDIT_RULES_D:-/etc/audit/rules.d}"
AUDIT_RULES="${AUDIT_RULES_FILE:-/etc/audit/audit.rules}"
BACKUP_ROOT="${AUDIT_BACKUP_DIR:-/var/backups/auditd-rules}"
AUDITCTL="${AUDITCTL:-auditctl}"
AUGENRULES="${AUGENRULES:-augenrules}"
GETENFORCE="${GETENFORCE:-getenforce}"
ARCH="${AUDIT_ARCH:-$(uname -m)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RULES_SRC=""
DRY_RUN=0
ROLLBACK=1

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; NC=""
fi
info() { printf '%s==>%s %s\n' "$YELLOW" "$NC" "$*"; }
ok()   { printf '%s[OK]%s %s\n' "$GREEN" "$NC" "$*"; }
err()  { printf '%s[ОШИБКА]%s %s\n' "$RED" "$NC" "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rules)       RULES_SRC="${2:?--rules требует путь к файлу}"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        --no-rollback) ROLLBACK=0; shift ;;
        -h|--help)     usage ;;
        *)             die "Неизвестный параметр: $1 (см. --help)" ;;
    esac
done

# --- 1. Выбор файла правил -----------------------------------------------------
if [[ -z "$RULES_SRC" ]]; then
    case "$ARCH" in
        aarch64) RULES_SRC="${REPO_DIR}/rules/99-custom-aarch64.rules" ;;
        x86_64)  RULES_SRC="${REPO_DIR}/rules/99-custom-x86_64.rules" ;;
        *)       die "Архитектура $ARCH не поддерживается (нужна aarch64 или x86_64)" ;;
    esac
fi
[[ -f "$RULES_SRC" ]] || die "Файл правил не найден: $RULES_SRC"
RULES_NAME="$(basename "$RULES_SRC")"
info "Архитектура: $ARCH, файл правил: $RULES_SRC"

if [[ $DRY_RUN -eq 0 && $EUID -ne 0 && -z "${AUDIT_ALLOW_NONROOT:-}" ]]; then
    die "Нужны права root: запустите через sudo"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- 2. Проверка файла ---------------------------------------------------------
lint_rules() {
    local f="$1" problems=0 n=0 line

    if [[ "$(head -c3 "$f" | od -An -tx1 | tr -d ' \n')" == "efbbbf" ]]; then
        err "Файл начинается с BOM (сохранён в Windows как «UTF-8 с BOM»)"
        problems=$((problems + 1))
    fi
    if grep -q $'\r' "$f"; then
        err "В файле Windows-переводы строк (CRLF): $(grep -c $'\r' "$f") строк"
        err "Исправить: sed -i 's/\\r\$//' $f   (или клонировать репозиторий заново — .gitattributes держит LF)"
        problems=$((problems + 1))
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! "$line" =~ ^-[A-Za-z] ]]; then
            err "Строка $n не похожа на правило (должна начинаться с «-»): $line"
            problems=$((problems + 1))
            continue
        fi
        if LC_ALL=C grep -q '[^ -~]' <<<"$line"; then
            err "Строка $n содержит не-ASCII символы (вероятно, склейка при вставке): $line"
            problems=$((problems + 1))
        fi
        if [[ "$ARCH" == "aarch64" ]]; then
            if [[ "$line" == *"arch=b32"* ]]; then
                err "Строка $n: arch=b32 на aarch64 не используется в этом наборе: $line"
                problems=$((problems + 1))
            fi
            if [[ "$line" =~ -S[[:space:]]+([^[:space:]]+) ]]; then
                local s
                for s in ${BASH_REMATCH[1]//,/ }; do
                    case "$s" in
                        chmod|chown|lchown|open|creat|rename|unlink|rmdir|mkdir|link|symlink|mknod)
                            err "Строка $n: syscall «$s» отсутствует на aarch64 — используйте *at-вариант"
                            problems=$((problems + 1)) ;;
                    esac
                done
            fi
        fi
    done < "$f"

    return $(( problems > 0 ))
}

info "Проверка файла правил..."
lint_rules "$RULES_SRC" || die "Файл не прошёл проверку, ядро не тронуто"
ok "Формат файла в порядке"

# SELinux: правила с subj_type без SELinux не загрузятся
INSTALL_SRC="$WORK/$RULES_NAME"
cp "$RULES_SRC" "$INSTALL_SRC"
if grep -qE '^[[:space:]]*-a.*subj_type=' "$INSTALL_SRC"; then
    selinux="$("$GETENFORCE" 2>/dev/null || echo Disabled)"
    if [[ "$selinux" == "Disabled" ]]; then
        info "SELinux выключен — правила с subj_type будут исключены из установки:"
        grep -nE '^[[:space:]]*-a.*subj_type=' "$INSTALL_SRC" | sed 's/^/    /'
        sed -i -E '/^[[:space:]]*-a.*subj_type=/d' "$INSTALL_SRC"
    else
        ok "SELinux: $selinux — правила с subj_type остаются"
    fi
fi

EXPECTED="$(grep -cE '^[[:space:]]*-[aw][[:space:]]' "$INSTALL_SRC" || true)"
info "Ожидается правил после загрузки: $EXPECTED"

if [[ $DRY_RUN -eq 1 ]]; then
    ok "Режим --dry-run: проверка пройдена, ничего не изменено"
    exit 0
fi

# --- 3. Резервная копия --------------------------------------------------------
BACKUP_DIR="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR/rules.d"
chmod 0700 "$BACKUP_ROOT" "$BACKUP_DIR"
shopt -s nullglob
old_rules=("$RULES_D"/*.rules)
shopt -u nullglob
for f in "${old_rules[@]}"; do cp -a "$f" "$BACKUP_DIR/rules.d/"; done
[[ -f "$AUDIT_RULES" ]] && cp -a "$AUDIT_RULES" "$BACKUP_DIR/audit.rules"
"$AUDITCTL" -l > "$BACKUP_DIR/auditctl-l.before.txt" 2>&1 || true
ok "Резервная копия: $BACKUP_DIR (файлов в rules.d: ${#old_rules[@]})"

restore_backup() {
    err "Откат к прежнему набору правил из $BACKUP_DIR"
    rm -f "$RULES_D"/*.rules
    cp -a "$BACKUP_DIR"/rules.d/. "$RULES_D"/ 2>/dev/null || true
    "$AUGENRULES" --load >/dev/null 2>&1 || true
    err "После отката загружено правил: $("$AUDITCTL" -l 2>/dev/null | grep -vc '^No rules' || true)"
}

# --- 4. Установка и загрузка ---------------------------------------------------
# Старые файлы убираем из rules.d: augenrules склеивает ВСЕ *.rules в каталоге
rm -f "$RULES_D"/*.rules
install -m 0640 "$INSTALL_SRC" "$RULES_D/$RULES_NAME"
command -v restorecon >/dev/null 2>&1 && restorecon -F "$RULES_D/$RULES_NAME" 2>/dev/null || true

info "Загрузка правил (augenrules --load)..."
set +e
"$AUGENRULES" --load > "$WORK/load.log" 2>&1
rc=$?
set -e
# Предупреждения о «старом» синтаксисе -w — не ошибки
grep -vE 'Old style watch rules are slower|perm used without an arch is slower|^No rules$|^enabled |^failure |^pid |^rate_limit |^backlog|^lost |^loginuid_immutable' \
    "$WORK/load.log" > "$WORK/load.errors" || true
cp "$WORK/load.log" "$BACKUP_DIR/augenrules-load.log"

ACTUAL="$("$AUDITCTL" -l 2>/dev/null | grep -vc '^No rules' || true)"

# --- 5. Итог -------------------------------------------------------------------
if [[ $rc -ne 0 || "$ACTUAL" -ne "$EXPECTED" ]]; then
    err "Загрузка не удалась: код $rc, загружено $ACTUAL из $EXPECTED"
    if [[ -s "$WORK/load.errors" ]]; then
        err "Сообщения augenrules/auditctl:"
        sed 's/^/    /' "$WORK/load.errors" >&2
        err "Номер строки в «error in line N» относится к $AUDIT_RULES — смотрите: sed -n 'Np' $AUDIT_RULES"
    fi
    [[ $ROLLBACK -eq 1 ]] && restore_backup
    exit 1
fi

ok "Загружено правил: $ACTUAL из $EXPECTED"
"$AUDITCTL" -l | grep -E 'key=network_socket_created' | sed 's/^/    /' || true
ok "Готово. Проверка: sudo ./deploy/verify.sh"
