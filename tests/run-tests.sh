#!/usr/bin/env bash
# ==============================================================================
#  Тесты deploy.sh без настоящего ядра: auditctl/augenrules/getenforce
#  подменяются заглушками, /etc/audit — временным каталогом.
#  Запуск: bash tests/run-tests.sh   (root не нужен)
# ==============================================================================
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAILS=0

setup() {
    T="$(mktemp -d)"
    mkdir -p "$T/etc/rules.d" "$T/bin" "$T/backup"
    : > "$T/kernel"   # «ядро»: загруженные правила, по одному на строку

    # auditctl: -l, -s, -D, -R file. Строка с FAILME имитирует ошибку ядра.
    cat > "$T/bin/auditctl" <<'EOS'
#!/usr/bin/env bash
K="$STUB_KERNEL"
case "$1" in
  -l) if [[ -s "$K" ]]; then cat "$K"; else echo "No rules"; fi ;;
  -s) echo "enabled 1"; echo "lost 0"; echo "backlog 0" ;;
  -D) : > "$K"; echo "No rules" ;;
  -R) n=0
      while IFS= read -r l; do
        n=$((n+1))
        [[ -z "$l" || "$l" == \#* ]] && continue
        case "$l" in
          -D) : > "$K" ;;
          -b*|-f*|-e*) ;;
          *FAILME*) echo "There was an error in line $n of $2" >&2; exit 1 ;;
          -w*) echo "Old style watch rules are slower" >&2; echo "$l" >> "$K" ;;
          -a*) echo "$l" >> "$K" ;;
          *) echo "parameter passed without an option given" >&2
             echo "There was an error in line $n of $2" >&2; exit 1 ;;
        esac
      done < "$2" ;;
esac
EOS
    # augenrules: склеить rules.d/*.rules без комментариев и загрузить
    cat > "$T/bin/augenrules" <<'EOS'
#!/usr/bin/env bash
out="$STUB_AUDIT_RULES"
{ echo "## generated"; cat "$STUB_RULES_D"/*.rules 2>/dev/null | grep -vE '^\s*(#|$)'; } > "$out"
auditctl -R "$out"
EOS
    printf '#!/bin/sh\necho "${STUB_SELINUX:-Enforcing}"\n' > "$T/bin/getenforce"
    chmod +x "$T/bin/"*

    export PATH="$T/bin:$PATH" STUB_KERNEL="$T/kernel" STUB_RULES_D="$T/etc/rules.d" \
           STUB_AUDIT_RULES="$T/etc/audit.rules" AUDIT_RULES_D="$T/etc/rules.d" \
           AUDIT_RULES_FILE="$T/etc/audit.rules" AUDIT_BACKUP_DIR="$T/backup" \
           AUDIT_ALLOW_NONROOT=1
    # «Старый» набор, который должен уйти в бэкап
    printf -- '-D\n-w /etc/old -p wa -k old\n-w /etc/old2 -p wa -k old\n' > "$T/etc/rules.d/audit.rules"
    augenrules --load >/dev/null 2>&1
}

check() {  # check <имя> <условие...>
    local name="$1"; shift
    if "$@"; then PASS=$((PASS+1)); echo "  ok   $name"
    else FAILS=$((FAILS+1)); echo "  FAIL $name"; fi
}
kernel_count() { grep -c . "$T/kernel" || true; }

echo "1. aarch64: чистая установка"
setup
AUDIT_ARCH=aarch64 bash "$REPO/deploy/deploy.sh" > "$T/out" 2>&1; rc=$?
check "код возврата 0" test $rc -eq 0
check "в ядре 55 правил" test "$(kernel_count)" -eq 55
check "старый файл убран из rules.d" test ! -e "$T/etc/rules.d/audit.rules"
check "старый файл есть в бэкапе" test -n "$(find "$T/backup" -name audit.rules -path '*rules.d*')"
rm -rf "$T"

echo "2. x86_64, SELinux Enforcing"
setup
STUB_SELINUX=Enforcing AUDIT_ARCH=x86_64 bash "$REPO/deploy/deploy.sh" > "$T/out" 2>&1; rc=$?
check "код возврата 0" test $rc -eq 0
check "в ядре 60 правил" test "$(kernel_count)" -eq 60
rm -rf "$T"

echo "3. x86_64, SELinux Disabled — subj_type вырезаются"
setup
STUB_SELINUX=Disabled AUDIT_ARCH=x86_64 bash "$REPO/deploy/deploy.sh" > "$T/out" 2>&1; rc=$?
check "код возврата 0" test $rc -eq 0
check "в ядре 58 правил" test "$(kernel_count)" -eq 58
check "subj_type не установлен" bash -c "! grep -q subj_type '$T/etc/rules.d/99-custom-x86_64.rules'"
check "исходник в репозитории не изменён" grep -q subj_type "$REPO/rules/99-custom-x86_64.rules"
rm -rf "$T"

echo "4. Файл с CRLF отклоняется, ядро не тронуто"
setup
sed 's/$/\r/' "$REPO/rules/99-custom-aarch64.rules" > "$T/crlf.rules"
AUDIT_ARCH=aarch64 bash "$REPO/deploy/deploy.sh" --rules "$T/crlf.rules" > "$T/out" 2>&1; rc=$?
check "код возврата != 0" test $rc -ne 0
check "сообщение про CRLF" grep -q CRLF "$T/out"
check "в ядре по-прежнему 2 старых правила" test "$(kernel_count)" -eq 2
rm -rf "$T"

echo "5. Мусор от вставки из буфера отклоняется"
setup
{ cat "$REPO/rules/99-custom-aarch64.rules"; echo "sudo augenrules --loadравила"; } > "$T/junk.rules"
AUDIT_ARCH=aarch64 bash "$REPO/deploy/deploy.sh" --rules "$T/junk.rules" > "$T/out" 2>&1; rc=$?
check "код возврата != 0" test $rc -ne 0
check "указана битая строка" grep -q 'не похожа на правило' "$T/out"
rm -rf "$T"

echo "6. Старый syscall на aarch64 отклоняется"
setup
{ cat "$REPO/rules/99-custom-aarch64.rules"; echo "-a always,exit -F arch=b64 -S chmod -k x"; } > "$T/old.rules"
AUDIT_ARCH=aarch64 bash "$REPO/deploy/deploy.sh" --rules "$T/old.rules" > "$T/out" 2>&1; rc=$?
check "код возврата != 0" test $rc -ne 0
check "названа причина" grep -q '«chmod» отсутствует на aarch64' "$T/out"
rm -rf "$T"

echo "7. Ошибка загрузки в ядро — откат к прежнему набору"
setup
{ cat "$REPO/rules/99-custom-aarch64.rules"; echo "-w /etc/FAILME -p wa -k x"; } > "$T/fail.rules"
AUDIT_ARCH=aarch64 bash "$REPO/deploy/deploy.sh" --rules "$T/fail.rules" > "$T/out" 2>&1; rc=$?
check "код возврата != 0" test $rc -ne 0
check "старый файл возвращён в rules.d" test -e "$T/etc/rules.d/audit.rules"
check "в ядре снова 2 старых правила" test "$(kernel_count)" -eq 2
rm -rf "$T"

echo "8. --dry-run ничего не меняет"
setup
AUDIT_ARCH=aarch64 bash "$REPO/deploy/deploy.sh" --dry-run > "$T/out" 2>&1; rc=$?
check "код возврата 0" test $rc -eq 0
check "в ядре 2 старых правила" test "$(kernel_count)" -eq 2
rm -rf "$T"

echo
echo "Итого: пройдено $PASS, упало $FAILS"
[[ $FAILS -eq 0 ]]
