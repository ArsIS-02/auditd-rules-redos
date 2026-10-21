#!/usr/bin/env bash
# ==============================================================================
#  verify.sh — проверка загруженного свода правил auditd
#
#   sudo ./deploy/verify.sh          # состояние правил и демона
#   sudo ./deploy/verify.sh --test   # + тестовые события (chmod, сокет)
#
#  --test запускайте из обычной SSH-сессии через sudo: правила фильтруют по
#  auid (идентификатор входа), а у сессии без входа (cron, systemd) он не задан.
# ==============================================================================
set -uo pipefail

AUDITCTL="${AUDITCTL:-auditctl}"
RUN_TEST=0
[[ "${1:-}" == "--test" ]] && RUN_TEST=1

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; NC=""
fi
FAIL=0
pass() { printf '%s[OK]%s %s\n' "$GREEN" "$NC" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$RED" "$NC" "$*"; FAIL=1; }
head_() { printf '\n%s=== %s ===%s\n' "$YELLOW" "$*" "$NC"; }

RULES="$("$AUDITCTL" -l 2>/dev/null | grep -v '^No rules')"
COUNT="$(grep -c . <<<"$RULES" || true)"

head_ "Правила в ядре"
echo "Загружено правил: $COUNT"
INSTALLED=( /etc/audit/rules.d/99-custom-*.rules )
if [[ -f "${INSTALLED[0]}" ]]; then
    EXPECTED="$(grep -cE '^[[:space:]]*-[aw][[:space:]]' "${INSTALLED[0]}" || true)"
    if [[ "$COUNT" -eq "$EXPECTED" ]]; then
        pass "Совпадает с файлом ${INSTALLED[0]} ($EXPECTED)"
    else
        fail "В файле ${INSTALLED[0]} $EXPECTED правил, в ядре $COUNT — загрузка неполная"
    fi
else
    fail "Файл /etc/audit/rules.d/99-custom-*.rules не найден"
fi

head_ "Ключевые правила"
for key in auditconfig identity_modification privilege_escalation user_management \
           cron_persistence systemd_persistence kernel_modules network_socket_created \
           perm_modification file_deletion unauthorized_access_attempt power_management; do
    n="$(grep -cE "(-k |key=)${key}\$" <<<"$RULES" || true)"
    if [[ "$n" -gt 0 ]]; then pass "$key: $n"; else fail "$key: нет правил"; fi
done

head_ "Фильтр шума для сокетов"
sock="$(grep 'key=network_socket_created' <<<"$RULES")"
if [[ -n "$sock" ]] && ! grep -v 'auid>=1000' <<<"$sock" | grep -q . \
                    && ! grep -vE 'auid!=(-1|4294967295)' <<<"$sock" | grep -q .; then
    pass "Все правила сокетов содержат auid>=1000 и auid!=-1"
else
    fail "Есть правила сокетов без фильтров auid — будет шум"
fi

head_ "Демон аудита"
"$AUDITCTL" -s | grep -E '^(enabled|failure|backlog_limit|backlog|lost) '
echo "Счётчик lost накопительный (с запуска auditd): важен его рост, а не значение."

if [[ $RUN_TEST -eq 1 ]]; then
    head_ "Тестовые события"
    t="$(mktemp /tmp/audit-verify.XXXXXX)"
    chmod 0644 "$t"; rm -f "$t"
    command -v python3 >/dev/null && python3 -c 'import socket; socket.socket().close()'
    sleep 2
    for key in perm_modification network_socket_created; do
        if ausearch -k "$key" -ts recent 2>/dev/null | grep -q 'type=SYSCALL'; then
            pass "$key: событие записано"
        else
            fail "$key: события нет (сессия без auid? запустите из SSH через sudo)"
        fi
    done
fi

echo
if [[ $FAIL -eq 0 ]]; then pass "Проверка пройдена"; else fail "Есть проблемы, см. выше"; fi
exit $FAIL
