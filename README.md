# auditd-rules-redos

Свод правил **auditd** для **РЕД ОС** (aarch64 и x86_64), настроенный под отправку
событий в SIEM — **Graylog** и **Wazuh**. Цель — видеть действия людей и попытки
закрепиться в системе, а не тысячи фоновых событий от системных служб.

В репозитории: сами правила, скрипт установки с проверками и откатом, скрипт
проверки, правила для Wazuh, pipeline для Graylog и подробный рассказ о том,
как набор создавался и какие грабли были собраны по пути.

## Кратко

| | aarch64 | x86_64 |
|---|---|---|
| Файл | [`rules/99-custom-aarch64.rules`](rules/99-custom-aarch64.rules) | [`rules/99-custom-x86_64.rules`](rules/99-custom-x86_64.rules) |
| Правил в `auditctl -l` | 56 | 61 (59 без SELinux) |
| Syscall | только `*at` (`fchmodat`, `openat`, `unlinkat`...) | старые и `*at` |
| 32-битные приложения (`arch=b32`) | нет | да |
| Исключения по SELinux (`subj_type`) | нет | да, убираются автоматически при `SELinux Disabled` |
| Статус | **проверен на 4 хостах** (audit 3.1.3) | синтаксис проверен, на живом хосте ещё не подтверждён |

Главная оптимизация: создание сокетов и файловые операции записываются только
в **пользовательских сессиях** (`-F auid>=1000 -F auid!=-1`). Было — больше
11 000 событий `network_socket_created` в отчёте, почти все от служб; стало —
только то, что делают люди (включая действия через `sudo`).

## Структура

```
auditd-rules-redos/
├── rules/
│   ├── 99-custom-aarch64.rules   # ARM64 (Raspberry Pi и др.)
│   └── 99-custom-x86_64.rules    # x86_64
├── deploy/
│   ├── deploy.sh                 # установка: проверка → бэкап → загрузка → сверка → откат
│   └── verify.sh                 # проверка загруженных правил (+ --test)
├── wazuh/
│   ├── local_rules.xml           # правила Wazuh по ключам аудита
│   └── README.md
├── graylog/
│   └── pipeline-rules.md         # извлечение key/auid/syscall в поля
├── docs/
│   ├── HISTORY.md                # как создавался набор: проблемы и решения
│   ├── ARCHITECTURE.md           # aarch64 и x86_64: syscall, b32, SELinux
│   └── TROUBLESHOOTING.md        # ошибки auditctl/augenrules и что с ними делать
├── tests/
│   └── run-tests.sh              # тесты deploy.sh на заглушках (root не нужен)
├── CHANGELOG.md
└── LICENSE
```

## Установка

### На самом хосте

```bash
git clone https://github.com/ArsIS-02/auditd-rules-redos.git
cd auditd-rules-redos
sudo bash deploy/deploy.sh --dry-run   # только проверить файл
sudo bash deploy/deploy.sh             # установить
sudo bash deploy/verify.sh --test      # проверить, в т.ч. тестовыми событиями
```

`deploy.sh` сам выбирает файл по `uname -m`. Перед загрузкой он проверяет файл
(CRLF, BOM, «мусорные» строки, syscall, которых нет на aarch64), сохраняет
прежние правила в `/var/backups/auditd-rules/<дата>/`, а после загрузки сверяет
число правил в ядре с числом правил в файле. Если не совпало — возвращает
прежний набор.

### С Windows на несколько хостов

Клонируйте репозиторий (файл `.gitattributes` гарантирует Unix-переводы строк
даже при `core.autocrlf=true`) и разверните по SSH из PowerShell:

```powershell
cd auditd-rules-redos
foreach ($h in "user@host1", "user@host2") {
    ssh $h "mkdir -p /tmp/auditd-rules"
    scp -r rules deploy "${h}:/tmp/auditd-rules/"
    ssh -t $h "sudo bash /tmp/auditd-rules/deploy/deploy.sh"
}
```

> Не вставляйте содержимое правил в терминал через буфер обмена (heredoc на
> сотню строк). Именно так на нескольких хостах получились обрезанные и
> «склеенные» файлы — подробности в [docs/HISTORY.md](docs/HISTORY.md).

### Вручную

```bash
sudo cp rules/99-custom-$(uname -m).rules /etc/audit/rules.d/
sudo augenrules --load
sudo auditctl -l | wc -l
```

Учтите: `augenrules` склеивает **все** `*.rules` в `/etc/audit/rules.d/`, поэтому
старые файлы оттуда нужно убрать.

## Ключи событий

| Ключ | Что фиксирует | Важность |
|---|---|---|
| `auditconfig`, `audispconfig`, `auditlog`, `audit_tools` | изменение конфигурации и журналов аудита, запуск его утилит | критическая |
| `identity_modification` | запись в `/etc/passwd`, `shadow`, `group`, `gshadow`, `opasswd` | критическая |
| `kernel_modules`, `kernel_modules_config` | загрузка/выгрузка модулей ядра, `modprobe.d` | критическая |
| `privilege_escalation` | запуск `sudo`, `su` | высокая |
| `user_management` | `useradd`, `usermod`, `passwd` и др. | высокая |
| `cron_persistence`, `systemd_persistence` | изменения cron и unit-файлов systemd | высокая |
| `suspicious_network_tool`, `suspicious_download` | `nmap`, `tcpdump`, `nc`, `wget`, `curl` | высокая |
| `unauthorized_access_attempt` | неудачные `open/openat` в `/etc` и `/root`, кроме обращения крона GLPI к `/etc/krb5.keytab` | высокая |
| `network_config` | `/etc/hosts`, NetworkManager, `sysconfig/network` | средняя |
| `network_socket_created` | создание сокетов IPv4/IPv6 в пользовательских сессиях | средняя |
| `perm_modification` | `chmod`/`chown` в пользовательских сессиях | средняя |
| `file_deletion` | удаление и переименование в пользовательских сессиях | средняя |
| `file_creation` | создание каталогов и ссылок в пользовательских сессиях | низкая |
| `power_management` | `shutdown`, `reboot`, `poweroff` | низкая |

## Как измерить шум

`aureport` и `ausearch` читают **журнал**, а не текущие правила, и после замены
правил ещё долго показывают старые ключи. `-ts recent` — это последние
10 минут, поэтому числа в повторных запусках «плавают». Для замера темпа:

```bash
sudo ausearch -k network_socket_created -ts recent 2>/dev/null | grep -c 'type=SYSCALL'
sudo aureport -k --summary -ts this-hour
```

## SIEM

- **Wazuh** — [`wazuh/`](wazuh/README.md): правила 100100–100115 по полю `audit.key`.
- **Graylog** — [`graylog/pipeline-rules.md`](graylog/pipeline-rules.md): поля
  `audit_key`, `audit_type`, `audit_auid`, `audit_exe`.

## Требования

- РЕД ОС с пакетом `audit` (проверено на audit 3.1.3);
- права root для установки;
- для x86_64 с SELinux Enforcing — исключения по `crond_t` работают как есть.

## Тесты

```bash
bash tests/run-tests.sh
```

Проверяют `deploy.sh` на заглушках `auditctl`/`augenrules`: чистую установку на
обеих архитектурах, вырезание `subj_type` без SELinux, отказ от файлов с CRLF,
мусором и «старыми» syscall на aarch64, откат при ошибке загрузки.

## См. также

- [Graylog_streams-alerts](https://github.com/ArsIS-02/Graylog_streams-alerts) — потоки, алерты и дашборды Graylog.

## Лицензия

[GPL-3.0](LICENSE) © ArsIS-02
