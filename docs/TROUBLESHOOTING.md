# Ошибки и что с ними делать

Сначала общее правило: **`auditctl -R` (и `augenrules --load`) останавливается
на первой ошибке.** Всё, что ниже битой строки, не загружено. Поэтому после
любой ошибки сверяйте число правил:

```bash
grep -cE '^-[aw] ' /etc/audit/rules.d/99-custom-*.rules
sudo auditctl -l | wc -l
```

И второе: номер в `There was an error in line N of /etc/audit/audit.rules`
относится к **сгенерированному** файлу, а не к вашему файлу в `rules.d`:

```bash
sudo sed -n 'Np' /etc/audit/audit.rules
```

---

### `Error sending add rule data request (Rule exists)`

В ядре уже есть такое правило. Причины:

- в файле нет `-D` в начале (в наборе он есть);
- в `/etc/audit/rules.d/` лежат другие `*.rules` с теми же правилами —
  `augenrules` склеивает все файлы каталога;
- `rules.d` пуст, и `augenrules` загрузил старый `/etc/audit/audit.rules`.

```bash
ls -l /etc/audit/rules.d/
sudo bash deploy/deploy.sh      # уберёт лишние файлы в резервную копию
```

### `Syscall name unknown: chmod` (aarch64)

На aarch64 нет «старых» syscall. Используйте `99-custom-aarch64.rules` —
см. [ARCHITECTURE.md](ARCHITECTURE.md).

### `parameter passed without an option given`

Строка не начинается с параметра `auditctl`. Типичные причины: Windows-переводы
строк (CRLF), BOM в начале файла, обрезанная или «склеенная» при вставке строка.

```bash
sudo cat -A /etc/audit/rules.d/99-custom-*.rules | grep -n '\^M'   # CRLF
head -c3 /etc/audit/rules.d/99-custom-*.rules | od -c              # BOM: 357 273 277
sudo sed -i 's/\r$//' /etc/audit/rules.d/99-custom-*.rules        # убрать CRLF
```

`deploy.sh --dry-run` находит все эти случаи до загрузки.

### `-bash: /etc/audit/rules.d/...: Отказано в доступе`

Вы выполнили `sudo cat ... > /etc/...` под обычным пользователем:
перенаправление делает ваша оболочка, а не `sudo`. Используйте
`sudo tee файл > /dev/null`, а лучше — `deploy.sh`.

### Ошибка на строке с `subj_type`

SELinux выключен (`getenforce` → `Disabled`). `deploy.sh` вырезает такие строки
автоматически; при ручной установке удалите их.

### `Unknown user: ntp`

В правиле указан пользователь по имени (`-F uid=ntp`), которого нет на хосте.
В этом наборе таких правил нет — значит, загружается старый файл
(см. `Rule exists`).

### `Error sending add rule data request (No such file or directory)`

Правило с `-F dir=` или `-F path=` указывает на несуществующий путь. В наборе
используются только `/etc` и `/root`; если ошибка есть — загружается
старый файл.

### `Old style watch rules are slower`

Не ошибка: так `auditctl` 3.x помечает каждое правило `-w`. По их числу удобно
понимать, докуда дошла загрузка (в наборе их 45).

### `perm used without an arch is slower`

Не ошибка: правило с `-F perm=` без `-F arch=`. В этом наборе таких правил нет.

### В `aureport` старые ключи и тысячи событий после замены правил

`aureport` читает журнал за период, а не текущие правила. `-ts recent` — это
последние 10 минут. Смотрите `auditctl -l` и замер по окну времени:

```bash
sudo ausearch -k network_socket_created -ts recent 2>/dev/null | grep -c 'type=SYSCALL'
```

### `lost` в `auditctl -s` больше нуля

Счётчик накопительный с момента запуска `auditd`. Проблема — только если он
растёт. Тогда увеличьте `-b` или ищите шумное правило:
`sudo aureport -k --summary -ts this-hour`.

### Тестовое событие не появляется

Правила пользовательских действий фильтруют по `auid`. Команда, запущенная из
cron, systemd или сессии без входа, имеет `auid=-1` и не записывается.
Проверяйте из обычной SSH-сессии (можно через `sudo`).

### Правила не загрузились после перезагрузки

```bash
ls -l /etc/audit/rules.d/
systemctl status auditd
sudo augenrules --check     # "No change" — audit.rules соответствует rules.d
```

### Как откатиться вручную

`deploy.sh` хранит копии в `/var/backups/auditd-rules/<дата>/`:

```bash
ls /var/backups/auditd-rules/
sudo rm /etc/audit/rules.d/*.rules
sudo cp /var/backups/auditd-rules/<дата>/rules.d/* /etc/audit/rules.d/
sudo augenrules --load
```
