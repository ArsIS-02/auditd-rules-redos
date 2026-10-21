# Graylog: разбор событий auditd

## Доставка журнала

Свод правил не зависит от способа доставки. Обычные варианты:

- **Graylog Sidecar + Filebeat** — чтение `/var/log/audit/audit.log`;
- **rsyslog** — модуль `imfile` для `/var/log/audit/audit.log` или плагин аудита
  `syslog` (`/etc/audit/plugins.d/syslog.conf`, `active = yes`), далее пересылка
  в Syslog-вход Graylog.

## Формат журнала: ENRICHED

Проверьте `/etc/audit/auditd.conf`:

```ini
log_format = ENRICHED
```

В этом режиме auditd ещё на хосте расшифровывает uid/gid, номер syscall,
архитектуру и адреса сокетов и дописывает их в конец записи после разделителя
`0x1D`: `ARCH=aarch64 SYSCALL=fchmodat AUID="user" UID="root" ...`.
Это важно для SIEM: UID имеет смысл только на том хосте, где событие возникло,
а Graylog видит уже готовые имена. После изменения — `sudo service auditd restart`.

`proctitle` при этом остаётся в hex (командная строка процесса, аргументы
разделены нулевым байтом).

## Pipeline

Создайте pipeline (System → Pipelines), подключите его к потоку с событиями
аудита и добавьте правила в один этап (Stage 0, «at least one rule»).

### 1. Тип записи и идентификатор события

Записи одного события (`SYSCALL`, `PATH`, `CWD`, `PROCTITLE`) имеют общий
`msg=audit(время:номер)` — по `audit_event_id` их удобно собирать вместе.

```
rule "auditd: type and event id"
when
  has_field("message") &&
  regex("type=[A-Z_]+ msg=audit\\(", to_string($message.message)).matches == true
then
  let m = regex("type=([A-Z_]+) msg=audit\\(([0-9.]+):([0-9]+)\\)", to_string($message.message));
  set_field("audit_type", m["0"]);
  set_field("audit_event_id", m["2"]);
  set_field("event_source_type", "auditd");
end
```

### 2. Ключ правила

```
rule "auditd: key"
when
  has_field("message") &&
  regex("key=\"[^\"]+\"", to_string($message.message)).matches == true
then
  let m = regex("key=\"([^\"]+)\"", to_string($message.message));
  set_field("audit_key", m["0"]);
end
```

### 3. Поля SYSCALL

```
rule "auditd: syscall fields"
when
  has_field("message") &&
  contains(to_string($message.message), "type=SYSCALL")
then
  let msg = to_string($message.message);
  let f = regex(" syscall=([0-9]+) success=([a-z]+) .* auid=([0-9]+) uid=([0-9]+) .* comm=\"([^\"]*)\" exe=\"([^\"]*)\"", msg);
  set_field("audit_syscall_nr", f["0"]);
  set_field("audit_success", f["1"]);
  set_field("audit_auid", f["2"]);
  set_field("audit_uid", f["3"]);
  set_field("audit_comm", f["4"]);
  set_field("audit_exe", f["5"]);
end
```

### 4. Расшифрованные имена (ENRICHED)

```
rule "auditd: enriched names"
when
  has_field("message") &&
  regex("AUID=\"[^\"]*\"", to_string($message.message)).matches == true
then
  let msg = to_string($message.message);
  let a = regex("AUID=\"([^\"]*)\"", msg);
  set_field("audit_auid_name", a["0"]);
  let s = regex("SYSCALL=([a-z0-9_]+)", msg);
  set_field("audit_syscall", s["0"]);
end
```

## Примеры поиска

```
audit_key:(identity_modification OR kernel_modules OR auditconfig)
audit_key:unauthorized_access_attempt AND audit_auid_name:*
audit_key:network_socket_created AND NOT audit_exe:"/usr/bin/python3.11"
```

## Идеи для алертов

| Условие | Тип |
|---|---|
| `audit_key:(identity_modification OR kernel_modules OR auditconfig OR audit_tools)` | любое событие |
| `audit_key:(cron_persistence OR systemd_persistence)` | любое событие |
| `audit_key:unauthorized_access_attempt` | > 10 за 2 минуты, группировка по `source` и `audit_auid` |
| `audit_key:suspicious_network_tool` | любое событие |
