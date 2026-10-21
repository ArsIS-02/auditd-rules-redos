# Интеграция с Wazuh

## Агент: читать журнал аудита

Если `audit` был установлен до агента Wazuh, агент уже читает
`/var/log/audit/audit.log`. Иначе добавьте в `/var/ossec/etc/ossec.conf` агента:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

## Сервер: правила по ключам

Штатный декодер Wazuh раскладывает событие auditd на поля `audit.key`,
`audit.exe`, `audit.auid`, `audit.euid` и т.д. Файл
[`local_rules.xml`](local_rules.xml) задаёт уровни тревоги по ключам этого свода:

| ID | Ключи | Уровень |
|---|---|---|
| 100100 | `auditconfig`, `audispconfig`, `auditlog`, `audit_tools` | 12 |
| 100101 | `identity_modification` | 12 |
| 100102 | `kernel_modules`, `kernel_modules_config` | 12 |
| 100103 | `privilege_escalation` | 6 |
| 100104 | `user_management` | 10 |
| 100105 | `cron_persistence`, `systemd_persistence` | 10 |
| 100106 | `suspicious_network_tool` | 10 |
| 100107 | `suspicious_download` | 7 |
| 100108 | `unauthorized_access_attempt` | 8 |
| 100109 | `network_config` | 8 |
| 100110 | `network_socket_created` | 3 |
| 100111 | `perm_modification` | 5 |
| 100112 | `file_deletion` | 3 |
| 100113 | `file_creation` | 3 |
| 100114 | `power_management` | 5 |
| 100115 | 10+ срабатываний 100108 за 2 минуты от одного `auid` | 12 |

Установка на сервере Wazuh:

```bash
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml   # или допишите группу в свой файл
sudo /var/ossec/bin/wazuh-logtest                                # вставьте строку из audit.log для проверки
sudo systemctl restart wazuh-manager
```

Если в `local_rules.xml` уже есть ваши правила, перенесите группу
`auditd_redos` в него целиком и проверьте, что идентификаторы 100100–100115
не заняты.

`sudo` (100103) специально оставлен на уровне 6: в домашней лаборатории он
запускается постоянно. Поднимите уровень, если на хосте sudo — редкость.
