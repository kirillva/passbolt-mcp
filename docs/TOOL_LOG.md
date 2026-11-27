# Локальный лог ошибок инструментов

Нужен, чтобы инструкции (гайды и скиллы) правились по фактическим отказам модели, а
не по догадкам. Пишется только при **ошибке** вызова инструмента, локально, одним
JSON-объектом на строку.

## Где и в каком виде

```
~/.config/passbolt-mcp/state/tool-errors.jsonl        # 0600, каталог 0700
~/.config/passbolt-mcp/state/tool-errors.jsonl.1      # ротация по 2 МБ, хранится 2 файла
~/.config/passbolt-mcp/state/tool-errors.jsonl.2
```

Поля строки:

| Поле | Что это |
|---|---|
| `ts` | время в UTC, ISO-8601 |
| `version` | версия сервера (`0.7.x`) |
| `tool` | имя инструмента, например `passbolt_use_secret` |
| `outcome` | `error`, `timeout`, `cancelled` |
| `code` | безопасный код конверта: `validation_failed`, `provider_configuration_invalid`, `provider_rate_limited`, … |
| `error` | класс исключения (`ProviderConfigurationError`, `ValueError`, …) |
| `hint` | наша собственная подсказка из конверта — если она есть, её и надо донести до инструкций |
| `actor`, `execution_id`, `duration_ms` | принципал, id исполнения (сходится с таблицей `audit` в `state/passbolt.sqlite`), длительность |
| `arguments` | форма аргументов: безопасные строки как есть (`target_url` — схема и host:port, `query`, `sink_ref`, `page`, `resource_id`, `limit`…), остальное — `{"chars": N}`, `{"kind": "object", "fields": N}` |

Чего в логе **не бывает**: пароля, `secret_source`, `note`, `fields`, полного URI с
путём/query, текста ошибки провайдера или синка. Строка обрезается до 2 КБ так, чтобы
остаться валидным JSON; запись, которая не удалась (нет диска, нет прав, symlink),
молча пропускается — лог не имеет права ломать вызов инструмента.

## Настройки

| Переменная | Смысл |
|---|---|
| `PASSBOLT_TOOL_LOG=0` (или `off`, `false`, `no`, `none`) | выключить лог |
| `PASSBOLT_TOOL_LOG_PATH=/home/<user>/.../errors.jsonl` | свой путь; принимается только внутри `$HOME`, иначе пишем в каталог состояния |

## Собрать отчёт

```sh
uv run python scripts/tool_log_report.py            # по умолчанию рядом с state-базой
uv run python scripts/tool_log_report.py --top 8 --samples 5
```

Отчёт группирует: по `tool`+`code`, по встречавшимся `hint`, отдельно — аргументы у
`validation_failed` / `provider_configuration_invalid` / `provider_disabled` (это
кандидаты в правку гайдов), и последние отказы. Секретов в нём нет по построению,
поэтому его можно приложить к задаче или обсуждению.

## Лог изменений данных

Пишется рядом с базой: `state/data-changes.jsonl` (0600, ротация 2 МБ, два файла). Одна
строка — одно **применённое** изменение:

| Поле | Что это |
|---|---|
| `ts`, `version`, `tool`, `operation`, `outcome`, `approval`, `actor`, `execution_id`, `duration_ms` | как в логе ошибок; `approval` — `operator` (подтверждал человек) или `auto` (стоячая политика) |
| `changes` | что просили изменить: `name`/`uri`/`username`/`permission`/`folder`/`resource_id` как есть, `fields.*` — по полям; `description` — только длина, `secret_source` — только `kind` |
| `result` | `resource_id`/`folder_id`/`created`/`updated`/`shared`/`idempotent` |
| `error` | класс ошибки, если изменение не применилось |

Пароля, `secret_source.value`/`ref` и текста заметки в логе нет по построению.

Собрать: `uv run python scripts/tool_log_report.py --changes`.

## Авто-подтверждение изменений

По умолчанию каждый write ждёт `passbolt-approval` (10 минут, одноразово, digest привязан к
аргументам). Оператор может включить стоячее подтверждение:

```
PASSBOLT_WRITE_APPROVAL=auto
```

Тогда изменение применяется за один вызов: сервер создаёт тот же digest-привязанный
`ApprovalRecord`, сразу принимает его как `acceptance_type=standing` c
`acceptance_origin=operator_config`, одноразово потребляет и пишет в лог `approval: "auto"`.
Модель этот режим включить не может — только окружение/конфиг оператора; `operator` остаётся
дефолтом, поэтому на чужой инсталляции поведение не меняется.

## Как этим править инструкции

1. `validation_failed` с одним и тем же `arguments` → в гайде не хватает примера
   формата (`target_url` — это host или URL, а не произвольная строка; `page` — маркер
   `[a-z0-9._-]`, и т. п.).
2. `provider_configuration_invalid` → `hint` уже содержит, что именно поправить
   (HTTPS vs plain-HTTP опт-ин, домен вне `domain_hosts`, отсутствующий `sink_ref`).
   Такие случаи стоит вынести в `resources/guide/errors.md` и в скиллы-зеркала.
3. `provider_disabled` / `permission denied` → чаще всего модель зовёт инструмент без
   нужного scope или до включения `PASSBOLT_USE_ENABLED`; это правило для `security.md`.
4. `provider_rate_limited` → vault ответил `429` (соблюдайте `Retry-After`) или, если
   оператор включил `PASSBOLT_RATE_LIMIT`, сработало его локальное окно; смотреть
   `retry_after_seconds` в ответе.

После правки гайдов не забыть зеркала в `skills/*/references/*.md` — их сверяет
`scripts/token_budget.py`.
