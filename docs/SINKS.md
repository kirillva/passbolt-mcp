# Sinks: доставка секретов и выполнение заданий

Sink — единственный путь, которым пароль покидает Passbolt. Пароль передаётся
только по stdin процесса, никогда не попадает в argv, stdout/stderr, журнал или
ответ MCP. Цель доставки (host, port, path/database) вычисляется сервером из
URI записи Passbolt; агент не может её переопределить.

## Слои

Код синков разделён на четыре слоя, чтобы политика не смешивалась с исполнением:

| Слой | Файлы | Отвечает |
|---|---|---|
| envelope | `passbolt_sinkkit/envelope.py` | конверт, target из URI записи, лимиты |
| guards | `guards/web.py`, `guards/sql.py`, `guards/ssh.py` | что разрешено: вкладка/шаги, read-only SQL, профили и каталоги |
| executors | `executors/web.py`, `executors/pg.py`, `executors/psql.py`, `executors/ssh.py` | CDP, psql, paramiko — только исполнение |
| cli/results | `passbolt_sinkkit/cli.py`, `results.py`, `errors.py` | композиция, единый JSON-результат и коды выхода |

Точки входа (`login_fill.py`, `pg_query.py`, `ssh_ops.py`) — по 10 строк. Guards возвращают
план, executors его выполняют; ни один executor не решает, можно ли действие. Пакет пинится
целиком через `bundle_sha256`, entrypoint — через `executable_sha256`.

## Модель

```
passbolt_search(query)                  # метаданные
passbolt_select(query)                  # selection_id + URI записи
passbolt_job.py ...                     # опционально: job_ref для pg/ssh
passbolt_use_secret(selection_id, sink_ref, job_ref?)
   -> target из URI записи (явный порт или default_port синка)
   -> envelope {resource_id, username, password, target, job?, job_sha256?}
   -> sink выполняет действие и пишет state/results/<sink>-last.json (0600)
   -> MCP возвращает только {"delivered_to_sink": true}
```

Политика (`policies.<binding>` в `sinks.json`) ограничивает, какие ресурсы и
какие `sink_refs` доступны принципалу. Доменных проверок и подтверждений по
несовпадению target больше нет: второго target не существует.

## URI записи → параметры подключения

Схема говорит, каким протоколом говорить с адресом; креды, query и fragment в URI
запрещены всегда. Набор допустимых схем задаётся у синка (`uri_schemes`), поэтому одна
запись не может «переехать» на чужой протокол.

| sink | схемы | порт по умолчанию | путь |
|---|---|---|---|
| `login_fill` | `https`, `http`* | 443 / 80 | префикс пути для `web-profiles` |
| `https_probe` | `https` | 443 | проверяемый endpoint |
| `pg_ro`, `pg_exec` | `postgresql`, `postgres` | 5432 | `/имя_базы`, иначе `default_database` |
| `ssh_ops`, `ssh_adhoc` | `ssh` | 22 | пусто |

\* `http` попадает в `uri_schemes` web-синка только при `PASSBOLT_ALLOW_INSECURE_HTTP=1`
или если оператор вписал его явно.

Явный порт в URI важнее схемы. «Голый» адрес `host[:port][/db]` принимается, если у синка
включён `"allow_bare_host": true` — так в vault уже лежат некоторые хосты, и тогда порт
берётся из `default_port` синка (`dev-ws-v-07:443` → порт 443, база `postgres`). Схема вне
списка синка → `provider_configuration_invalid` с подсказкой, какие схемы допустимы.

```
postgresql://db.example:5432/app     ssh://bastion
dev-ws-v-07:443                      https://demo.it-serv.ru/armnext/demo_kavkaz
```

Логин по-прежнему уходит только туда, что записано в записи: `target_url` вызывающего на
адрес не влияет.

### pg_ro: строки и типы

Запрос оборачивается в `SELECT row_to_json(...) … LIMIT max_rows+1`, поэтому значения
сохраняют типы PostgreSQL (number/bool/null/string), а одна строка — один JSON-объект.
`columns` берутся из первой строки, при нуле строк — дешёвый `LIMIT 0` ради заголовка.
Ответ: `status, host, port, database, db_user, sql_sha256, columns, rows, row_count,
truncated, psql_version, format: "json-rows"`; предел — `max_rows` или 1 МиБ вывода.

Пароль не попадает ни в argv, ни в окружение: sink пишет временный `PGPASSFILE` (0600) в
приватный каталог и удаляет его после вызова, а сервер работает в read-only сессии
(`PGOPTIONS=…default_transaction_read_only=on`). `sslmode` берётся из конфига синка, по
умолчанию `require` — шифрование без проверки сертификата; `verify-full` c
`--pg-sslrootcert` включается явно. `pg_exec` (`pg_check.py`) — диагностика: фиксированные
read-only запросы, отчёт в `results/pg_exec-last.json` (0600) и одна JSON-строка в stdout.

### custom:// — адрес в заметке

Если запись не должна нести адрес в URI, URI пишется как `custom://<метка>`, а параметры
подключения — в заметке (description) записи, по одному `key = value` на строку:

```
# стенд заказчика
scheme = postgresql
host = dev-ws-v-02
port = 6543
database = app
```

- допустимые ключи: `scheme`, `host`, `port`, `database`, `path`; `#` — комментарий, пустые
  строки игнорируются, повтор ключа — ошибка;
- `scheme` обязателен и должен входить в `uri_schemes` синка; `host` обязателен; `port`,
  `database`, `path` — как в обычном URI, дефолты берутся из конфига синка;
- заметка ≤ 8 КБ, значение ≤ 256 символов; `username`/`password`/`token` в заметке
  запрещены — креды остаются в vault, иначе заметка стала бы вторым хранилищем паролей;
- заметку читает **сервер** при `use_secret` и передаёт синку уже готовый `target`
  (`"source": "note"`); в аудит уходит `custom_note`, сама заметка в синк не попадает.

Метка после `custom://` — только для читаемости: адрес всегда берётся из заметки.

### android_fill — вход в Android-приложение

URI записи: `android://<package>` (достаточно пакета: `android://ru.itserv.skr` и
`android://ru.itserv.skr/` — одно и то же); `android://<package>/<Activity>` сужает профиль, если
в приложении несколько экранов входа. Порт не используется (в target попадает 5037 — порт adb). Sink подключается к устройству через
uiautomator2 (`--device <serial>`, иначе `ANDROID_SERIAL`, иначе единственное подключённое) и
работает только с приложением **на переднем плане**: если открыто другое — `no_target`,
приложение нужно открыть заранее (агент это делает через playwright/uiautomator2 MCP).

Профиль `android-profiles.json` (0600) описывает шаги:

```json
{"profiles": {"ru.itserv.skr": {
  "match": {"package": "ru.itserv.skr"},
  "steps": [
    {"action": "fill",  "selector": {"resource_id": "ru.itserv.skr:id/security_login"}, "value_ref": "username"},
    {"action": "fill",  "selector": {"resource_id": "ru.itserv.skr:id/security_pass"},  "value_ref": "password"},
    {"action": "click", "selector": {"resource_id": "ru.itserv.skr:id/security_ok"}}
  ],
  "verify": {"absent": {"resource_id": "ru.itserv.skr:id/security_pass"}, "timeout_ms": 15000}
}}}
```

Селектор — ровно один из `text`, `resource_id`, `class_name`, `description`, `xpath`
(xpath только абсолютный). Действия: `fill`, `click`, `press` (enter/back/home/delete/search),
`wait`. `verify`: `present` или `absent` + `timeout_ms`; без него успех — исчезло поле пароля.
Без профиля работает эвристика: два EditText (пароль с `password=true`) и кнопка «Ок/Войти/Login».

Статусы: `logged_in` (поля логина исчезли — единственный признак успеха), `rejected` (поля
логина остались на экране после `timeout_ms`; текст ошибки приложения, если он виден, попадает
в `detail`, но решение от него не зависит), `mfa_required`, `timeout`, `no_target`,
`form_error`. Пароль вводится
через accessibility (`set_text`), а не `adb shell input text`, поэтому не попадает в командную
строку процессов на хосте.

## Конфиг `sinks.json`

```json
{
  "version": 3,
  "sinks": {
    "login_fill": {
      "kind": "secure_fill",
      "command": ["/abs/path/secrets/sinks/login_fill.py",
                  "--web-profiles", "/abs/path/secrets/sinks/web-profiles.json"],
      "executable_sha256": "<64 hex>",
      "bundle_sha256": "<64 hex>",
      "timeout_seconds": 90,
      "default_port": 443
    },
    "pg_ro": {
      "kind": "secure_fill",
      "command": ["/abs/path/secrets/sinks/pg_query.py", "--result-dir", "/abs/.../results"],
      "executable_sha256": "<64 hex>",
      "bundle_sha256": "<64 hex>",
      "timeout_seconds": 60,
      "default_port": 5432,
      "default_database": "postgres",
      "sslmode": "verify-full",
      "sslrootcert": "/abs/path/secrets/sinks/pg-ca.crt",
      "requires_job": true,
      "require_approval": "never",
      "job_dir": "/abs/path/state/jobs",
      "max_job_bytes": 65536
    },
    "ssh_ops": {
      "kind": "secure_fill",
      "command": ["/abs/path/secrets/sinks/ssh_ops.py", "--profiles", ".../ssh-profiles.json",
                  "--known-hosts", ".../known_hosts", "--upload-root", "/abs/path/state/upload",
                  "--result-dir", ".../results"],
      "executable_sha256": "<64 hex>",
      "bundle_sha256": "<64 hex>",
      "timeout_seconds": 120,
      "default_port": 22,
      "requires_job": true,
      "require_approval": "never",
      "job_dir": "/abs/path/state/jobs",
      "max_job_bytes": 65536
    },
    "ssh_adhoc": { "...": "то же + --adhoc, require_approval: always" }
  },
  "policies": {
    "default": {
      "resource_scope": "all",
      "sink_refs": ["login_fill", "pg_ro", "ssh_ops"]
    }
  }
}
```

- `sslmode`/`sslrootcert` > `PGSSLMODE`/`PGSSLROOTCERT` для psql. По умолчанию
  `require` — шифрование без проверки сертификата; `verify-full` + CA включается явно.
- `require_approval`: `never` (по умолчанию) или `always` (рекомендуется для
  `ssh_adhoc`). Одобрение выдаётся вне MCP через `passbolt-approval`.
- `requires_job` + `job_dir`: sink принимает только задание из приватного
  каталога (0700), файлы 0600, не symlink, размер ≤ `max_job_bytes`.
- `uri_schemes`: какие схемы принимает этот синк (`https`, `http`, `postgresql`,
  `postgres`, `ssh`). Без ключа — `https` (+`http` при `PASSBOLT_ALLOW_INSECURE_HTTP=1`).
- `allow_bare_host`: `true` разрешает записи вида `host[:port][/db]` без схемы; порт
  тогда берётся из `default_port`.
- `domain_policy` в политике: `any` (по умолчанию) — vault сам является списком
  разрешённых адресов, запись и обновление URI не ограничены; `allowlist` — старое
  поведение со строгим HTTPS-origin. При `any` непустой `domain_hosts` остаётся
  подсказкой: выдача на хост вне списка пишет в аудит `unlisted_host`, но не блокирует;
  `http`-цель помечается `plain_http`.

## Веб-профили (данные, не код)

Логин на сайт — один sink на все сайты. Специфика формы описывается в
`web-profiles.json` (0600), выбор — по host и префиксу пути; без профиля работает
эвристика (видимое поле пароля + login + submit).

```json
{"profiles": {
  "default": {"mode": "heuristic"},
  "portal": {
    "match": {"host": "portal.example", "path_prefix": "/login"},
    "steps": [
      {"action": "fill",  "selector": "input[name=username]", "value_ref": "username"},
      {"action": "fill",  "selector": "input[type=password]", "value_ref": "password"},
      {"action": "click", "selector": "button[type=submit]"},
      {"action": "expect","url_not": "*/login*", "timeout_ms": 10000}
    ]
  }
}}
```

Разрешены только `fill`, `click`, `press` (Enter/Tab/Escape), `wait`, `expect`, `otp`;
селекторы — CSS, без `javascript:`; `value_ref` — `username`/`password`/`totp`.
Двухшаговый логин, iframe-подобные сценарии и OTP описываются шагами, а не новым
синком. Для `otp` нужен TOTP из записи; иначе sink вернёт `6`, и продолжает
playwright MCP.

Необязательный блок `verify` проверяет, **кем** вошли, не раскрывая секрет:
после шагов читается ключ `sessionStorage` и сравнивается с логином из записи.

```json
"verify": {"session_storage": "username", "equals_ref": "username"}
```

Несовпадение — статус `account_mismatch` (код 8), а не «успешный вход».

### Исход логина: logged_in, rejected, unconfirmed

После шагов sink не объявляет успех автоматически, а подтверждает его:

- `logged_in` — поле пароля исчезло или адрес страницы изменился (и, если задан
  `verify`, вошёл ожидаемый аккаунт);
- `rejected` — сайт сам отказал: alert либо видимый диалог с текстом отказа
  («Неверный логин или пароль», «invalid credentials», «учётная запись заблокирована»
  и т. п.). Текст приходит в `detail` — это ответ сервера, а не догадка синка;
- `unconfirmed` — форма логина всё ещё на экране, подтверждения нет. Это тоже не
  успех: угадывать нельзя, надо смотреть страницу;
- `mfa_required`, `timeout`, `no_target`, `form_error` — как раньше.

Ожидание подтверждения (`settle_ms`, 1000–30000, по умолчанию 6000) задаётся в
профиле — для медленных сайтов, которые перерисовываются дольше:

```json
"settle_ms": 15000
```

Сайт, который ходит в собственный API по `http://`, надо открывать по `http://` и
в браузере: страница, молча повышенная до HTTPS, отправит такой вызов через схему,
и бэкенд ответит 401 — приложение покажет это как «неверный логин».

### Несколько вкладок на один сайт

По умолчанию sink требует единственную вкладку на хосте записи (порты 80 и 443 одного
хоста считаются одним сайтом — браузер повышает HTTP сам). Чтобы держать
несколько аккаунтов одного сайта одновременно, каждая вкладка открывается с
несекретным маркером в query, а вызов передаёт `page`:

```
https://app.example.internal/arm/dev/?pb=u-disp#/auth   →   use_secret(..., page="u-disp")
```

- маркер выбирает только вкладку; host/port/path по-прежнему берутся из URI записи;
- формат `[a-z0-9._-]`, до 32 символов; читается из параметра `pb` URL вкладки;
- маркер входит в approval digest и не может быть подменён после подтверждения;
- блокировка синка теперь per-marker (`.browser-<page>.lock`), разные аккаунты
  не сериализуются;
- при неоднозначности sink печатает `no_target` и число вкладок на origin, а не
  угадывает.

Сессия сайта должна быть по вкладкам (`sessionStorage`/изолированный контекст).
Если сайт хранит токен в `localStorage` или cookie, вкладки одного профиля
поделят сессию — тогда нужны изолированные контексты или отдельные браузеры.

## Задания (`job_ref`)

Создаются локально CLI (0600, одноразовые; после выполнения sink переносит файл
в `job_dir/archive/`). Сервер хеширует файл и включает `job_sha256` в approval
digest; подмена между подготовкой и запуском отклоняется.

### Postgres

```json
{"version": 1, "sink": "pg_ro", "sql": "select now(), current_user",
 "max_rows": 200, "statement_timeout_ms": 15000}
```

```sh
uv run python scripts/passbolt_job.py pg --sql-file query.sql
```

Исполнение: `options=-c default_transaction_read_only=on`, `BEGIN TRANSACTION
READ ONLY`, `SET LOCAL statement_timeout`, ровно один statement, лимит строк и
1 MiB результата. SQL проверяется консервативным allowlist: только
`SELECT/WITH/UNION/TABLE/VALUES`; запрещены DML/DDL, `SET`, `COPY`, `DO`, `CALL`,
`EXPLAIN ANALYZE`, multi-statement и опасные функции (`pg_read_file`, `dblink`,
`lo_export`, `nextval`, ...). Если в окружении есть `sqlglot`, он используется
как дополнительный парсер.

Важно: read-only транзакция не защищает от всех побочных эффектов, если логин из
Passbolt — суперпользователь. Основная защита — парсер + гранты; при возможности
заведите отдельную роль `passbolt_ro` с `default_transaction_read_only=on` и
только `SELECT`.

### SSH

```json
{"version": 1, "sink": "ssh_ops", "profile": "deploy",
 "commands": [["systemctl", "status", "nginx"]],
 "uploads": [{"local": "app.tgz", "remote": "/opt/deploy/app.tgz"}],
 "allow_overwrite": false}
```

```sh
uv run python scripts/passbolt_job.py ssh --profile deploy \
  --command "systemctl status nginx" --upload app.tgz:/opt/deploy/app.tgz
```

`ssh-profiles.json` (0600):

```json
{"profiles": {"deploy": {"commands": [["systemctl", "status", "nginx"]],
                          "upload_dirs": ["/opt/deploy"], "max_bytes": 10485760,
                          "allow_overwrite": false, "allow_sudo": false}}}
```

- Команды — argv-массивы, без shell-метасимволов; в профильном режиме задание
  может выполнить только команду из `commands` профиля (точное совпадение).
- `--adhoc` разрешает произвольные argv, но сервер требует `require_approval:
  always`.
- Загрузки: только из `state/upload/` (0700), запрет `..`, symlink-выхода за
  пределы каталога, лимит `max_bytes`; загрузка идёт во временное имя и
  переименовывается атомарно, sha256 пишется в результат.
- Ключи хоста проверяются по `known_hosts` (`RejectPolicy`), парольный вход,
  `allow_agent=False`, `look_for_keys=False`.

## Развёртывание

```sh
uv run python scripts/install_sinks.py \
  --python login_fill=$PWD/.venv/bin/python \
  --python pg_ro=$PWD/secrets/sinks/.venv-pg/bin/python \
  --python ssh_ops=$PWD/secrets/sinks/.venv-ssh/bin/python \
  --python ssh_adhoc=$PWD/secrets/sinks/.venv-ssh/bin/python \
  --pg-sslmode verify-full --pg-sslrootcert $PWD/secrets/sinks/pg-ca.crt
```

Скрипт копирует entrypoints и пакет `passbolt_sinkkit/` в `secrets/sinks/` (0700),
переписывает shebang, создаёт `state/jobs|state/upload|results` (0700), пересчитывает
`executable_sha256`/`bundle_sha256` и атомарно обновляет `sinks.json` (0600). Политики он не
меняет: добавьте новые `sink_refs` в политику вручную. После изменения скрипта
повторный запуск обязателен — иначе сервер откажет по хешу.

Необязательный `secrets/sinks/web-profiles.json` (0600) добавляет селекторы для
конкретных сайтов; без него работает эвристика. Перед первым использованием
`ssh_ops` создайте `secrets/sinks/known_hosts`
(например, `ssh-keyscan host`) и `ssh-profiles.json` (0600). Для PG положите CA
рядом и укажите `--sslrootcert`.

## Результаты и коды выхода

Результаты: `secrets/sinks/results/<sink_ref>-last.json` (0600) — статус, host/port,
тайминги, для pg — колонки/строки, для ssh — код и вывод по каждой команде,
sha256 загрузок. Пароль туда не попадает.

Каждый sink дополнительно печатает в stdout **одну** JSON-строку с исходом
(`status`, `url`, `account`, `page`, `error`, `detail`). Сервер читает её и
возвращает вызывающему `passbolt_use_secret` вместе с `delivered_to_sink`, поэтому
`status`/`detail` видны агенту и при ошибке. Полные строки pg/ssh в stdout не
печатаются — только в файл результата.

Общие коды: `0` ok; `2` плохой конверт/job; `3` нет цели/соединения; `7`
policy/profile denied; `8` ошибка на стороне цели (включая `account_mismatch`);
`9` внутренняя ошибка. `login_fill`: дополнительно `4` форма не найдена, `5`
таймаут, `6` MFA/капча.

## Ограничения

- Секрет всё равно оказывается в памяти процесса-синка и в целевом сервисе.
- Sink пинится по sha256 только entrypoint; venv и интерпретатор не пинятся.
- Агент имеет shell на хосте и может читать результаты; ограничения sink-ов
  защищают от случайных действий и ограничивают поверхность, но не изолируют от
  самого агента.
