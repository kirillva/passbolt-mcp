# Windows

Сервер и синки работают на Windows нативно, но часть проверок там устроена иначе: нет
`chmod`, нет `fcntl`, у `.py` нет исполняемого бита, консоль по умолчанию не UTF-8. Ниже — что
поставить и чем это компенсируется. В WSL2 всё работает как на Linux и этот файл не нужен.

## Что поставить

| Компонент | Зачем |
|---|---|
| Python 3.12–3.14 + [uv](https://docs.astral.sh/uv/) | сервер (`uvx`), установщик синков, `passbolt-approval` |
| [Gpg4win](https://www.gpg4win.org/) | `gpg.exe`/`gpgconf.exe` в `PATH` — расшифровка секретов и метаданных Passbolt |
| PostgreSQL client | `psql.exe` для синков `pg_ro`/`pg_exec` |
| Android platform-tools | `adb.exe` для `android_fill` (и venv с `uiautomator2`) |
| Google Chrome | общий headless-браузер с CDP для `login_fill` |
| OpenSSH Client (компонент Windows) или Git | `ssh-keyscan`/`ssh` для `known_hosts` и ssh-синков |

## Пути и venv

Виртуальные окружения на Windows лежат иначе — интерпретатор в `Scripts\python.exe`:

```powershell
uv venv "$env:USERPROFILE\.config\passbolt-mcp\secrets\sinks\.venv-ssh" --python 3.14
uv pip install --python "$env:USERPROFILE\.config\passbolt-mcp\secrets\sinks\.venv-ssh\Scripts\python.exe" paramiko invoke

uv venv "$env:USERPROFILE\.config\passbolt-mcp\secrets\sinks\.venv-android" --python 3.14
uv pip install --python "$env:USERPROFILE\.config\passbolt-mcp\secrets\sinks\.venv-android\Scripts\python.exe" uiautomator2
```

`install_sinks.py` сам ставит интерпретатор первым элементом команды синка и пишет
`"executable_index": 1` — именно этот файл (а не интерпретатор) пиннится по SHA-256. На POSIX
это работает так же, поэтому реестр один на обе платформы.

```powershell
uv run python scripts\install_sinks.py `
  --dest   "$env:USERPROFILE\.config\passbolt-mcp\secrets\sinks" `
  --config "$env:USERPROFILE\.config\passbolt-mcp\secrets\sinks.json" `
  --state  "$env:USERPROFILE\.config\passbolt-mcp\state" `
  --psql   "C:\Program Files\PostgreSQL\18\bin\psql.exe" `
  --android-adb "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" `
  --python "login_fill=<интерпретатор с websockets>" `
  --python "android_fill=...\.venv-android\Scripts\python.exe" `
  --python "ssh_ops=...\.venv-ssh\Scripts\python.exe" `
  --python "ssh_adhoc=...\.venv-ssh\Scripts\python.exe"
```

## Конфигурация

`mcp.local.json` и `passbolt.env` — обычный JSON/`KEY=VALUE`; в путях либо прямые слэши, либо
двойные обратные (`"C:\\Users\\..."`).

Рекомендуется один раз задать кодировку для сервера и любых ручных запусков:

```powershell
[Environment]::SetEnvironmentVariable("PYTHONUTF8", "1", "User")
```

Сервер и синки уже общаются по pipe в UTF-8 (включая `stdin`/`stdout` синка), но переменная
избавит от сюрпризов в логах и при отладке в консоли.

## Браузер для входа на сайты

`examples/windows/start-cdp-chrome.ps1` — аналог `start-cdp-chrome.sh`: тот же Chromium с
`--remote-debugging-port=9222`, тем же профилем (`%TEMP%\opencode\pw-cdp-profile`) и теми же
флагами (игнор сертификата и отключение авто-повышения HTTP→HTTPS). Запускать перед первым
`login_fill`; playwright MCP подключается к `http://127.0.0.1:9222`.

## Отличия в защите

| Linux | Windows |
|---|---|
| `chmod 0600` для секретов, state, профилей | права файлов — ACL профиля пользователя; проверки `0o077` не применяются |
| `fcntl.flock` для лока вкладки | `msvcrt.locking` (тот же per-marker lock) |
| `O_NOFOLLOW` при записи лога | флага нет — запись идёт без него |
| симлинки как атака на кастоди | провенанс файлов проверяется, но NTFS-симлинки требуют прав администратора |
| `ssh-keyscan` из OpenSSH | то же, если установлен клиент OpenSSH |

Практический вывод: держите `%USERPROFILE%\.config\passbolt-mcp` в профиле, к которому нет
доступа у других учётных записей машины, — это и есть «0600» на Windows.

## Что проверено тестами

- команда синка `[python, script, ...]` с `executable_index` (пиннится скрипт);
- режимные проверки профилей (`web-profiles.json`, `ssh-profiles.json`,
  `android-profiles.json`) отключаются вне POSIX;
- запись лога без `O_NOFOLLOW`;
- лок вкладки через `msvcrt`, если `fcntl` недоступен.
