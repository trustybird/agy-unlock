# agy-unlock-analog

Снимает региональную блокировку Google Antigravity на Windows, macOS и Linux.

## Что делает

- Сам находит установленные приложения и патчит проверку региона:
  - Antigravity 2.0 — бинарь `language_server`;
  - Antigravity CLI — бинарь `agy`;
  - Antigravity IDE — файл `main.js` (плюс чистка кэшей);
  - Antigravity Desktop — `resources/app.asar` (см. ниже).
- Два механизма на бинарях, дополняют друг друга:
  - **байтовые гейты** — точечные правки переходов (`hasValidAuth`,
    eligibility-экран, CLI v1/v2, ARM64);
  - **rename-гейт** (подход [confeden/Antigravity](https://github.com/confeden/Antigravity),
    без копирования кода) — переименование protobuf-поля `ineligible` →
    `inexigible` одинаковой длины по всему файлу. Не зависит от раскладки
    кода и архитектуры, поэтому выручает на сборках, где байтовые гейты
    не совпали. Если байтовые гейты не нашлись, а rename применился —
    разблокировка засчитывается.
- Desktop ≥ 2.4 (модульный шелл, auth переехал в language_server):
  определяется автоматически — JS-патч не применяется, достаточно патча
  бинарей.
- `app.asar` поддерживается: `dist/main.js` читается прямо из архива;
  старая архитектура распаковывается (`app.asar` → `app.asar.bak`,
  Electron предпочитает каталог `resources/app`), откат возвращает архив.
- Перед изменением делает бэкап `<файл>.agybak`, откат — одной командой.
- Если файл занят запущенным приложением — установщик сам останавливает
  мешающие процессы (Antigravity.exe, language_server*, с выводом PID)
  и не считает занятый `app.asar` «отсутствующим main.js».
- Байтовые гейты знают обе раскладки eligibility (`2.21` и сжатую `2.29`).
- Умеет переживать обновления:
  - `daemon` — фоновый автопатч после обновлений;
  - `learn` — сам находит гейты заново, если новая сборка не совпала
    со встроенными сигнатурами;
  - `sigs` — импорт/экспорт паков сигнатур.
- `doctor` — диагностика «пропатчено, но ineligible»: состояние патча,
  ошибки региона из лога language_server и какие домены Google уходят
  напрямую вместо geo-DNS.
- Только стандартная библиотека Python, без телеметрии.

Важно: клиентский патч недостаточен сам по себе — Google проверяет регион
ещё и на стороне сети, поэтому дополнительно нужен DNS с подменой геолокации.
Без него доступ всё равно будет отклонён.

## Установка и патчинг одной командой

Нужен Python 3.8+. Перед установкой закрой Antigravity.

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/trustybird/agy-unlock/main/install.ps1 | iex
```

Windows CMD:

```cmd
curl -fsSL https://raw.githubusercontent.com/trustybird/agy-unlock/main/install.cmd -o install.cmd && install.cmd && del install.cmd
```

Linux / macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/trustybird/agy-unlock/main/install.sh | bash
```

Скрипт сам найдёт приложения, сделает бэкапы и пропатчит. Больше ничего
нажимать не нужно.

## macOS: особенности

- Нужен Python 3.8+ (в системе его нет — ставь с python.org).
- Запись в `/Applications` требует прав: закрой Antigravity и при
  отказе запускай с `sudo` (скрипт сам подскажет).
- После патча переподписывается весь код в bundle ad-hoc — каждый вложенный
  элемент отдельно (framework'и, helper'ы, бинари; от самых глубоких),
  с сохранением entitlements, hardened runtime и флагов — затем сам bundle.
  `codesign --deep` не используется: он пропускает ещё валидно подписанный
  родной (Google) код, остаётся смесь Team ID, и library validation убивает
  приложение при запуске. Подпись проверяется (`codesign --verify`);
  если проверка не прошла — патч считается неуспешным, а не «готово».
- Apple Silicon и Intel поддерживаются (сигнатуры под каждую архитектуру).
- Запись бинаря идёт через временный файл рядом и `rename` поверх, а не
  перезаписью по месту. На macOS это обязательно: у перезаписанного на месте
  Mach-O остаётся старый кэш подписи ядра, и процесс умирает на старте с
  «Code Signature Invalid», пока файл не переподписан; кроме того, работающий
  бинарь при перезаписи своих страниц падает с SIGBUS. Права (бит
  исполнения) переносятся с оригинала.

### Если словил SIGKILL или «different Team IDs»

Два симптома битой подписи:

- `Language server exited unexpectedly (signal=SIGKILL)` — пропатченный
  бинарь остался с недействительной подписью;
- краш приложения сразу при запуске (`EXC_CRASH (SIGABRT)`, в отчёте
  DYLD: `... (non-platform) have different Team IDs`) — главный exe уже
  ad-hoc, а часть вложенного кода (Electron Framework и т.п.) осталась
  с родной подписью; library validation не даёт грузить чужой Team ID.

Починка без повторного патча (закрой Antigravity), основной способ:

```sh
agy-unlock-analog sign
```

Если патчера рядом нет, вручную (после `sudo`):

```sh
sudo xattr -dr com.apple.quarantine /Applications/Antigravity.app
cd /Applications/Antigravity.app
sudo find Contents -depth \( -name '*.framework' -o -name '*.app' \
  -o -name '*.xpc' -o -name '*.appex' -o -name '*.bundle' \) \
  -exec codesign --force --sign - {} +
sudo find Contents -type f \( -name '*.dylib' -o -name '*.node' \) \
  -exec codesign --force --sign - {} +
sudo codesign --force --sign - Contents/Resources/bin/language_server
sudo codesign --force --sign - /Applications/Antigravity.app
sudo codesign --verify --deep --strict /Applications/Antigravity.app
```

Важно: `codesign --force --deep --sign -` здесь не поможет — он не
трогает ещё валидно подписанный вложенный код, и смесь Team ID остаётся.

### Диагностика: «пропатчено, но всё равно ineligible»

```sh
agy-unlock-analog doctor
```

Проверяет три слоя и подсказывает, где именно сломалось:

1. **клиент** — статус гейтов manager (auth/elig/rename);
2. **лог language_server** — ищет отказ региона от сервера Google:
   `FAILED_PRECONDITION (code 400): User location is not supported for the
   API use` (встречается и как `LOCATION_NOT_ELIGIBLE`, и как «Detected
   location: XX»). Это отказ на стороне Google, клиентский патч тут
   бессилен. Логи ищутся во всех продуктах сразу — Desktop
   (`logs/language_server.log`), IDE (`logs/<сессия>/ls-main.log`) и CLI
   (`~/.gemini/*/log/cli-*.log`), потому что у каждого свой путь;
3. **DNS-покрытие** — какие домены Google резолвятся через geo-DNS,
   а какие уходят напрямую. Типичный случай: API-домены покрыты, но
   `oauth2.googleapis.com` и `accounts.google.com` — нет, тогда Google
   видит реальный регион в токенах и входе. Лечение: попросить
   провайдера geo-DNS покрыть эти домены или включить VPN на всю
   систему (language_server понимает и `https_proxy`).

### Если на macOS «не срабатывает»

Частые причины, по порядку проверки:

1. **Приложение не перезапущено.** Патч пишется в файл, но уже запущенный
   `language_server` продолжает работать со старым кодом. Установщик
   останавливает бэкенд сам (`language_server`), но если Antigravity запускать
   заново вручную — закрой его полностью и открой заново.
2. **На Apple Silicon работает только rename-гейт.** Байтовые гейты
   написаны под x86-64 и на arm64-бинаре не совпадут никогда. Архитектура
   видна в `agy-unlock-analog status` (`arch: arm64`). Если rename-гейт не
   применился — сборка новая, помогает `agy-unlock-analog learn manager`.
3. **Бит подписи.** Если приложение падает на старте — `agy-unlock-analog sign`
   (раздел выше).
4. **Регион на стороне сети.** Клиентский патч снимает проверку в клиенте,
   но Google отказывает и по сети — нужен geo-DNS или VPN на всю систему.
   Показывает `doctor`.

Проверить состояние одной командой:

```sh
agy-unlock-analog status
agy-unlock-analog doctor
```

## Готовый exe (без Python)

Последняя сборка: https://github.com/trustybird/agy-unlock/releases —
файл `agy-unlock_v1.0.exe`. Скачай и запусти, меню всё покажет.
