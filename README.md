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
  отказе запускай с `sudo` (установщик сам попробует через `sudo`).
- В **macOS 13+ (Ventura / Sonoma / Sequoia)** действует защита App Management:
  если запись отклонена с `Operation not permitted`, откройте:
  *Системные настройки → Конфиденциальность и безопасность → Управление приложениями*
  и разрешите **Терминал**.
- **Корректная подпись кода:**
  Переподписывается **только сам пропатченный бинарник** (`language_server` / `agy`)
  ad-hoc подписью (`codesign --force --sign - --preserve-metadata=identifier`)
  без Hardened Runtime и restricted entitlements (которые на Apple Silicon
  приводят к SIGKILL со стороны AMFI), и с файла и бандла снимается атрибут карантина
  (`xattr -dr com.apple.quarantine`).
  Сам бандл `Antigravity.app` и вложенный `Electron Framework` намеренно **НЕ переподписываются**,
  так как `language_server` запускается как независимый дочерний процесс, а нарушение
  оригинальной подписи Google ломало бы Library Validation, Gatekeeper и macOS Keychain.
- Apple Silicon (M1/M2/M3/M4) и Intel поддерживаются.
- Запись бинаря идёт через временный файл рядом: бинарник подписывается
  **до** перемещения на место, что гарантирует получение свежего vnode в ядре.

### Если приложение ранее было повреждено старой версией патчера

Если на macOS ранее запускался старый скрипт, который переподписал весь бандл и
приложение крашится при запуске (`EXC_CRASH (SIGABRT)` / `different Team IDs`),
проще всего переустановить Antigravity:
1. Удалите `Antigravity.app` из `/Applications`.
2. Скачайте свежий DMG с официального сайта и перетащите его заново в `/Applications`.
3. Запустите обновлённый `install.sh`.

### Диагностика: «пропатчено, но всё равно ineligible / 400»

```sh
agy-unlock-analog doctor
```

Проверяет три слоя и подсказывает, где именно сломалось:

1. **клиент** — статус гейтов manager (auth/elig/rename);
2. **лог language_server** — ищет отказ региона от сервера Google:
   `FAILED_PRECONDITION (code 400): User location is not supported for the
   API use`. Это отказ на стороне Google по IP, клиентский патч тут
   бессилен.
3. **DNS / Сеть** — Google блокирует запросы к `cloudcode-pa.googleapis.com`
   по российскому IP. Для работы на macOS требуется активный VPN на всю систему,
   geo-DNS или прокси для language_server (`https_proxy`).

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
