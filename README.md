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
- Если файл занят запущенным приложением — честно просит его закрыть
  (установщик сам ждёт закрытия до 2 минут и не считает занятый
  `app.asar` «отсутствующим main.js»).
- Байтовые гейты знают обе раскладки eligibility (`2.21` и сжатую `2.29`).
- Умеет переживать обновления:
  - `daemon` — фоновый автопатч после обновлений;
  - `learn` — сам находит гейты заново, если новая сборка не совпала
    со встроенными сигнатурами;
  - `sigs` — импорт/экспорт паков сигнатур.
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
- После патча бинарь переподписывается автоматически (`codesign -s -`,
  снимается карантин) — иначе macOS не даст приложению запуститься.
- Apple Silicon и Intel поддерживаются (сигнатуры под каждую архитектуру).

## Готовый exe (без Python)

Последняя сборка: https://github.com/trustybird/agy-unlock/releases —
файл `agy-unlock_v1.0.exe`. Скачай и запусти, меню всё покажет.
