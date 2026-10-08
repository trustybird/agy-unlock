# agy-unlock-analog

Снимает региональную блокировку Google Antigravity на Windows, macOS и Linux.

## Что делает

- Сам находит установленные приложения и патчит проверку региона:
  - Antigravity 2.0 — бинарь `language_server`;
  - Antigravity CLI — бинарь `agy`;
  - Antigravity IDE — файл `main.js` (плюс чистка кэшей).
- Перед изменением делает бэкап `<файл>.agybak`, откат — одной командой.
- Если файл занят запущенным приложением — честно просит его закрыть.
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

## Готовый exe (без Python)

Последняя сборка: https://github.com/trustybird/agy-unlock/releases —
файл `agy-unlock_v1.0.exe`. Скачай и запусти, меню всё покажет.
