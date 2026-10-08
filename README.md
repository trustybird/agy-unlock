# agy-unlock-analog

Снимает региональную блокировку Google Antigravity на Windows, macOS и Linux.

## Что делает

- Патчит проверку региона в трёх компонентах:
  - Antigravity 2.0 — бинарь `language_server` (два гейта);
  - Antigravity CLI — бинарь `agy`;
  - Antigravity IDE — файл `main.js` (замена флага региона на `true`, чистка кэшей).
- Перед изменением делает бэкап `<файл>.agybak`, откат — одной командой.
- Находит установленные приложения сам, либо принимает путь через `--path`.
- Умеет переживать обновления:
  - `daemon` — фоновый автопатч после обновлений;
  - `learn` — сам находит гейты заново, если новая сборка не совпала
    со встроенными сигнатурами;
  - `sigs` — импорт/экспорт паков сигнатур.
- Только стандартная библиотека Python, без телеметрии.

Важно: клиентский патч недостаточен сам по себе — Google проверяет регион
ещё и на стороне сети, поэтому дополнительно нужен DNS с подменой геолокации.
Без него доступ всё равно будет отклонён.

## Установка

Нужен Python 3.8+.

```powershell
.\install.ps1        # Windows PowerShell
install.cmd          # Windows CMD
```

```sh
sh install.sh        # Linux / macOS
```

## Использование

```sh
agy-unlock-analog status          # найти приложения и показать состояние патча
agy-unlock-analog unlock all      # пропатчить всё найденное
agy-unlock-analog unlock manager --path "D:\...\language_server.exe"
agy-unlock-analog unlock cli --path "...\agy.exe"
agy-unlock-analog unlock ide --path "...\main.js"
agy-unlock-analog restore all     # откатить из бэкапов
agy-unlock-analog daemon install  # фоновый автопатч (переустановка после обновлений)
agy-unlock-analog daemon status
agy-unlock-analog daemon uninstall
agy-unlock-analog learn manager          # переоткрыть гейты в новой сборке
agy-unlock-analog learn manager --apply  # + сразу применить
agy-unlock-analog version
```

`unlock --if-needed` пропускает уже пропатченное (для демона).
Протухший бэкап после обновления приложения ротируется в `.agybak.prev`.

## Файлы

- `patcher.py` — основной скрипт;
- `install.sh` / `install.ps1` / `install.cmd` — установщики;
- `README.md` — этот файл.
