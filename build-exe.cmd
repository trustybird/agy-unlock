@echo off
REM Сборка agy-unlock-analog.exe (нужен Python 3.8+ и pip)
python -m pip install --quiet pyinstaller
python -m PyInstaller --noconfirm --onefile --console --name agy-unlock-analog --noupx patcher.py
echo.
echo Готово: dist\agy-unlock-analog.exe
echo Залей его в GitHub Release вручную, в git бинарь не коммитим.
