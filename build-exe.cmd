@echo off
REM Build agy-unlock-analog.exe (needs Python 3.8+ and pip)
python -m pip install --quiet pyinstaller
python -m PyInstaller --noconfirm --onefile --console --name agy-unlock-analog --noupx patcher.py
echo.
echo Done: dist\agy-unlock-analog.exe
echo Upload it to GitHub Release manually, do not commit binaries.
