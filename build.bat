@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d C:\Users\IT\AdminChecker
rc /nologo AdminChecker.rc
cl /EHsc /utf-8 /DUNICODE /D_UNICODE AdminChecker.cpp AdminChecker.res /link user32.lib gdi32.lib advapi32.lib shell32.lib netapi32.lib ole32.lib comctl32.lib /SUBSYSTEM:WINDOWS /OUT:AdminChecker.exe
