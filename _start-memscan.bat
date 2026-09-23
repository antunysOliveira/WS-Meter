@echo off
REM Runs memscan.exe in a loop, updating ws-engine.mem-players.json every 2s.
REM Requires admin (Warspear runs elevated). Keep this window open while playing.
REM Class detection is accumulative — once a player's class is scanned, it persists.
title WS-engine memory scanner
:loop
"%~dp0memscan.exe"
timeout /t 2 /nobreak >nul
goto loop
