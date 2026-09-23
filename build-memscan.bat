@echo off
set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" ( echo csc.exe not found & exit /b 1 )
"%CSC%" /nologo /target:exe /platform:x64 ^
    /out:"%~dp0memscan.exe" ^
    /reference:System.dll ^
    "%~dp0src\MemScan.cs"
if errorlevel 1 ( echo Build failed. & exit /b 1 )
echo Built: %~dp0memscan.exe
