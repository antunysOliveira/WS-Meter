@echo off
REM Build WS-engine.exe using .NET Framework csc (ships with Windows).
setlocal
set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
    echo csc.exe not found at %CSC%
    exit /b 1
)
"%CSC%" /nologo /target:winexe /platform:anycpu ^
    /out:"%~dp0WS-engine.exe" ^
    /win32icon:"%~dp0assets\ws-engine.ico" ^
    /win32manifest:"%~dp0src\app.manifest" ^
    /reference:System.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll ^
    /reference:"%~dp0libs\Microsoft.Web.WebView2.Core.dll" ^
    /reference:"%~dp0libs\Microsoft.Web.WebView2.WinForms.dll" ^
    /reference:"%~dp0libs\System.Data.SQLite.dll" ^
    /reference:System.Data.dll ^
    "%~dp0src\WebViewHost.cs" ^
    "%~dp0src\Capture.cs" ^
    "%~dp0src\Reassembly.cs" ^
    "%~dp0src\TlvSplit.cs" ^
    "%~dp0src\TlvScan.cs" ^
    "%~dp0src\ContainerStats.cs" ^
    "%~dp0src\FindValue.cs" ^
    "%~dp0src\Opcodes.cs" ^
    "%~dp0src\GameData.cs" ^
    "%~dp0src\PlayerResolver.cs" ^
    "%~dp0src\EntityState.cs" ^
    "%~dp0src\Replay.cs" ^
    "%~dp0src\Inventory.cs" ^
    "%~dp0src\Entropy.cs" ^
    "%~dp0src\Framing2.cs" ^
    "%~dp0src\Envelope.cs" ^
    "%~dp0src\Tlv.cs" ^
    "%~dp0src\Lz4.cs" ^
    "%~dp0src\TlvDamageDecoderV3.cs" ^
    "%~dp0src\Tag99HealDecoder.cs" ^
    "%~dp0src\Tag429BuffDecoder.cs" ^
    "%~dp0src\Tag26EntitySpawnDecoder.cs" ^
    "%~dp0src\SummonOwnerMap.cs" ^
    "%~dp0src\Tag207Decoder.cs" ^
    "%~dp0src\Tag11PlayerDetailDecoder.cs" ^
    "%~dp0src\Tag10PlayerClassDecoder.cs" ^
    "%~dp0src\Tag554Decoder.cs" ^
    "%~dp0src\Tag551Decoder.cs" ^
    "%~dp0src\Database.cs" ^
    "%~dp0src\ProcessMonitor.cs" ^
    "%~dp0src\ServerDiscovery.cs" ^
    "%~dp0src\Summary.cs" ^
    "%~dp0src\ProbeIds.cs" ^
    "%~dp0src\RosterAnalyze.cs" ^
    "%~dp0src\C2sCensus.cs" ^
    "%~dp0src\FindClassNearName.cs" ^
    "%~dp0src\ProtocolCensus.cs" ^
    "%~dp0src\CommunitySync.cs" ^
    "%~dp0src\WS-engine.cs"
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
copy /Y "%~dp0libs\WebView2Loader.dll" "%~dp0WebView2Loader.dll" > NUL
copy /Y "%~dp0libs\Microsoft.Web.WebView2.Core.dll" "%~dp0Microsoft.Web.WebView2.Core.dll" > NUL
copy /Y "%~dp0libs\Microsoft.Web.WebView2.WinForms.dll" "%~dp0Microsoft.Web.WebView2.WinForms.dll" > NUL
copy /Y "%~dp0libs\System.Data.SQLite.dll" "%~dp0System.Data.SQLite.dll" > NUL
copy /Y "%~dp0libs\SQLite.Interop.dll" "%~dp0SQLite.Interop.dll" > NUL
echo Built: %~dp0WS-engine.exe
endlocal
