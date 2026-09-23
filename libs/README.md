# libs/

Third-party managed + native DLLs shipped alongside `WS-engine.exe`.

## Files

- `Microsoft.Web.WebView2.Core.dll` — WebView2 managed API (MIT, from NuGet package `Microsoft.Web.WebView2` v1.0.2151.40)
- `Microsoft.Web.WebView2.WinForms.dll` — WinForms host control (MIT, same package)
- `WebView2Loader.dll` — Native loader (x64). Must sit next to `.exe` at runtime.

## Refreshing

Run the commands in Task 1 of `docs/superpowers/plans/2026-09-20-webview2-ui-migration.md` with a new version.

## License

MIT. Full text at <https://github.com/MicrosoftEdge/WebView2Feedback/blob/main/LICENSE>.
