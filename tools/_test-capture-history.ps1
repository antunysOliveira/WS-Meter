# Smoke test: SanitizeFileName + SaveSidecar/LoadSidecar roundtrip.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
$probe = @'
using System;
using System.IO;
using WSEngine;

class TestCH {
    static int fail = 0;
    static void Check(string label, bool ok) {
        Console.WriteLine("  [" + (ok ? "OK  " : "FAIL") + "] " + label);
        if (!ok) fail++;
    }
    static int Main(string[] args) {
        // 1. Sanitize
        Check("basic", CaptureHistory.SanitizeFileName("hello world") == "hello world");
        Check("removes <>|:", CaptureHistory.SanitizeFileName("bad<>|:name") == "bad____name");
        Check("removes control chars", CaptureHistory.SanitizeFileName("xy") == "xy");
        Check("trim trailing dot/space", CaptureHistory.SanitizeFileName("name. ") == "name");
        Check("accents kept", CaptureHistory.SanitizeFileName("Teste Ação") == "Teste Ação");

        // 2. Roundtrip sidecar
        string tmp = Path.Combine(Path.GetTempPath(), "ws-t4-" + Guid.NewGuid() + ".pcapng");
        File.WriteAllBytes(tmp, new byte[]{0,0,0,0});
        CaptureHistory.SaveSidecar(tmp, "raid teste \"aspas\"", "Necromante \\ Brokeblade");
        var it = CaptureHistory.LoadSidecar(tmp);
        Check("sidecar name preserved", it.Name == "raid teste \"aspas\"");
        Check("sidecar note preserved", it.Note == "Necromante \\ Brokeblade");
        Check("sidecar file exists", File.Exists(tmp + ".meta.json"));

        // 3. RenameCaptureFile (no active capture)
        string err;
        string np = CaptureHistory.RenameCaptureFile(tmp, "renamed teste", out err);
        Check("rename returns non-null", np != null);
        if (np != null) {
            Check("new file exists", File.Exists(np));
            Check("new sidecar moved", File.Exists(np + ".meta.json"));
            Check("old file gone", !File.Exists(tmp));
            File.Delete(np); File.Delete(np + ".meta.json");
        }

        // 4. List with orphan sidecar
        string dir = Path.Combine(Path.GetTempPath(), "ws-t4-list-" + Guid.NewGuid());
        Directory.CreateDirectory(dir);
        try {
            string p1 = Path.Combine(dir, "a.pcapng");
            File.WriteAllBytes(p1, new byte[]{0});
            CaptureHistory.SaveSidecar(p1, "primeira", "");
            // orphan
            string p2 = Path.Combine(dir, "b.pcapng");
            CaptureHistory.SaveSidecar(p2, "deleted-but-metadata-exists", "");
            var list = CaptureHistory.List(dir);
            Check("list count = 2", list.Count == 2);
            bool foundOrphan = false;
            foreach (var e in list) if (!e.Available && e.Name == "deleted-but-metadata-exists") foundOrphan = true;
            Check("orphan sidecar detected", foundOrphan);
        } finally {
            try { Directory.Delete(dir, true); } catch { }
        }

        Console.WriteLine(fail == 0 ? "ALL OK" : ("FAILED: " + fail));
        return fail == 0 ? 0 : 1;
    }
}
'@
    New-Item -ItemType Directory -Force tools\_test-ch | Out-Null
    Set-Content -Path tools\_test-ch\Test.cs -Value $probe -Encoding UTF8
    $csc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    & $csc /nologo /out:tools\_test-ch\Test.exe tools\_test-ch\Test.cs `
        src\CaptureHistory.cs src\Reassembly.cs `
        /reference:System.Core.dll 2>&1
    if ($LASTEXITCODE -ne 0) { throw "compile failed" }
    & tools\_test-ch\Test.exe
    exit $LASTEXITCODE
} finally { Pop-Location }
