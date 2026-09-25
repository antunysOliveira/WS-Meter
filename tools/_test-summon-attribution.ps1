# Regression: SummonOwnerMap deve montar entradas para 100% das invocações
# (tid ∈ SummonRegistry) com owner válido, em capturas pré e pós update
# Warspear v13.4.4.
#
# Testado em:
#   ws_20260921_183825.pcapng — pré, IPv4 152.233.19.169, eid 0x05xxxxxx
#   ws_20260923_234032.pcapng — pré, IPv4 152.233.19.169, eid 0x05xxxxxx
#   ws_20260924_171950.pcapng — pós, IPv6 2a02:6ea0:d01c::3, eid 0x0Bxxxxxx

param([switch]$Verbose)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {

$probe = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using WSEngine;

class TestSummonAttrib {
    static int fail = 0;
    static void Check(string name, int got, int expected) {
        string tag = (got == expected) ? "OK  " : "FAIL";
        Console.WriteLine("  [" + tag + "] " + name + "  got=" + got + " expected=" + expected);
        if (got != expected) fail++;
    }
    static void CheckAtLeast(string name, int got, int min) {
        string tag = (got >= min) ? "OK  " : "FAIL";
        Console.WriteLine("  [" + tag + "] " + name + "  got=" + got + " min=" + min);
        if (got < min) fail++;
    }
    static void Run(string pcap, string ip, int expectedSummonSpawns, int expectedSummonEidsMin, int expectedOwnersMin) {
        Console.WriteLine();
        Console.WriteLine("== " + pcap + "  (ip=" + ip + ")");
        string diag;
        var segs = PcapngReader.ReadTcp(pcap, ip, out diag);
        var msgs = TlvSplit.Parse(segs).Messages;
        var r = SummonOwnerMap.BuildResult(msgs);
        Check("summon eids collected", r.AllSummonEids.Count, expectedSummonEidsMin);
        CheckAtLeast("owner map size", r.Owners.Count, expectedOwnersMin);
        // Ratio: 100% of AllSummonEids ideally have an owner. Some spawns may
        // ship owner=0 and get filtered — we don't fail on that but report.
        int missing = r.AllSummonEids.Count - r.Owners.Count;
        Console.WriteLine("  info: " + missing + " summon eids seen without valid owner in body");
    }
    static int Main(string[] args) {
        // Pre-update, IPv4 baseline — 55 summon-tid eids all mapped
        // (66 was total 0x05 eids in old probe; whitelist é mais estrita).
        Run("captures/ws_20260921_183825.pcapng", "152.233.19.169", 55, 55, 55);
        // Pre-update raid — 232 summon-tid spawns, 231 distinct eids all mapped.
        Run("captures/ws_20260923_234032.pcapng", "152.233.19.169", 231, 231, 231);
        // Post-update, IPv6 — 26 summon-tid spawns all mapped (was 0 pre-fix).
        Run("captures/ws_20260924_171950.pcapng", "2a02:6ea0:d01c::3", 26, 26, 26);
        Console.WriteLine();
        Console.WriteLine(fail == 0 ? "ALL OK" : ("FAILED: " + fail));
        return fail == 0 ? 0 : 1;
    }
}
'@
    New-Item -ItemType Directory -Force tools\_test-summon-attrib | Out-Null
    Set-Content -Path tools\_test-summon-attrib\Test.cs -Value $probe -Encoding UTF8
    $csc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    & $csc /nologo /out:tools\_test-summon-attrib\Test.exe tools\_test-summon-attrib\Test.cs `
        src\Reassembly.cs src\TlvSplit.cs src\Lz4.cs `
        src\SummonRegistry.cs src\SummonOwnerMap.cs `
        /reference:System.Core.dll 2>&1
    if ($LASTEXITCODE -ne 0) { throw "compile failed" }
    & tools\_test-summon-attrib\Test.exe
    exit $LASTEXITCODE
} finally { Pop-Location }
