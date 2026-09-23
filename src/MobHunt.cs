using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

// Search memory for specific entity IDs (from packets) and dump context around each hit.
// Goal: find memory structs that link mob/summon IDs to their names.
namespace WSMobHunt
{
    static class Program
    {
        [Flags]
        enum ProcessAccess : uint { QueryInformation = 0x0400, VmRead = 0x0010 }
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(ProcessAccess a, bool i, int p);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr b, byte[] buf, int sz, out int r);
        [DllImport("kernel32.dll", SetLastError = true)] static extern int VirtualQueryEx(IntPtr h, IntPtr a, out MBI b, int s);
        [DllImport("kernel32.dll")] static extern void GetSystemInfo(out SI I);

        [StructLayout(LayoutKind.Sequential)]
        struct MBI { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
        [StructLayout(LayoutKind.Sequential)]
        struct SI { public ushort a; public ushort b; public uint c; public IntPtr d; public IntPtr e; public IntPtr f; public uint g; public uint h; public uint i; public ushort j; public ushort k; }

        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_GUARD = 0x100;
        const uint PAGE_NOACCESS = 0x01;
        static bool IsReadable(uint p) { return (p & PAGE_GUARD) == 0 && (p & PAGE_NOACCESS) == 0 && (p & 0xEE) != 0; }

        static void Main(string[] args)
        {
            // Target IDs to look for (from user's snapshot — top damage-dealing mobs)
            uint[] targets = new uint[] {
                0x05F6D27A, 0x05F739C9, 0x05F72F22, 0x05F6E6F7, 0x05F63B75,
                0x05F71738, 0x00563057 /* Sirpe — known player, control */
            };

            var procs = Process.GetProcessesByName("warspear");
            if (procs.Length == 0) { Console.WriteLine("no proc"); return; }
            IntPtr h = OpenProcess(ProcessAccess.QueryInformation | ProcessAccess.VmRead, false, procs[0].Id);
            if (h == IntPtr.Zero) { Console.WriteLine("OpenProcess fail"); return; }

            SI si; GetSystemInfo(out si);
            ulong maxA = 0x7FFFFFFFUL;
            IntPtr addr = si.d;
            MBI mbi;
            int sz = Marshal.SizeOf(typeof(MBI));

            var results = new Dictionary<uint, int>();
            foreach (var t in targets) results[t] = 0;

            while ((ulong)addr.ToInt64() < maxA)
            {
                if (VirtualQueryEx(h, addr, out mbi, sz) == 0) break;
                ulong rSz = (ulong)mbi.RegionSize.ToInt64();
                if (rSz == 0) break;
                if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
                {
                    int size = rSz > int.MaxValue ? int.MaxValue : (int)rSz;
                    byte[] buf = new byte[size];
                    int r;
                    if (ReadProcessMemory(h, mbi.BaseAddress, buf, size, out r) && r > 32)
                    {
                        ulong baseAddr = (ulong)mbi.BaseAddress.ToInt64();
                        // For each target ID, scan 4-byte-aligned positions for match
                        for (int i = 0; i <= r - 4; i += 1)
                        {
                            uint v = BitConverter.ToUInt32(buf, i);
                            foreach (var t in targets)
                            {
                                if (v == t)
                                {
                                    results[t]++;
                                    // Only dump first 3 hits per target to avoid spam
                                    if (results[t] <= 3)
                                    {
                                        int ctxStart = Math.Max(0, i - 32);
                                        int ctxEnd = Math.Min(r, i + 96);
                                        var sb = new StringBuilder();
                                        for (int k = ctxStart; k < ctxEnd; k++) sb.Append(buf[k].ToString("x2") + " ");
                                        // Also decode any UTF-16 ASCII runs in that region
                                        var strs = FindUtf16Strings(buf, ctxStart, ctxEnd);
                                        Console.WriteLine("[0x" + t.ToString("X8") + "] @ 0x" + (baseAddr + (ulong)i).ToString("X"));
                                        Console.WriteLine("  ctx: " + sb.ToString().TrimEnd());
                                        if (strs.Count > 0) Console.WriteLine("  strs: " + string.Join(", ", strs.ToArray()));
                                    }
                                }
                            }
                        }
                    }
                }
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
            Console.WriteLine();
            Console.WriteLine("hit counts:");
            foreach (var kv in results) Console.WriteLine("  0x" + kv.Key.ToString("X8") + " x" + kv.Value);
            CloseHandle(h);
        }

        static List<string> FindUtf16Strings(byte[] buf, int start, int end)
        {
            var res = new List<string>();
            var sb = new StringBuilder();
            for (int i = start; i + 1 < end; i += 2)
            {
                byte lo = buf[i]; byte hi = buf[i + 1];
                if (hi == 0 && lo >= 0x20 && lo < 0x7F) sb.Append((char)lo);
                else
                {
                    if (sb.Length >= 3) res.Add(sb.ToString());
                    sb.Clear();
                }
            }
            if (sb.Length >= 3) res.Add(sb.ToString());
            return res;
        }
    }
}
