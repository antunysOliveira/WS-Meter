using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

// Targeted memory probe: find every player struct, dump 128 bytes after each
// name, and try to identify guild-linkage patterns.
namespace WSEngineMemProbe
{
    static class Program
    {
        [Flags]
        enum ProcessAccess : uint { QueryInformation = 0x0400, VmRead = 0x0010 }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(ProcessAccess desiredAccess, bool inheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO Info);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress; public IntPtr AllocationBase;
            public uint AllocationProtect; public IntPtr RegionSize;
            public uint State; public uint Protect; public uint Type;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_INFO {
            public ushort ProcessorArchitecture; public ushort Reserved; public uint PageSize;
            public IntPtr MinimumApplicationAddress; public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask; public uint NumberOfProcessors;
            public uint ProcessorType; public uint AllocationGranularity;
            public ushort ProcessorLevel; public ushort ProcessorRevision;
        }

        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_GUARD = 0x100;
        const uint PAGE_NOACCESS = 0x01;
        static bool IsReadable(uint p) { return (p & PAGE_GUARD) == 0 && (p & PAGE_NOACCESS) == 0 && (p & 0xEE) != 0; }

        // Target names to probe (override via CLI args). Default = user char.
        static string[] targets = { "Centablg" };

        static IntPtr gHandle;

        static void Main(string[] args)
        {
            if (args.Length > 0) targets = args;
            var procs = Process.GetProcessesByName("warspear");
            if (procs.Length == 0) { Console.WriteLine("No warspear"); return; }
            gHandle = OpenProcess(ProcessAccess.QueryInformation | ProcessAccess.VmRead, false, procs[0].Id);
            if (gHandle == IntPtr.Zero) { Console.WriteLine("OpenProcess failed"); return; }

            bool w6; IsWow64Process(gHandle, out w6);
            SYSTEM_INFO si; GetSystemInfo(out si);
            ulong minAddr = (ulong)si.MinimumApplicationAddress.ToInt64();
            ulong maxAddr = 0x7FFFFFFFUL;

            IntPtr addr = new IntPtr((long)minAddr);
            MEMORY_BASIC_INFORMATION mbi;
            int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

            var hitAddrs = new List<ulong>();

            while ((ulong)addr.ToInt64() < maxAddr)
            {
                if (VirtualQueryEx(gHandle, addr, out mbi, mbiSize) == 0) break;
                ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                if (regionSize == 0) break;
                if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
                {
                    int size = regionSize > int.MaxValue ? int.MaxValue : (int)regionSize;
                    byte[] buf = new byte[size];
                    int read;
                    if (ReadProcessMemory(gHandle, mbi.BaseAddress, buf, size, out read) && read > 32)
                    {
                        ulong baseAddr = (ulong)mbi.BaseAddress.ToInt64();
                        foreach (var t in targets)
                        {
                            byte[] name = Encoding.Unicode.GetBytes(t);
                            int idx = 0;
                            while ((idx = IndexOf(buf, name, idx, read)) >= 0)
                            {
                                if (idx >= 16
                                    && buf[idx - 8] == 0x13 && buf[idx - 7] == 0 && buf[idx - 6] == 0 && buf[idx - 5] == 0
                                    && buf[idx - 4] == (byte)t.Length && buf[idx - 3] == 0 && buf[idx - 2] == 0 && buf[idx - 1] == 0)
                                {
                                    ulong hitAddr = baseAddr + (ulong)idx;
                                    // struct_base = hitAddr - 16 (name at offset 16 of struct)
                                    // self_ptr at struct offset 4 = buf[idx - 12..idx - 9]
                                    // Field at struct offset 4 points to the STRING DATA
                                    // (which lives inline at struct offset 16, = name position).
                                    uint sp = BitConverter.ToUInt32(buf, idx - 12);
                                    ulong structBase = hitAddr - 16;
                                    if ((ulong)sp == hitAddr)
                                    {
                                        int nameEnd = idx + name.Length;
                                        int dumpLen = Math.Min(512, read - nameEnd);
                                        Console.WriteLine("=== " + t + " struct @ 0x" + structBase.ToString("X") + " ===");
                                        // extended PRE: 256 bytes before the struct base (structBase = hitAddr - 16)
                                        int preExtStart = Math.Max(0, idx - 16 - 256);
                                        int preExtLen = Math.Min(256, idx - 16 - preExtStart);
                                        Console.WriteLine("PRE-EXT (" + preExtLen + " B before struct):");
                                        HexDump(buf, preExtStart, preExtLen, structBase - (ulong)(idx - 16 - preExtStart));
                                        Console.WriteLine("HEADER + NAME:");
                                        HexDump(buf, idx - 16, 16 + name.Length, structBase);
                                        Console.WriteLine("POST (" + dumpLen + " B after name):");
                                        HexDump(buf, nameEnd, dumpLen, structBase + 16 + (ulong)name.Length);
                                        for (int k = 0; k + 4 <= dumpLen; k += 4)
                                        {
                                            uint ptr = BitConverter.ToUInt32(buf, nameEnd + k);
                                            if (ptr >= 0x00400000 && ptr < 0x7FFFFFFF)
                                            {
                                                byte[] deref = new byte[40];
                                                int r;
                                                if (ReadProcessMemory(gHandle, new IntPtr(ptr), deref, 40, out r) && r >= 16)
                                                {
                                                    if (deref[4] == 0x13 && deref[5] == 0 && deref[6] == 0 && deref[7] == 0
                                                        && deref[9] == 0 && deref[10] == 0 && deref[11] == 0
                                                        && deref[8] >= 3 && deref[8] <= 15)
                                                    {
                                                        byte nlen = deref[8];
                                                        int nBytes = nlen * 2;
                                                        if (12 + nBytes <= 40)
                                                        {
                                                            bool ascii = true;
                                                            for (int m = 0; m < nBytes; m += 2) if (deref[12 + m + 1] != 0) { ascii = false; break; }
                                                            if (ascii)
                                                            {
                                                                string nm = Encoding.Unicode.GetString(deref, 12, nBytes);
                                                                Console.WriteLine("  ptr@+" + k + " -> 0x" + ptr.ToString("X") + " => \"" + nm + "\"");
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Console.WriteLine();
                                        hitAddrs.Add(hitAddr);
                                    }
                                }
                                idx += name.Length;
                            }
                        }
                    }
                }
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
            CloseHandle(gHandle);
        }

        static void HexDump(byte[] buf, int off, int len, ulong baseAddr)
        {
            for (int row = 0; row < len; row += 16)
            {
                int rowLen = Math.Min(16, len - row);
                var hex = new StringBuilder();
                var asc = new StringBuilder();
                for (int i = 0; i < rowLen; i++)
                {
                    byte b = buf[off + row + i];
                    hex.Append(b.ToString("x2")).Append(' ');
                    asc.Append(b >= 0x20 && b < 0x7f ? (char)b : '.');
                }
                while (hex.Length < 48) hex.Append("   ");
                Console.WriteLine("  0x" + (baseAddr + (ulong)row).ToString("X") + "  " + hex + " |" + asc + "|");
            }
        }

        static int IndexOf(byte[] hay, byte[] pat, int from, int len)
        {
            int end = len - pat.Length;
            for (int i = from; i <= end; i++)
            {
                int j;
                for (j = 0; j < pat.Length; j++) if (hay[i + j] != pat[j]) break;
                if (j == pat.Length) return i;
            }
            return -1;
        }
    }
}
