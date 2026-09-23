// PlayerResolver — on-demand memory lookup for player name + class.
//
// Given a world entity_id from a damage frame, search Warspear's memory for a
// PlayerEntry struct where offset 0 matches the id, then extract the UTF-16
// name + optional classId (from adjacent PlayerClassEntry struct sharing the
// same name).
//
// Cache: 30-second TTL per entity_id (auto-refresh if player renames or
// re-enters area). No JSON persistence — always fresh.
//
// Requires WS-engine.exe running as Administrator (manifest already sets this).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WSEngine
{
    static class PlayerResolver
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

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress; public IntPtr AllocationBase;
            public uint AllocationProtect; public IntPtr RegionSize;
            public uint State; public uint Protect; public uint Type;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_INFO
        {
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

        public struct Resolved { public string Name; public int ClassId; public DateTime At; }
        static readonly Dictionary<uint, Resolved> _cache = new Dictionary<uint, Resolved>();
        static readonly object _lock = new object();
        const int CacheTtlSec = 30;

        // Public API — returns (name, classId) or (null, 0) if not found.
        // Cached for 30s per entity_id.
        // Misses are cached with short TTL so we don't hammer memory scans for
        // players whose structs aren't loaded (typical for far-away PvP opponents).
        const int MissTtlSec = 15;

        public static Resolved Lookup(uint entityId)
        {
            if (entityId == 0) return default(Resolved);
            lock (_lock)
            {
                Resolved cached;
                if (_cache.TryGetValue(entityId, out cached))
                {
                    double age = (DateTime.UtcNow - cached.At).TotalSeconds;
                    bool valid = !string.IsNullOrEmpty(cached.Name) ? age < CacheTtlSec : age < MissTtlSec;
                    if (valid) return cached;
                }
            }
            var fresh = ScanMemoryFor(entityId);
            fresh.At = DateTime.UtcNow;
            lock (_lock) { _cache[entityId] = fresh; }  // cache hits AND misses (short TTL for misses)
            return fresh;
        }

        // Bypasses cache — always re-scans. For the event-driven worker: after a
        // combat event we want to retry on the retry schedule (1s / 3s / 10s)
        // instead of waiting for the 15s miss-TTL to expire.
        public static Resolved LookupForced(uint entityId)
        {
            if (entityId == 0) return default(Resolved);
            var fresh = ScanMemoryFor(entityId);
            fresh.At = DateTime.UtcNow;
            lock (_lock) { _cache[entityId] = fresh; }
            return fresh;
        }

        static Resolved ScanMemoryFor(uint entityId)
        {
            var procs = Process.GetProcessesByName("warspear");
            if (procs.Length == 0) return new Resolved();
            IntPtr handle = OpenProcess(ProcessAccess.QueryInformation | ProcessAccess.VmRead, false, procs[0].Id);
            if (handle == IntPtr.Zero) return new Resolved();
            try
            {
                SYSTEM_INFO si; GetSystemInfo(out si);
                ulong minAddr = (ulong)si.MinimumApplicationAddress.ToInt64();
                ulong maxAddr = 0x7FFFFFFFUL;
                byte[] idBytes = BitConverter.GetBytes(entityId);
                string foundName = null;
                // Pass 1: find name struct where offset 0 == entityId
                // Look for `[id u32][selfPtr u32]<any 8 bytes>[nlen u32][utf16 name]`
                // in TWO layouts:
                //   A) nlen at offset 12 (type=0x13 style, name at +16)
                //   B) nlen at offset 16 (no-type style, name at +20)
                WalkRegions(handle, minAddr, maxAddr, (buf, read) => {
                    for (int i = 0; i + 32 <= read; i++)
                    {
                        if (buf[i] != idBytes[0] || buf[i+1] != idBytes[1] || buf[i+2] != idBytes[2] || buf[i+3] != idBytes[3]) continue;
                        for (int layoutOff = 12; layoutOff <= 16; layoutOff += 4)
                        {
                            if (i + layoutOff + 4 > read) break;
                            if (buf[i + layoutOff + 1] != 0 || buf[i + layoutOff + 2] != 0 || buf[i + layoutOff + 3] != 0) continue;
                            byte nlen = buf[i + layoutOff];
                            if (nlen < 3 || nlen > 20) continue;
                            int nameStart = i + layoutOff + 4;
                            if (nameStart + nlen * 2 > read) continue;
                            uint selfPtr = BitConverter.ToUInt32(buf, i + 4);
                            if (selfPtr < 0x00400000) continue;
                            bool ok = true;
                            for (int k = 0; k < nlen; k++)
                            {
                                byte lo = buf[nameStart + k * 2];
                                byte hi = buf[nameStart + k * 2 + 1];
                                if (hi != 0) { ok = false; break; }
                                bool letter = (lo >= 'A' && lo <= 'Z') || (lo >= 'a' && lo <= 'z');
                                bool digit = lo >= '0' && lo <= '9';
                                if (!letter && !digit) { ok = false; break; }
                            }
                            if (!ok) continue;
                            byte first = buf[nameStart];
                            if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) continue;
                            foundName = Encoding.Unicode.GetString(buf, nameStart, nlen * 2);
                            return true;
                        }
                    }
                    return false;
                });

                if (foundName == null) return new Resolved();

                // Pass 2: find class struct with matching name — walk ALL regions (class
                // struct may live in a separate memory region from the name struct).
                int foundClass = 0;
                WalkRegions(handle, minAddr, maxAddr, (buf, read) => {
                    int cid = FindClassIdByName(buf, read, foundName);
                    if (cid > 0) { foundClass = cid; return true; }
                    return false;
                });

                return new Resolved { Name = foundName, ClassId = foundClass };
            }
            finally { CloseHandle(handle); }
        }

        // Walk committed readable regions, invoke callback(buf, read). Stops when
        // callback returns true.
        static void WalkRegions(IntPtr handle, ulong minAddr, ulong maxAddr, Func<byte[], int, bool> cb)
        {
            IntPtr addr = new IntPtr((long)minAddr);
            MEMORY_BASIC_INFORMATION mbi;
            int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            while ((ulong)addr.ToInt64() < maxAddr)
            {
                if (VirtualQueryEx(handle, addr, out mbi, mbiSize) == 0) break;
                ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                if (regionSize == 0) break;
                if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
                {
                    int size = regionSize > 32 * 1024 * 1024 ? 32 * 1024 * 1024 : (int)regionSize;
                    byte[] buf = new byte[size];
                    int read;
                    if (ReadProcessMemory(handle, mbi.BaseAddress, buf, size, out read) && read > 32)
                    {
                        if (cb(buf, read)) return;
                    }
                }
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
        }

        // Scan same buffer for `[classId u8][0x21][flags u16][ptr u32][0x13 u32][name_len u32][utf16 name]`
        // where name matches the given name.
        static int FindClassIdByName(byte[] buf, int len, string name)
        {
            byte[] nameBytes = Encoding.Unicode.GetBytes(name);
            byte nlen = (byte)name.Length;
            for (int i = 0; i + 16 + nameBytes.Length <= len; i++)
            {
                byte classId = buf[i];
                if (classId < 1 || classId > 20) continue;
                if (buf[i+1] != 0x21) continue;
                if (buf[i+8] != 0x13 || buf[i+9] != 0 || buf[i+10] != 0 || buf[i+11] != 0) continue;
                if (buf[i+12] != nlen || buf[i+13] != 0 || buf[i+14] != 0 || buf[i+15] != 0) continue;
                bool match = true;
                for (int k = 0; k < nameBytes.Length; k++)
                {
                    if (buf[i + 16 + k] != nameBytes[k]) { match = false; break; }
                }
                if (match) return classId;
            }
            return 0;
        }
    }
}
